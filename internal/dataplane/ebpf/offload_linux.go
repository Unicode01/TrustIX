//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unsafe"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/dataplane"
)

const (
	ethtoolGSSetInfo  = 0x00000037
	ethtoolGStrings   = 0x0000001b
	ethtoolGFeatures  = 0x0000003a
	ethtoolSFeatures  = 0x0000003b
	ethSSFeatures     = 4
	siocEthtool       = 0x8946
	ethtoolStringSize = 32
)

var lanUnsafeOffloadFeatures = map[string]struct{}{
	"rx-checksum":                    {},
	"rx-checksumming":                {},
	"tx-checksumming":                {},
	"tx-checksum-ipv4":               {},
	"tx-checksum-ip-generic":         {},
	"tx-checksum-ipv6":               {},
	"tx-checksum-sctp":               {},
	"tx-sg":                          {},
	"scatter-gather":                 {},
	"tx-scatter-gather":              {},
	"tx-scatter-gather-fraglist":     {},
	"tx-tso":                         {},
	"tcp-segmentation-offload":       {},
	"tx-tcp-segmentation":            {},
	"tx-tcp-ecn-segmentation":        {},
	"tx-tcp-mangleid-segmentation":   {},
	"tx-tcp6-segmentation":           {},
	"tx-gso":                         {},
	"generic-segmentation-offload":   {},
	"rx-gro":                         {},
	"generic-receive-offload":        {},
	"rx-lro":                         {},
	"large-receive-offload":          {},
	"tx-udp-segmentation":            {},
	"tx-udp_tnl-segmentation":        {},
	"tx-udp_tnl-csum-segmentation":   {},
	"tx-gre-segmentation":            {},
	"tx-gre-csum-segmentation":       {},
	"tx-ipxip4-segmentation":         {},
	"tx-ipxip6-segmentation":         {},
	"tx-tunnel-remcsum-segmentation": {},
	"tx-gso-partial":                 {},
	"tx-gso-list":                    {},
}

var lanRouteGSOPreservedOffloadFeatures = map[string]struct{}{
	"rx-checksum":             {},
	"rx-checksumming":         {},
	"rx-gro":                  {},
	"generic-receive-offload": {},
	"rx-lro":                  {},
	"large-receive-offload":   {},
}

var lanAllRouteGSOOffloadFeaturesPreserved = map[string]struct{}{}

type persistedLinkOffloadState struct {
	Iface     string                        `json:"iface"`
	NetNSName string                        `json:"netns_name,omitempty"`
	NetNSPath string                        `json:"netns_path,omitempty"`
	Features  []persistedLinkOffloadFeature `json:"features,omitempty"`
	Peers     []persistedLinkOffloadState   `json:"peers,omitempty"`
}

type persistedLinkOffloadFeature struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

func (state *persistedLinkOffloadState) Detail() string {
	if state == nil || len(state.Features) == 0 && len(state.Peers) == 0 {
		return ""
	}
	names := make([]string, 0, len(state.Features))
	for _, feature := range state.Features {
		if feature.Name != "" {
			names = append(names, feature.Name)
		}
	}
	detail := strings.Join(names, ",")
	for _, peer := range state.Peers {
		peerDetail := (&peer).Detail()
		if peerDetail == "" {
			continue
		}
		target := peer.Iface
		if peer.NetNSName != "" {
			target = peer.NetNSName + "/" + target
		} else if peer.NetNSPath != "" {
			target = peer.NetNSPath + "/" + target
		}
		if detail != "" {
			detail += ";"
		}
		detail += "peer " + target + ":" + peerDetail
	}
	return detail
}

type linkOffloadTarget struct {
	Iface     string
	NetNSName string
	NetNSPath string
}

type ethtoolIFReq struct {
	Name [unix.IFNAMSIZ]byte
	Data uintptr
}

type ethtoolSSetInfo struct {
	Cmd      uint32
	Reserved uint32
	Mask     uint64
	Data     [1]uint32
}

type ethtoolFeature struct {
	Index        int
	Name         string
	Available    bool
	Active       bool
	NeverChanged bool
}

func (manager *Manager) applyLANOffloadProtectionLocked(link netlink.Link, spec dataplane.AttachSpec) error {
	if link == nil || !lanOffloadProtectionApplies(spec) {
		if kernelUDPTXSecureDirectRequestedForSpec(spec) && strings.EqualFold(spec.LANAttachMode, "existing") && lanOffloadProtectionMode() == "auto" {
			manager.warnings = append(manager.warnings, "LAN offload protection skipped for existing LAN iface; set TRUSTIX_LAN_OFFLOAD_PROTECTION=force if this existing iface can deliver veth/GSO or CHECKSUM_PARTIAL packets to TC")
		}
		return nil
	}

	var allChanged []string
	var allFailures []string
	var errs []string
	if manager.lanOffloadProtections == nil {
		manager.lanOffloadProtections = make(map[string]*persistedLinkOffloadState)
	}
	iface := link.Attrs().Name
	accumulated := manager.lanOffloadProtections[iface]
	if accumulated == nil || accumulated.Iface != link.Attrs().Name {
		accumulated = &persistedLinkOffloadState{Iface: link.Attrs().Name}
	}

	targets := []linkOffloadTarget{{Iface: link.Attrs().Name}}
	peerTarget, peerWarning := vethPeerOffloadTarget(link)
	if peerWarning != "" {
		manager.warnings = append(manager.warnings, peerWarning)
	}
	if peerTarget != nil {
		targets = append(targets, *peerTarget)
	}

	featureSet := lanOffloadProtectionFeaturesForSpec(spec)
	preserveRouteGSO := lanOffloadProtectionPreservesRouteGSO(spec)
	preserveRouteGSORX := lanOffloadProtectionPreservesRouteGSORX(spec)
	for i, target := range targets {
		state, changed, failures, err := disableUnsafeLANOffloadsOnTarget(target, featureSet)
		if state != nil && len(state.Features) > 0 {
			if i == 0 {
				accumulated = mergeLinkOffloadState(accumulated, state)
			} else {
				accumulated = mergePeerLinkOffloadState(accumulated, *state)
			}
		}
		targetLabel := target.offloadLabel()
		for _, feature := range changed {
			allChanged = append(allChanged, targetLabel+":"+feature)
		}
		for _, feature := range failures {
			allFailures = append(allFailures, targetLabel+":"+feature)
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", targetLabel, err))
		}
	}

	if accumulated.hasRestorableFeatures() {
		manager.lanOffloadProtections[iface] = accumulated
		if iface == manager.spec.LANIface || manager.lanOffloadProtection == nil {
			manager.lanOffloadProtection = accumulated
		}
	}
	if len(allChanged) > 0 {
		manager.capabilities = appendCapability(manager.capabilities, "lan-offload-protection")
		manager.warnings = append(manager.warnings, fmt.Sprintf("LAN offload protection disabled %s for TC/XDP linear-packet safety", strings.Join(allChanged, ",")))
	}
	if preserveRouteGSO {
		manager.capabilities = appendCapability(manager.capabilities, "lan-offload-protection-route-gso")
		manager.warnings = append(manager.warnings, "LAN offload protection preserved TX checksum/SG/TSO/GSO for kernel UDP active-GSO or experimental_tcp route-GSO")
	}
	if preserveRouteGSORX {
		manager.capabilities = appendCapability(manager.capabilities, "lan-offload-protection-route-gso-rx")
		manager.warnings = append(manager.warnings, "LAN offload protection preserved RX checksum/GRO for explicit kernel UDP active-GSO experiment")
	}
	if len(allFailures) > 0 {
		manager.warnings = append(manager.warnings, fmt.Sprintf("LAN offload protection could not disable %s", strings.Join(allFailures, ",")))
	}
	if len(errs) > 0 {
		return fmt.Errorf("LAN offload protection on %q: %s", link.Attrs().Name, strings.Join(errs, "; "))
	}
	return nil
}

func (manager *Manager) restoreLANOffloadProtectionLocked(link netlink.Link) error {
	states := manager.lanOffloadProtections
	if len(states) == 0 && manager.lanOffloadProtection != nil {
		states = map[string]*persistedLinkOffloadState{manager.lanOffloadProtection.Iface: manager.lanOffloadProtection}
	}
	if len(states) == 0 {
		manager.lanOffloadProtection = nil
		manager.lanOffloadProtections = make(map[string]*persistedLinkOffloadState)
		return nil
	}
	var errs []string
	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		state := states[key]
		if state == nil || !state.hasRestorableFeatures() {
			continue
		}
		stateLink := link
		if len(state.Features) > 0 && (stateLink == nil || stateLink.Attrs().Name != state.Iface) {
			found, err := netlink.LinkByName(state.Iface)
			if err != nil {
				errs = append(errs, fmt.Sprintf("inspect LAN iface %q: %v", state.Iface, err))
			} else {
				stateLink = found
			}
		}
		if len(state.Features) > 0 && stateLink != nil {
			if err := restoreUnsafeLANOffloadsOnTarget(state); err != nil {
				errs = append(errs, err.Error())
			}
		}
		for i := range state.Peers {
			peer := state.Peers[i]
			if len(peer.Features) == 0 {
				continue
			}
			if err := restoreUnsafeLANOffloadsOnTarget(&peer); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	manager.lanOffloadProtection = nil
	manager.lanOffloadProtections = make(map[string]*persistedLinkOffloadState)
	if len(errs) > 0 {
		return fmt.Errorf("restore LAN offloads: %s", strings.Join(errs, "; "))
	}
	return nil
}

func lanOffloadProtectionMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_LAN_OFFLOAD_PROTECTION"))) {
	case "", "auto":
		return "auto"
	case "0", "false", "no", "off", "disabled":
		return "off"
	case "managed":
		return "managed"
	case "required", "require", "strict":
		return "required"
	case "1", "true", "yes", "on", "enabled", "force":
		return "force"
	default:
		return "auto"
	}
}

func lanOffloadProtectionRequired() bool {
	return lanOffloadProtectionMode() == "required"
}

func lanOffloadProtectionApplies(spec dataplane.AttachSpec) bool {
	switch lanOffloadProtectionMode() {
	case "off":
		return false
	case "force", "required":
		return true
	case "managed", "auto":
		return strings.EqualFold(spec.LANAttachMode, "managed") ||
			spec.KernelUDPTXDirectOnly ||
			spec.ExperimentalTCPTXDirect
	default:
		return strings.EqualFold(spec.LANAttachMode, "managed")
	}
}

func lanOffloadProtectionPreservesRouteGSO(spec dataplane.AttachSpec) bool {
	if envTruthy(
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_ROUTE_GSO",
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_TX_GSO",
	) {
		return true
	}
	if envFalsey(
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_ROUTE_GSO",
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_TX_GSO",
	) {
		return false
	}
	switch lanOffloadProtectionMode() {
	case "auto", "managed":
	default:
		return false
	}
	if kernelUDPTXDirectOnlyEnabled(spec) &&
		kernelUDPTunnelGSOEnabledForOptions(kernelUDPTXDirectProgramOptions{
			Enabled:       true,
			KernelUDPOnly: true,
			DirectOnly:    true,
		}) &&
		kernelUDPTunnelGSOActiveSKBEnabledForOptions(kernelUDPTXDirectProgramOptions{
			Enabled:       true,
			KernelUDPOnly: true,
			DirectOnly:    true,
		}) {
		return true
	}
	if experimentalTCPActiveGSOLANOffloadPreserveRequested(spec) {
		return true
	}
	return false
}

func experimentalTCPActiveGSOLANOffloadPreserveRequested(spec dataplane.AttachSpec) bool {
	if !spec.ExperimentalTCPTXDirect || !kernelUDPTXDirectOnlyEnabled(spec) {
		return false
	}
	if experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequested() ||
		experimentalTCPTXDirectRouteTCPGSOKfuncRequested() {
		return true
	}
	if !experimentalTCPTXDirectFinalizeFlowTCPHeaderKfuncRequested() {
		return false
	}
	if experimentalTCPSkipOuterTCPChecksum() || experimentalTCPTXDirectPreOuterInnerChecksumEnabled() {
		return false
	}
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ACTIVE_GSO_SAFE",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_SAFE_ACTIVE_GSO",
	) {
		return false
	}
	if !experimentalTCPUnsafeActiveGSOAcknowledged() {
		return false
	}
	return kernelUDPTunnelGSOEnabledForOptions(kernelUDPTXDirectProgramOptions{
		Enabled:             true,
		ExperimentalTCPOnly: true,
		DirectOnly:          true,
	}) &&
		envTruthy(
			"TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO",
			"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ACTIVE_GSO",
		) &&
		envTruthy(
			"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ACTIVE_GSO_SAFE",
			"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_SAFE_ACTIVE_GSO",
		)
}

func lanOffloadProtectionPreservesRouteGSORX(spec dataplane.AttachSpec) bool {
	if !lanOffloadProtectionPreservesRouteGSO(spec) {
		return false
	}
	if envTruthy(
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_RX_GRO",
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_RX_OFFLOADS",
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_ALL_GSO",
	) {
		return true
	}
	if envFalsey(
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_RX_GRO",
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_RX_OFFLOADS",
		"TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_ALL_GSO",
	) {
		return false
	}
	return false
}

func lanOffloadProtectionFeaturesForSpec(spec dataplane.AttachSpec) map[string]struct{} {
	if lanOffloadProtectionPreservesRouteGSORX(spec) {
		return lanAllRouteGSOOffloadFeaturesPreserved
	}
	if lanOffloadProtectionPreservesRouteGSO(spec) {
		return lanRouteGSOPreservedOffloadFeatures
	}
	return lanUnsafeOffloadFeatures
}

func disableUnsafeLANOffloads(iface string, unsafeFeatures map[string]struct{}) (*persistedLinkOffloadState, []string, []string, error) {
	features, err := ethtoolFeatures(iface)
	if err != nil {
		return nil, nil, nil, err
	}
	if unsafeFeatures == nil {
		unsafeFeatures = lanUnsafeOffloadFeatures
	}
	state := &persistedLinkOffloadState{Iface: iface}
	var changed []string
	var failures []string
	for _, feature := range features {
		if !feature.Active || !feature.Available || feature.NeverChanged {
			continue
		}
		if _, ok := unsafeFeatures[feature.Name]; !ok {
			continue
		}
		if err := setEthtoolFeature(iface, len(features), feature.Index, false); err != nil {
			failures = append(failures, feature.Name)
			continue
		}
		state.Features = append(state.Features, persistedLinkOffloadFeature{Name: feature.Name, Active: true})
		changed = append(changed, feature.Name)
	}
	if len(state.Features) == 0 {
		state = nil
	}
	if len(failures) > 0 {
		return state, changed, failures, fmt.Errorf("failed features: %s", strings.Join(failures, ","))
	}
	return state, changed, nil, nil
}

func restoreUnsafeLANOffloads(state *persistedLinkOffloadState) error {
	if state == nil || state.Iface == "" {
		return nil
	}
	features, err := ethtoolFeatures(state.Iface)
	if err != nil {
		return err
	}
	byName := make(map[string]ethtoolFeature, len(features))
	for _, feature := range features {
		byName[feature.Name] = feature
	}
	var failures []string
	for _, saved := range state.Features {
		feature, ok := byName[saved.Name]
		if !ok || feature.Active == saved.Active {
			continue
		}
		if err := setEthtoolFeature(state.Iface, len(features), feature.Index, saved.Active); err != nil {
			failures = append(failures, saved.Name)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("restore LAN offloads on %q failed for %s", state.Iface, strings.Join(failures, ","))
	}
	return nil
}

func disableUnsafeLANOffloadsOnTarget(target linkOffloadTarget, unsafeFeatures map[string]struct{}) (*persistedLinkOffloadState, []string, []string, error) {
	if target.NetNSPath == "" {
		return disableUnsafeLANOffloads(target.Iface, unsafeFeatures)
	}
	var state *persistedLinkOffloadState
	var changed []string
	var failures []string
	err := withNetNS(target.NetNSPath, func() error {
		var disableErr error
		state, changed, failures, disableErr = disableUnsafeLANOffloads(target.Iface, unsafeFeatures)
		return disableErr
	})
	if state != nil {
		state.NetNSName = target.NetNSName
		state.NetNSPath = target.NetNSPath
	}
	return state, changed, failures, err
}

func restoreUnsafeLANOffloadsOnTarget(state *persistedLinkOffloadState) error {
	if state == nil || state.Iface == "" || len(state.Features) == 0 {
		return nil
	}
	if state.NetNSPath == "" {
		return restoreUnsafeLANOffloads(state)
	}
	return withNetNS(state.NetNSPath, func() error {
		return restoreUnsafeLANOffloads(state)
	})
}

func vethPeerOffloadTarget(link netlink.Link) (*linkOffloadTarget, string) {
	veth, ok := link.(*netlink.Veth)
	if !ok {
		return nil, ""
	}
	peerIndex, err := netlink.VethPeerIndex(veth)
	if err != nil {
		return nil, fmt.Sprintf("LAN offload protection could not inspect veth peer for %s: %v", link.Attrs().Name, err)
	}
	if peerIndex <= 0 {
		return nil, fmt.Sprintf("LAN offload protection could not inspect veth peer for %s: invalid peer ifindex %d", link.Attrs().Name, peerIndex)
	}
	if peer, err := netlink.LinkByIndex(peerIndex); err == nil && peer != nil {
		return &linkOffloadTarget{Iface: peer.Attrs().Name}, ""
	}
	target, err := findNamedNetNSLinkByIndex(peerIndex)
	if err != nil {
		return nil, fmt.Sprintf("LAN offload protection could not locate veth peer ifindex %d for %s: %v", peerIndex, link.Attrs().Name, err)
	}
	if target == nil {
		return nil, fmt.Sprintf("LAN offload protection could not locate veth peer ifindex %d for %s in named netns", peerIndex, link.Attrs().Name)
	}
	return target, ""
}

func vethPeerHardwareAddr(link netlink.Link) (net.HardwareAddr, string) {
	target, warning := vethPeerOffloadTarget(link)
	if target == nil {
		return nil, warning
	}
	var hw net.HardwareAddr
	read := func() error {
		peer, err := netlink.LinkByName(target.Iface)
		if err != nil {
			return err
		}
		if peer == nil || peer.Attrs() == nil || len(peer.Attrs().HardwareAddr) != 6 {
			return fmt.Errorf("peer %s has no Ethernet hardware address", target.offloadLabel())
		}
		hw = append(net.HardwareAddr(nil), peer.Attrs().HardwareAddr...)
		return nil
	}
	var err error
	if target.NetNSPath == "" {
		err = read()
	} else {
		err = withNetNS(target.NetNSPath, read)
	}
	if err != nil {
		return nil, fmt.Sprintf("LAN veth peer MAC discovery failed for %s: %v", link.Attrs().Name, err)
	}
	return hw, ""
}

func findNamedNetNSLinkByIndex(index int) (*linkOffloadTarget, error) {
	paths, err := namedNetNSPaths()
	if err != nil {
		return nil, err
	}
	for _, candidate := range paths {
		var iface string
		err := withNetNS(candidate.path, func() error {
			link, err := netlink.LinkByIndex(index)
			if err != nil {
				return err
			}
			if link == nil {
				return fmt.Errorf("missing link")
			}
			iface = link.Attrs().Name
			return nil
		})
		if err == nil && iface != "" {
			return &linkOffloadTarget{Iface: iface, NetNSName: candidate.name, NetNSPath: candidate.path}, nil
		}
	}
	return nil, nil
}

type namedNetNSPath struct {
	name string
	path string
}

func namedNetNSPaths() ([]namedNetNSPath, error) {
	var paths []namedNetNSPath
	seen := make(map[string]struct{})
	var firstErr error
	for _, dir := range []string{"/run/netns", "/var/run/netns"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, entry := range entries {
			if entry.Name() == "" || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			paths = append(paths, namedNetNSPath{name: entry.Name(), path: path})
		}
	}
	if len(paths) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return paths, nil
}

func withNetNS(path string, fn func() error) error {
	if path == "" {
		return fn()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := netns.Get()
	if err != nil {
		return err
	}
	defer original.Close()

	target, err := netns.GetFromPath(path)
	if err != nil {
		return err
	}
	defer target.Close()

	if err := netns.Set(target); err != nil {
		return err
	}
	defer func() {
		_ = netns.Set(original)
	}()
	return fn()
}

func (target linkOffloadTarget) offloadLabel() string {
	if target.NetNSName != "" {
		return target.NetNSName + "/" + target.Iface
	}
	if target.NetNSPath != "" {
		return target.NetNSPath + "/" + target.Iface
	}
	return target.Iface
}

func (state *persistedLinkOffloadState) hasRestorableFeatures() bool {
	if state == nil {
		return false
	}
	if len(state.Features) > 0 {
		return true
	}
	for _, peer := range state.Peers {
		if len(peer.Features) > 0 {
			return true
		}
	}
	return false
}

func mergeLinkOffloadState(base, add *persistedLinkOffloadState) *persistedLinkOffloadState {
	if add == nil {
		return base
	}
	if base == nil || base.Iface != add.Iface || base.NetNSPath != add.NetNSPath {
		clone := *add
		clone.Features = append([]persistedLinkOffloadFeature(nil), add.Features...)
		clone.Peers = append([]persistedLinkOffloadState(nil), add.Peers...)
		return &clone
	}
	base.Features = mergeOffloadFeatures(base.Features, add.Features)
	return base
}

func mergePeerLinkOffloadState(base *persistedLinkOffloadState, peer persistedLinkOffloadState) *persistedLinkOffloadState {
	if base == nil {
		base = &persistedLinkOffloadState{}
	}
	for i := range base.Peers {
		existing := &base.Peers[i]
		if existing.Iface == peer.Iface && existing.NetNSPath == peer.NetNSPath {
			existing.Features = mergeOffloadFeatures(existing.Features, peer.Features)
			if existing.NetNSName == "" {
				existing.NetNSName = peer.NetNSName
			}
			return base
		}
	}
	base.Peers = append(base.Peers, peer)
	return base
}

func mergeOffloadFeatures(existing, added []persistedLinkOffloadFeature) []persistedLinkOffloadFeature {
	seen := make(map[string]struct{}, len(existing)+len(added))
	merged := make([]persistedLinkOffloadFeature, 0, len(existing)+len(added))
	for _, feature := range existing {
		if feature.Name == "" {
			continue
		}
		if _, ok := seen[feature.Name]; ok {
			continue
		}
		seen[feature.Name] = struct{}{}
		merged = append(merged, feature)
	}
	for _, feature := range added {
		if feature.Name == "" {
			continue
		}
		if _, ok := seen[feature.Name]; ok {
			continue
		}
		seen[feature.Name] = struct{}{}
		merged = append(merged, feature)
	}
	return merged
}

func ethtoolFeatures(iface string) ([]ethtoolFeature, error) {
	count, err := ethtoolFeatureCount(iface)
	if err != nil {
		return nil, err
	}
	if count <= 0 {
		return nil, nil
	}
	names, err := ethtoolFeatureNames(iface, count)
	if err != nil {
		return nil, err
	}
	available, active, neverChanged, err := ethtoolFeatureBits(iface, count)
	if err != nil {
		return nil, err
	}
	features := make([]ethtoolFeature, 0, count)
	for i, name := range names {
		if name == "" {
			continue
		}
		features = append(features, ethtoolFeature{
			Index:        i,
			Name:         name,
			Available:    bitIsSet(available, i),
			Active:       bitIsSet(active, i),
			NeverChanged: bitIsSet(neverChanged, i),
		})
	}
	return features, nil
}

func ethtoolFeatureCount(iface string) (int, error) {
	info := ethtoolSSetInfo{
		Cmd:  ethtoolGSSetInfo,
		Mask: 1 << ethSSFeatures,
	}
	if err := ioctlEthtool(iface, unsafe.Pointer(&info)); err != nil {
		return 0, err
	}
	return int(info.Data[0]), nil
}

func ethtoolFeatureNames(iface string, count int) ([]string, error) {
	buf := make([]byte, 12+count*ethtoolStringSize)
	binary.LittleEndian.PutUint32(buf[0:4], ethtoolGStrings)
	binary.LittleEndian.PutUint32(buf[4:8], ethSSFeatures)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(count))
	if err := ioctlEthtool(iface, unsafe.Pointer(&buf[0])); err != nil {
		return nil, err
	}
	names := make([]string, count)
	for i := 0; i < count; i++ {
		raw := buf[12+i*ethtoolStringSize : 12+(i+1)*ethtoolStringSize]
		if end := bytesIndexByte(raw, 0); end >= 0 {
			raw = raw[:end]
		}
		names[i] = strings.TrimSpace(string(raw))
	}
	return names, nil
}

func ethtoolFeatureBits(iface string, count int) ([]uint32, []uint32, []uint32, error) {
	blocks := featureBlocks(count)
	buf := make([]byte, 8+blocks*16)
	binary.LittleEndian.PutUint32(buf[0:4], ethtoolGFeatures)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(blocks))
	if err := ioctlEthtool(iface, unsafe.Pointer(&buf[0])); err != nil {
		return nil, nil, nil, err
	}
	available := make([]uint32, blocks)
	active := make([]uint32, blocks)
	neverChanged := make([]uint32, blocks)
	for i := 0; i < blocks; i++ {
		off := 8 + i*16
		available[i] = binary.LittleEndian.Uint32(buf[off : off+4])
		active[i] = binary.LittleEndian.Uint32(buf[off+8 : off+12])
		neverChanged[i] = binary.LittleEndian.Uint32(buf[off+12 : off+16])
	}
	return available, active, neverChanged, nil
}

func setEthtoolFeature(iface string, count int, index int, active bool) error {
	if index < 0 || index >= count {
		return fmt.Errorf("feature index %d out of range", index)
	}
	blocks := featureBlocks(count)
	buf := make([]byte, 8+blocks*8)
	binary.LittleEndian.PutUint32(buf[0:4], ethtoolSFeatures)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(blocks))
	block := index / 32
	bit := uint32(1) << uint(index%32)
	off := 8 + block*8
	binary.LittleEndian.PutUint32(buf[off:off+4], bit)
	if active {
		binary.LittleEndian.PutUint32(buf[off+4:off+8], bit)
	}
	return ioctlEthtool(iface, unsafe.Pointer(&buf[0]))
}

func ioctlEthtool(iface string, data unsafe.Pointer) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifreq ethtoolIFReq
	copy(ifreq.Name[:unix.IFNAMSIZ-1], iface)
	ifreq.Data = uintptr(data)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(siocEthtool), uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return errno
	}
	return nil
}

func featureBlocks(count int) int {
	return (count + 31) / 32
}

func bitIsSet(blocks []uint32, index int) bool {
	block := index / 32
	if block < 0 || block >= len(blocks) {
		return false
	}
	return blocks[block]&(uint32(1)<<uint(index%32)) != 0
}

func appendCapability(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func bytesIndexByte(payload []byte, value byte) int {
	for i, item := range payload {
		if item == value {
			return i
		}
	}
	return -1
}
