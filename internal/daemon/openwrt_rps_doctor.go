package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"trustix.local/trustix/internal/config"
)

const openWrtRPSFix = "uci set network.globals.packet_steering='0'; uci commit network; /etc/init.d/network restart"

type openWrtRPSInterfaceState struct {
	Name         string
	Driver       string
	RXQueuePaths []string
	RXQueueMasks []string
}

func (daemon *Daemon) openWrtRPSDoctorCheck() (doctorCheck, bool) {
	if daemon == nil || !runtimeLooksLikeOpenWrt() ||
		!kernelDatapathFullPlaintextEnabledForDesired(daemon.desired) {
		return doctorCheck{}, false
	}
	ifaces := openWrtRPSUnderlayInterfaces(daemon.desired)
	if len(ifaces) == 0 {
		return doctorCheck{}, false
	}
	states := make([]openWrtRPSInterfaceState, 0, len(ifaces))
	for _, ifname := range ifaces {
		state, err := probeOpenWrtRPSInterface("/sys/class/net", ifname)
		if err != nil {
			continue
		}
		states = append(states, state)
	}
	return openWrtRPSDoctorCheckForStates(states)
}

func openWrtRPSUnderlayInterfaces(desired config.Desired) []string {
	seen := make(map[string]struct{})
	add := func(raw string) {
		ifname := strings.TrimSpace(raw)
		if ifname == "" || filepath.Base(ifname) != ifname {
			return
		}
		seen[ifname] = struct{}{}
	}
	for _, lan := range config.EffectiveLANs(desired) {
		add(lan.UnderlayIface)
	}
	for _, endpoint := range desired.Endpoints {
		add(endpoint.LocalBind.Iface)
	}
	for _, peer := range desired.Peers {
		for _, endpoint := range peer.Endpoints {
			add(endpoint.LocalBind.Iface)
		}
	}
	out := make([]string, 0, len(seen))
	for ifname := range seen {
		out = append(out, ifname)
	}
	sort.Strings(out)
	return out
}

func probeOpenWrtRPSInterface(sysClassNetRoot, ifname string) (openWrtRPSInterfaceState, error) {
	state := openWrtRPSInterfaceState{Name: strings.TrimSpace(ifname)}
	if state.Name == "" || filepath.Base(state.Name) != state.Name {
		return state, fmt.Errorf("invalid interface name %q", ifname)
	}
	base := filepath.Join(sysClassNetRoot, state.Name)
	driver, err := filepath.EvalSymlinks(filepath.Join(base, "device", "driver"))
	if err != nil {
		return state, err
	}
	state.Driver = filepath.Base(driver)
	queuePaths, err := filepath.Glob(filepath.Join(base, "queues", "rx-*", "rps_cpus"))
	if err != nil {
		return state, err
	}
	sort.Strings(queuePaths)
	for _, path := range queuePaths {
		payload, err := os.ReadFile(path)
		if err != nil {
			return state, err
		}
		state.RXQueuePaths = append(state.RXQueuePaths, path)
		state.RXQueueMasks = append(state.RXQueueMasks, strings.TrimSpace(string(payload)))
	}
	return state, nil
}

func (daemon *Daemon) reconcileOpenWrtFullPlaintextRPS(desired config.Desired) error {
	if !openWrtFullPlaintextRPSTuningEnabledForDesired(desired) {
		return daemon.restoreOpenWrtFullPlaintextRPS()
	}
	states := make([]openWrtRPSInterfaceState, 0)
	activePaths := make(map[string]struct{})
	for _, ifname := range openWrtRPSUnderlayInterfaces(desired) {
		state, err := probeOpenWrtRPSInterface("/sys/class/net", ifname)
		if err != nil {
			continue
		}
		states = append(states, state)
		if state.Driver != "virtio_net" || len(state.RXQueueMasks) < 2 ||
			len(state.RXQueuePaths) != len(state.RXQueueMasks) {
			continue
		}
		for _, path := range state.RXQueuePaths {
			activePaths[path] = struct{}{}
		}
	}
	if err := daemon.restoreOpenWrtFullPlaintextRPSExcept(activePaths); err != nil {
		return err
	}
	return daemon.applyOpenWrtFullPlaintextRPSStates(states)
}

func openWrtFullPlaintextRPSTuningEnabledForDesired(desired config.Desired) bool {
	if !runtimeLooksLikeOpenWrt() ||
		envFalsey("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT_RPS_TUNING") ||
		envFalsey("TRUSTIX_KERNEL_DATAPATH_OPENWRT_RPS_TUNING") {
		return false
	}
	return kernelDatapathFullPlaintextEnabledForDesired(desired)
}

func (daemon *Daemon) applyOpenWrtFullPlaintextRPSStates(states []openWrtRPSInterfaceState) error {
	if daemon == nil {
		return nil
	}
	for _, state := range states {
		if state.Driver != "virtio_net" || len(state.RXQueueMasks) < 2 ||
			len(state.RXQueuePaths) != len(state.RXQueueMasks) {
			continue
		}
		if _, bad := sharedNonzeroRPSMask(state.RXQueueMasks); !bad {
			continue
		}
		for index, path := range state.RXQueuePaths {
			if daemon.kernelRPSRestore == nil {
				daemon.kernelRPSRestore = make(map[string]string)
			}
			if _, exists := daemon.kernelRPSRestore[path]; !exists {
				daemon.kernelRPSRestore[path] = state.RXQueueMasks[index]
			}
			if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
				restoreErr := daemon.restoreOpenWrtFullPlaintextRPS()
				return errors.Join(fmt.Errorf("disable shared OpenWrt RPS mask for %q: %w", path, err), restoreErr)
			}
		}
	}
	return nil
}

func (daemon *Daemon) restoreOpenWrtFullPlaintextRPS() error {
	return daemon.restoreOpenWrtFullPlaintextRPSExcept(nil)
}

func (daemon *Daemon) restoreOpenWrtFullPlaintextRPSExcept(keep map[string]struct{}) error {
	if daemon == nil || len(daemon.kernelRPSRestore) == 0 {
		return nil
	}
	var errs []error
	for path, value := range daemon.kernelRPSRestore {
		if _, ok := keep[path]; ok {
			continue
		}
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				delete(daemon.kernelRPSRestore, path)
				continue
			}
			errs = append(errs, fmt.Errorf("restore OpenWrt RPS mask %q: %w", path, err))
			continue
		}
		delete(daemon.kernelRPSRestore, path)
	}
	return errors.Join(errs...)
}

func openWrtRPSDoctorCheckForStates(states []openWrtRPSInterfaceState) (doctorCheck, bool) {
	checked := make([]string, 0, len(states))
	for _, state := range states {
		if state.Driver != "virtio_net" || len(state.RXQueueMasks) < 2 {
			continue
		}
		checked = append(checked, fmt.Sprintf("%s queues=%d", state.Name, len(state.RXQueueMasks)))
		mask, bad := sharedNonzeroRPSMask(state.RXQueueMasks)
		if !bad {
			continue
		}
		return doctorCheck{
			Name:   "openwrt_rps",
			Status: "warn",
			Detail: fmt.Sprintf("OpenWrt full plaintext datapath underlay %s uses the same nonzero RPS mask %s on all %d virtio_net RX queues; this configuration reduced measured throughput substantially. Disable packet steering during a maintenance window: %s", state.Name, mask, len(state.RXQueueMasks), openWrtRPSFix),
		}, true
	}
	if len(checked) == 0 {
		return doctorCheck{}, false
	}
	return doctorCheck{
		Name:   "openwrt_rps",
		Status: "ok",
		Detail: "OpenWrt multiqueue virtio_net underlay RPS layout is not the known shared-mask performance trap: " + strings.Join(checked, ", "),
	}, true
}

func sharedNonzeroRPSMask(masks []string) (string, bool) {
	if len(masks) < 2 {
		return "", false
	}
	first, ok := normalizeRPSMask(masks[0])
	if !ok || first == "0" {
		return "", false
	}
	for _, raw := range masks[1:] {
		mask, valid := normalizeRPSMask(raw)
		if !valid || mask != first {
			return "", false
		}
	}
	return first, true
}

func normalizeRPSMask(raw string) (string, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.ReplaceAll(raw, ",", "")
	if raw == "" {
		return "", false
	}
	for _, char := range raw {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return "", false
		}
	}
	raw = strings.TrimLeft(raw, "0")
	if raw == "" {
		return "0", true
	}
	return raw, true
}
