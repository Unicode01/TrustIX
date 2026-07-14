//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/observability"
	"trustix.local/trustix/internal/transport/kerneludp"
	"trustix.local/trustix/internal/transport/tixtcp"
)

const (
	tixTCPDefaultRingEntries                   = 4096
	tixTCPDefaultUMEMFrames                    = 4096
	tixTCPDefaultUMEMFrameSize                 = 2048
	tixTCPDefaultRXBurst                       = 256
	tixTCPDefaultRXPollTimeoutMS               = 10
	tixTCPDefaultRXIdlePollTimeoutMS           = 10
	tixTCPMinUMEMFrameSize                     = 2048
	tixTCPMaxUMEMFrameSize                     = 65536
	tixTCPDirectOnlyControlRingEntries         = 512
	tixTCPDirectOnlyControlUMEMFrames          = 1024
	ethernetHeaderLen                          = 14
	etherTypeIPv4                       uint16 = 0x0800
	tixTCPDefaultMaxQueues                     = 8
	tixTCPTXBackpressureWait                   = 50 * time.Millisecond
	tixTCPTXBackpressurePoll                   = 50 * time.Microsecond
	tixTCPDefaultTXKickBatch                   = 256
	tixTCPDefaultTXFlushInterval               = 0 * time.Microsecond
	tixTCPDefaultTXSoftKickBackoff             = 0
	tixTCPDefaultTXReclaimIdleInterval         = 100 * time.Millisecond
	tixTCPAFXDPBaseOverhead                    = ethernetHeaderLen + 20 + 20 + tixtcp.HeaderLen
	kernelUDPAFXDPBaseOverhead                 = ethernetHeaderLen + 20 + 8 + kerneludp.HeaderLen
	tixTCPAFXDPTXFrameTailroom                 = 384
	tixTCPDefaultTXMultiFrameMaxFrames         = 2
	tixTCPDefaultTXMultiFrameMaxIPv4Len        = 1500

	xdpActDrop = 1
	xdpActPass = 2
)

const (
	tixTCPXDPAttachNative    = "native"
	tixTCPXDPAttachSKB       = "skb"
	tixTCPAFXDPBindZeroCopy  = "zerocopy"
	tixTCPAFXDPBindCopy      = "copy"
	tixTCPXDPProgramName     = "trustix_tix_tcp"
	tixTCPModeEnvAuto        = "auto"
	tixTCPModeEnvNative      = "native"
	tixTCPModeEnvDriver      = "driver"
	tixTCPModeEnvDriverShort = "drv"
)

var (
	errAFXDPTXPoolExhausted = errors.New("AF_XDP tx frame pool exhausted")
	errAFXDPRingFull        = errors.New("AF_XDP ring full")
	errAFXDPKickDeferred    = errors.New("AF_XDP tx kick deferred")
)

type tixTCPAttachPlan struct {
	xdpMode    string
	xdpFlags   int
	bindMode   string
	bindFlags  uint16
	needWakeup bool
}

type tixTCPFastPathOptions struct {
	preferSKBXDPMode       bool
	preferSKBXDPModeNote   string
	forceSKBXDPMode        bool
	forceCopyBindMode      bool
	limitQueues            int
	virtioNetSafety        bool
	directOnlyControlPlane bool
}

type afXDPSocketConfig struct {
	ringEntries            uint32
	umemFrames             uint32
	umemFrameSize          uint32
	requestedUMEMFrameSize uint32
}

type tixTCPRXPollConfig struct {
	BaseTimeoutMS int
	IdleTimeoutMS int
}

type tixTCPFastPath struct {
	mu                               sync.RWMutex
	link                             netlink.Link
	xskMap                           *cebpf.Map
	portMap                          *cebpf.Map
	xdpStatsMap                      *cebpf.Map
	xdpProg                          *cebpf.Program
	xdpObject                        *tixTCPXDPObject
	txSealObject                     *tixTCPTXSealObject
	sockets                          []*afXDPSocket
	done                             chan struct{}
	wg                               sync.WaitGroup
	closeOnce                        sync.Once
	ready                            atomic.Bool
	provider                         string
	attachedXDP                      bool
	xdpAttachMode                    string
	xdpAttachFlags                   int
	afXDPBindMode                    string
	afXDPBindFlags                   uint16
	queueCount                       int
	kernelCryptoRX                   bool
	kernelCryptoTX                   bool
	skipTCPChecksum                  bool
	skipUDPChecksum                  bool
	kernelOpenInPlace                bool
	kernelUDPXDPOpen                 bool
	kernelUDPXDPPassOpened           bool
	kernelUDPXDPRXDirect             bool
	kernelUDPXDPRXSecureDirect       bool
	kernelUDPXDPRXTrustInnerChecksum bool
	directOnlyControlPlane           bool
	virtioNetSafety                  bool
	loadWarning                      string
	modeFallback                     string
	txCursor                         atomic.Uint64
	txAffinityFlow                   atomic.Uint64
	txAffinityTuple                  atomic.Uint64
	txAffinityFragment               atomic.Uint64
	txAffinityCursor                 atomic.Uint64
}

type tixTCPTXAffinityStats struct {
	flow     uint64
	tuple    uint64
	fragment uint64
	cursor   uint64
}

type receivedTIXTCPFrame struct {
	frame                   dataplane.TIXTCPFrame
	packet                  tixtcp.TCPPacket
	rawTupleValidated       bool
	kernelOpenPlain         []byte
	kernelOpenPlainRelease  func()
	kernelOpenPlainInPlace  bool
	encryptedKernelPayload  bool
	encryptedKernelFragment bool
	wireSequenceCount       uint64
}

type receivedKernelUDPFrame struct {
	frame                   dataplane.KernelUDPFrame
	packet                  kerneludp.UDPPacket
	kernelOpenPlain         []byte
	kernelOpenPlainRelease  func()
	borrowedKernelPayload   bool
	encryptedKernelPayload  bool
	encryptedKernelFragment bool
	wireInnerIPv4           bool
	wireSequenceCount       uint64
}

type afXDPRXRecycleMode uint8

const (
	afXDPRXRecycleNow afXDPRXRecycleMode = iota
	afXDPRXRecycleAfterDeliver
	afXDPRXRecycleByRelease
)

func (manager *Manager) attachTIXTCPFastPathLocked(ctx context.Context, spec dataplane.AttachSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if manager.tixTCPFastPath != nil {
		return nil
	}
	if spec.UnderlayIface == "" {
		manager.warnings = append(manager.warnings, "tix_tcp AF_XDP disabled: lan.underlay_iface is not configured")
		return nil
	}
	link, err := netlink.LinkByName(spec.UnderlayIface)
	if err != nil {
		return fmt.Errorf("inspect tix_tcp underlay iface %q: %w", spec.UnderlayIface, err)
	}
	var provider *kernelCryptoProviderObject
	if manager.kernelCryptoProductionReadyLocked() ||
		(tixTCPXDPDirectOpenKfuncEnabled() && manager.kernelCryptoDirectSlotProviderReadyLocked()) {
		provider = manager.kernelCryptoProvider
	}
	options := manager.tixTCPFastPathOptionsForSpec(spec, link)
	fastPath, err := newTIXTCPFastPathWithOptions(link, provider, options)
	if err != nil {
		detached, detachErr := detachTrustIXTIXTCPXDP(link)
		if detachErr != nil {
			return fmt.Errorf("attach tix_tcp AF_XDP fast path on %q: %w; detach stale TrustIX XDP: %v", spec.UnderlayIface, err, detachErr)
		}
		if !detached {
			return fmt.Errorf("attach tix_tcp AF_XDP fast path on %q: %w", spec.UnderlayIface, err)
		}
		link, err = netlink.LinkByName(spec.UnderlayIface)
		if err != nil {
			return fmt.Errorf("inspect tix_tcp underlay iface %q after stale XDP detach: %w", spec.UnderlayIface, err)
		}
		fastPath, err = newTIXTCPFastPathWithOptions(link, provider, options)
		if err != nil {
			return fmt.Errorf("attach tix_tcp AF_XDP fast path on %q after stale TrustIX XDP detach: %w", spec.UnderlayIface, err)
		}
	}
	if fastPath.loadWarning != "" {
		manager.warnings = append(manager.warnings, fastPath.loadWarning)
	}
	manager.tixTCPFastPath = fastPath
	fastPath.start(manager)
	return nil
}

func (manager *Manager) tixTCPFastPathOptionsForSpec(spec dataplane.AttachSpec, underlayLink netlink.Link) tixTCPFastPathOptions {
	options := tixTCPFastPathOptions{
		directOnlyControlPlane: kernelUDPTXDirectOnlyEnabled(spec),
	}
	if tixTCPVirtioNetSafetyRequired(underlayLink) {
		options.preferSKBXDPMode = true
		options.forceSKBXDPMode = true
		options.forceCopyBindMode = true
		options.virtioNetSafety = true
		options.preferSKBXDPModeNote = "virtio_net underlay uses skb/copy AF_XDP to avoid virtio_net TX watchdog while still binding all available RX/TX queues; set TRUSTIX_AF_XDP_ALLOW_UNSAFE_VIRTIO_NET=1 only for isolated native/zerocopy experiments"
		return options
	}
	if !kernelUDPXDPRXDirectEnabled() || !tixTCPXDPModeAuto() || spec.LANIface == "" {
		return options
	}
	lanLink, err := netlink.LinkByName(spec.LANIface)
	if err != nil || !isVethLink(lanLink) {
		return options
	}
	options.preferSKBXDPMode = true
	options.preferSKBXDPModeNote = "kernel_udp XDP RX direct to veth prefers skb XDP because native XDP redirect to veth is not supported by common drivers"
	return options
}

func (manager *Manager) detachTIXTCPFastPathLocked() error {
	if manager.tixTCPFastPath == nil {
		return nil
	}
	err := manager.tixTCPFastPath.Close()
	manager.tixTCPFastPath = nil
	return err
}

var detachIdleStaleTIXTCPXDP = func(manager *Manager) error {
	return manager.detachStaleTIXTCPXDPLocked(nil)
}

func (manager *Manager) detachStaleTIXTCPXDPLocked(state *persistedTIXTCPXDPState) error {
	underlay := manager.spec.UnderlayIface
	attachFlags := 0
	if state != nil && state.Attached {
		underlay = strings.TrimSpace(state.Underlay)
		if underlay == "" {
			underlay = manager.spec.UnderlayIface
		}
		attachFlags = state.AttachFlags
	}
	if underlay == "" {
		return nil
	}
	link, err := netlink.LinkByName(underlay)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("inspect stale tix_tcp XDP iface %q: %w", underlay, err)
	}
	if state == nil || !state.Attached {
		var trustix bool
		trustix, attachFlags, err = trustIXTIXTCPXDPAttach(link)
		if err != nil || !trustix {
			return nil
		}
	}
	if attachFlags == 0 {
		attachFlags = tixTCPXDPAttachFlags(link)
	}
	if err := detachTIXTCPXDP(link, attachFlags); err != nil && !isNotFound(err) && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("detach stale tix_tcp XDP program from %q: %w", underlay, err)
	}
	return nil
}

func newTIXTCPFastPath(link netlink.Link, provider *kernelCryptoProviderObject) (*tixTCPFastPath, error) {
	return newTIXTCPFastPathWithOptions(link, provider, tixTCPFastPathOptions{})
}

func newTIXTCPFastPathWithOptions(link netlink.Link, provider *kernelCryptoProviderObject, options tixTCPFastPathOptions) (*tixTCPFastPath, error) {
	queueCount := tixTCPQueueCountWithOptions(link, options)
	xdpObject, err := loadTIXTCPXDPObject(queueCount, tixTCPXDPReplacements{
		kernelCryptoProvider: provider,
	})
	if err != nil {
		return nil, err
	}
	xskMap := xdpObject.xskMap
	portMap := xdpObject.portMap
	xdpStatsMap := xdpObject.xdpStatsMap
	xdpProg := xdpObject.program
	var txSealObject *tixTCPTXSealObject
	var txSealWarning string
	if provider != nil && provider.flowIndexMap != nil && provider.contextSlots != nil {
		txSealObject, err = loadTIXTCPTXSealObject(provider)
		if err != nil {
			txSealWarning = "tix_tcp TX packet kernel seal unavailable; using provider frame seal fallback: " + err.Error()
		}
	}
	var sockets []*afXDPSocket
	var selected tixTCPAttachPlan
	var queueFallbackReason string
	var fallbackReasons []string
	for _, plan := range tixTCPAttachPlansWithOptions(options) {
		if err := netlink.LinkSetXdpFdWithFlags(link, xdpProg.FD(), plan.xdpFlags); err != nil {
			fallbackReasons = append(fallbackReasons, fmt.Sprintf("%s/%s attach failed: %v", plan.xdpMode, plan.bindMode, err))
			continue
		}
		sockets, _, queueFallbackReason, err = newTIXTCPSocketsWithQueueFallbackWithOptions(link, queueCount, plan.bindFlags, xskMap, options)
		if err == nil {
			selected = plan
			break
		}
		fallbackReasons = append(fallbackReasons, fmt.Sprintf("%s/%s AF_XDP bind failed: %v", plan.xdpMode, plan.bindMode, err))
		_ = detachTIXTCPXDP(link, plan.xdpFlags)
	}
	if len(sockets) == 0 {
		if txSealObject != nil {
			_ = txSealObject.Close()
		}
		_ = xdpObject.Close()
		return nil, fmt.Errorf("attach tix_tcp AF_XDP provider: %s", strings.Join(fallbackReasons, "; "))
	}
	config, err := configureTIXTCPBPFConfig(xdpObject.configMap, len(sockets))
	if err != nil {
		closeAFXDPSockets(sockets)
		if txSealObject != nil {
			_ = txSealObject.Close()
		}
		_ = xdpObject.Close()
		return nil, err
	}
	xdpObject.skipTCPChecksum = config&tixTCPConfigSkipTCPChecksum != 0
	loadWarning := xdpObject.fallbackReason
	if txSealWarning != "" {
		if loadWarning != "" {
			loadWarning += "; "
		}
		loadWarning += txSealWarning
	}
	if options.preferSKBXDPMode && options.preferSKBXDPModeNote != "" {
		if loadWarning != "" {
			loadWarning += "; "
		}
		loadWarning += "tix_tcp AF_XDP mode preference: " + options.preferSKBXDPModeNote
	}
	modeFallback := ""
	if len(fallbackReasons) > 0 {
		modeFallback = strings.Join(fallbackReasons, "; ")
		if loadWarning != "" {
			loadWarning += "; "
		}
		loadWarning += "tix_tcp AF_XDP mode fallback: " + modeFallback
	}
	if queueFallbackReason != "" {
		if modeFallback != "" {
			modeFallback += "; "
		}
		modeFallback += queueFallbackReason
		if loadWarning != "" {
			loadWarning += "; "
		}
		loadWarning += "tix_tcp AF_XDP queue fallback: " + queueFallbackReason
	}
	skipTCPChecksum := xdpObject.skipTCPChecksum || (txSealObject != nil && txSealObject.skipTCPChecksum)
	skipUDPChecksum := kernelUDPSkipUDPChecksum()
	kernelOpenInPlace := tixTCPKernelOpenInPlaceEnabled()
	txMultiFrameMaxFrames := tixTCPTXMultiFrameMaxFrames()
	txMultiFrameMaxIPv4Len := tixTCPTXMultiFrameMaxIPv4Len()
	txMultiFrameEncrypted := tixTCPTXMultiFrameEncryptedEnabled()
	kernelUDPXDPOpen := config&tixTCPConfigKernelUDPXDPOpen != 0
	kernelUDPXDPPassOpened := config&tixTCPConfigKernelUDPXDPPassOpened != 0
	kernelUDPXDPRXDirect := config&tixTCPConfigKernelUDPXDPRXDirect != 0
	kernelUDPXDPRXSecureDirect := config&tixTCPConfigKernelUDPXDPRXSecureDirect != 0
	kernelUDPXDPRXTrustInnerChecksum := config&tixTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum != 0
	for _, socket := range sockets {
		socket.skipTCPChecksum = skipTCPChecksum
		socket.skipUDPChecksum = skipUDPChecksum
		socket.kernelOpenInPlace = kernelOpenInPlace
		socket.txMultiFrameMaxFrames = txMultiFrameMaxFrames
		socket.txMultiFrameMaxIPv4Len = txMultiFrameMaxIPv4Len
		socket.txMultiFrameEncrypted = txMultiFrameEncrypted
	}
	fastPath := &tixTCPFastPath{
		link:                             link,
		xskMap:                           xskMap,
		portMap:                          portMap,
		xdpStatsMap:                      xdpStatsMap,
		xdpProg:                          xdpProg,
		xdpObject:                        xdpObject,
		txSealObject:                     txSealObject,
		sockets:                          sockets,
		done:                             make(chan struct{}),
		provider:                         "af_xdp",
		attachedXDP:                      true,
		xdpAttachMode:                    selected.xdpMode,
		xdpAttachFlags:                   selected.xdpFlags,
		afXDPBindMode:                    selected.bindMode,
		afXDPBindFlags:                   selected.bindFlags,
		queueCount:                       len(sockets),
		kernelCryptoRX:                   xdpObject.kernelCryptoRX,
		kernelCryptoTX:                   txSealObject != nil,
		skipTCPChecksum:                  skipTCPChecksum,
		skipUDPChecksum:                  skipUDPChecksum,
		kernelOpenInPlace:                kernelOpenInPlace,
		kernelUDPXDPOpen:                 kernelUDPXDPOpen,
		kernelUDPXDPPassOpened:           kernelUDPXDPPassOpened,
		kernelUDPXDPRXDirect:             kernelUDPXDPRXDirect,
		kernelUDPXDPRXSecureDirect:       kernelUDPXDPRXSecureDirect,
		kernelUDPXDPRXTrustInnerChecksum: kernelUDPXDPRXTrustInnerChecksum,
		directOnlyControlPlane:           options.directOnlyControlPlane,
		virtioNetSafety:                  options.virtioNetSafety,
		loadWarning:                      loadWarning,
		modeFallback:                     modeFallback,
	}
	fastPath.ready.Store(true)
	return fastPath, nil
}

func (fastPath *tixTCPFastPath) SetKernelUDPTCRXDirect(enabled bool) error {
	return fastPath.SetKernelUDPRXDirectWithOptions(enabled, false, false, tixTCPBPFConfigOptions{})
}

func (fastPath *tixTCPFastPath) SetKernelUDPRXDirect(tcDirect bool, xdpDirect bool, tcSecureDirect bool) error {
	return fastPath.SetKernelUDPRXDirectWithOptions(tcDirect, xdpDirect, tcSecureDirect, tixTCPBPFConfigOptions{})
}

func (fastPath *tixTCPFastPath) SetKernelUDPRXDirectWithOptions(tcDirect bool, xdpDirect bool, tcSecureDirect bool, options tixTCPBPFConfigOptions) error {
	if fastPath == nil || fastPath.xdpObject == nil || fastPath.xdpObject.configMap == nil {
		return nil
	}
	queueCount := fastPath.queueCount
	if queueCount <= 0 {
		queueCount = fastPath.QueueCount()
	}
	config, err := configureTIXTCPBPFConfigValueForOptions(fastPath.xdpObject.configMap, queueCount, tcDirect, xdpDirect, tcSecureDirect, options)
	if err != nil {
		return err
	}
	fastPath.xdpObject.skipTCPChecksum = config&tixTCPConfigSkipTCPChecksum != 0
	fastPath.skipTCPChecksum = fastPath.xdpObject.skipTCPChecksum || (fastPath.txSealObject != nil && fastPath.txSealObject.skipTCPChecksum)
	fastPath.kernelUDPXDPOpen = config&tixTCPConfigKernelUDPXDPOpen != 0
	fastPath.kernelUDPXDPPassOpened = config&tixTCPConfigKernelUDPXDPPassOpened != 0
	fastPath.kernelUDPXDPRXDirect = config&tixTCPConfigKernelUDPXDPRXDirect != 0
	fastPath.kernelUDPXDPRXSecureDirect = config&tixTCPConfigKernelUDPXDPRXSecureDirect != 0
	fastPath.kernelUDPXDPRXTrustInnerChecksum = config&tixTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum != 0
	return nil
}

func tixTCPAttachPlans() []tixTCPAttachPlan {
	return tixTCPAttachPlansWithOptions(tixTCPFastPathOptions{})
}

func tixTCPAttachPlansWithOptions(options tixTCPFastPathOptions) []tixTCPAttachPlan {
	xdpModes := tixTCPRequestedXDPModesWithOptions(options)
	bindMode := normalizeTIXTCPModeEnv(os.Getenv("TRUSTIX_AF_XDP_BIND_MODE"))
	needWakeupModes := tixTCPRequestedNeedWakeupModes()
	plans := make([]tixTCPAttachPlan, 0, len(xdpModes)*2*len(needWakeupModes))
	for _, xdpMode := range xdpModes {
		for _, mode := range tixTCPBindModesForXDPWithOptions(xdpMode, bindMode, options) {
			for _, needWakeup := range needWakeupModes {
				plans = append(plans, tixTCPAttachPlan{
					xdpMode:    xdpMode,
					xdpFlags:   tixTCPXDPFlags(xdpMode),
					bindMode:   mode,
					bindFlags:  tixTCPBindFlags(mode, needWakeup),
					needWakeup: needWakeup,
				})
			}
		}
	}
	return plans
}

func tixTCPRequestedXDPModes() []string {
	return tixTCPRequestedXDPModesWithOptions(tixTCPFastPathOptions{})
}

func tixTCPRequestedXDPModesWithOptions(options tixTCPFastPathOptions) []string {
	if options.forceSKBXDPMode {
		return []string{tixTCPXDPAttachSKB}
	}
	switch normalizeTIXTCPModeEnv(os.Getenv("TRUSTIX_XDP_MODE")) {
	case tixTCPModeEnvNative, tixTCPModeEnvDriver, tixTCPModeEnvDriverShort:
		return []string{tixTCPXDPAttachNative}
	case tixTCPXDPAttachSKB:
		return []string{tixTCPXDPAttachSKB}
	default:
		if options.preferSKBXDPMode {
			return []string{tixTCPXDPAttachSKB, tixTCPXDPAttachNative}
		}
		return []string{tixTCPXDPAttachNative, tixTCPXDPAttachSKB}
	}
}

func tixTCPXDPModeAuto() bool {
	value := normalizeTIXTCPModeEnv(os.Getenv("TRUSTIX_XDP_MODE"))
	return value == "" || value == tixTCPModeEnvAuto
}

func tixTCPBindModesForXDP(xdpMode string, requested string) []string {
	return tixTCPBindModesForXDPWithOptions(xdpMode, requested, tixTCPFastPathOptions{})
}

func tixTCPBindModesForXDPWithOptions(xdpMode string, requested string, options tixTCPFastPathOptions) []string {
	if options.forceCopyBindMode {
		return []string{tixTCPAFXDPBindCopy}
	}
	switch requested {
	case tixTCPAFXDPBindZeroCopy:
		return []string{tixTCPAFXDPBindZeroCopy}
	case tixTCPAFXDPBindCopy:
		return []string{tixTCPAFXDPBindCopy}
	}
	if xdpMode == tixTCPXDPAttachNative {
		return []string{tixTCPAFXDPBindZeroCopy, tixTCPAFXDPBindCopy}
	}
	return []string{tixTCPAFXDPBindCopy}
}

func normalizeTIXTCPModeEnv(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func tixTCPXDPFlags(mode string) int {
	flags := unix.XDP_FLAGS_UPDATE_IF_NOEXIST
	if mode == tixTCPXDPAttachNative {
		return flags | unix.XDP_FLAGS_DRV_MODE
	}
	return flags | unix.XDP_FLAGS_SKB_MODE
}

func tixTCPBindFlags(mode string, needWakeup bool) uint16 {
	flags := uint16(0)
	if needWakeup {
		flags |= uint16(unix.XDP_USE_NEED_WAKEUP)
	}
	if mode == tixTCPAFXDPBindZeroCopy {
		return flags | uint16(unix.XDP_ZEROCOPY)
	}
	return flags | uint16(unix.XDP_COPY)
}

func tixTCPRequestedNeedWakeupModes() []bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_AF_XDP_NEED_WAKEUP")))
	switch value {
	case "1", "true", "yes", "on", "enabled":
		return []bool{true}
	case "auto":
		return []bool{true, false}
	default:
		return []bool{false}
	}
}

func newTIXTCPSocketsWithQueueFallback(link netlink.Link, queueCount int, bindFlags uint16, xskMap *cebpf.Map) ([]*afXDPSocket, int, string, error) {
	return newTIXTCPSocketsWithQueueFallbackWithOptions(link, queueCount, bindFlags, xskMap, tixTCPFastPathOptions{})
}

func newTIXTCPSocketsWithQueueFallbackWithOptions(link netlink.Link, queueCount int, bindFlags uint16, xskMap *cebpf.Map, options tixTCPFastPathOptions) ([]*afXDPSocket, int, string, error) {
	if queueCount <= 0 {
		queueCount = 1
	}
	requestedFrameSize := tixTCPAFXDPUMEMFrameSize()
	var fallbackReasons []string
	for _, frameSize := range tixTCPAFXDPUMEMFrameSizeCandidates(requestedFrameSize) {
		ringEntries := tixTCPAFXDPRingEntriesForFrameSizeWithOptions(frameSize, options)
		config := afXDPSocketConfig{
			ringEntries:            ringEntries,
			umemFrames:             tixTCPAFXDPUMEMFramesWithOptions(ringEntries, frameSize, options),
			umemFrameSize:          frameSize,
			requestedUMEMFrameSize: requestedFrameSize,
		}
		sockets := make([]*afXDPSocket, 0, queueCount)
		for queueID := 0; queueID < queueCount; queueID++ {
			socket, err := newAFXDPSocket(link, uint32(queueID), bindFlags, config)
			if err != nil {
				reason := fmt.Sprintf("umem_frame_size=%d queue=%d bind failed: %v", frameSize, queueID, err)
				if len(sockets) > 0 {
					queueFallback := fmt.Sprintf("requested_queues=%d selected_queues=%d requested_umem_frame_size=%d selected_umem_frame_size=%d: bind queue=%d failed: %v", queueCount, len(sockets), requestedFrameSize, frameSize, queueID, err)
					if frameSize != requestedFrameSize || len(fallbackReasons) > 0 {
						queueFallback += "; umem fallback: " + strings.Join(append(fallbackReasons, reason), "; ")
					}
					return sockets, len(sockets), queueFallback, nil
				}
				closeAFXDPSockets(sockets)
				fallbackReasons = append(fallbackReasons, reason)
				break
			}
			fd := uint32(socket.fd)
			if err := xskMap.Update(uint32(queueID), fd, cebpf.UpdateAny); err != nil {
				_ = socket.Close()
				reason := fmt.Sprintf("umem_frame_size=%d queue=%d publish failed: %v", frameSize, queueID, err)
				if len(sockets) > 0 {
					queueFallback := fmt.Sprintf("requested_queues=%d selected_queues=%d requested_umem_frame_size=%d selected_umem_frame_size=%d: publish queue=%d failed: %v", queueCount, len(sockets), requestedFrameSize, frameSize, queueID, err)
					if frameSize != requestedFrameSize || len(fallbackReasons) > 0 {
						queueFallback += "; umem fallback: " + strings.Join(append(fallbackReasons, reason), "; ")
					}
					return sockets, len(sockets), queueFallback, nil
				}
				closeAFXDPSockets(sockets)
				fallbackReasons = append(fallbackReasons, reason)
				break
			}
			sockets = append(sockets, socket)
		}
		if len(sockets) == queueCount {
			if frameSize == requestedFrameSize && len(fallbackReasons) == 0 {
				return sockets, len(sockets), "", nil
			}
			return sockets, len(sockets), fmt.Sprintf("requested_umem_frame_size=%d selected_umem_frame_size=%d: %s", requestedFrameSize, frameSize, strings.Join(fallbackReasons, "; ")), nil
		}
	}
	if len(fallbackReasons) == 0 {
		return nil, 0, "", fmt.Errorf("create AF_XDP sockets: no UMEM frame size candidates")
	}
	return nil, 0, "", fmt.Errorf("%s", strings.Join(fallbackReasons, "; "))
}

func detachTrustIXTIXTCPXDP(link netlink.Link) (bool, error) {
	trustix, attachFlags, err := trustIXTIXTCPXDPAttach(link)
	if err != nil || !trustix {
		return false, err
	}
	return true, detachTIXTCPXDP(link, attachFlags)
}

func trustIXTIXTCPXDPAttach(link netlink.Link) (bool, int, error) {
	if link == nil || link.Attrs() == nil || link.Attrs().Xdp == nil || !link.Attrs().Xdp.Attached || link.Attrs().Xdp.ProgId == 0 {
		return false, 0, nil
	}
	program, err := cebpf.NewProgramFromID(cebpf.ProgramID(link.Attrs().Xdp.ProgId))
	if err != nil {
		return false, 0, err
	}
	defer program.Close()
	info, err := program.Info()
	if err != nil {
		return false, 0, err
	}
	return info.Name == tixTCPXDPProgramName, tixTCPXDPAttachFlags(link), nil
}

func tixTCPXDPAttachFlags(link netlink.Link) int {
	if link == nil || link.Attrs() == nil || link.Attrs().Xdp == nil {
		return 0
	}
	xdp := link.Attrs().Xdp
	switch xdp.AttachMode {
	case nl.XDP_ATTACHED_DRV:
		return unix.XDP_FLAGS_DRV_MODE
	case nl.XDP_ATTACHED_SKB:
		return unix.XDP_FLAGS_SKB_MODE
	case nl.XDP_ATTACHED_HW:
		return unix.XDP_FLAGS_HW_MODE
	}
	return int(xdp.Flags) & (unix.XDP_FLAGS_DRV_MODE | unix.XDP_FLAGS_SKB_MODE | unix.XDP_FLAGS_HW_MODE)
}

func tixTCPXDPDetachFlags(attachFlags int) []int {
	const modeMask = unix.XDP_FLAGS_DRV_MODE | unix.XDP_FLAGS_SKB_MODE | unix.XDP_FLAGS_HW_MODE
	candidates := make([]int, 0, 3)
	add := func(flags int) {
		if flags == 0 {
			return
		}
		for _, existing := range candidates {
			if existing == flags {
				return
			}
		}
		candidates = append(candidates, flags)
	}
	add(attachFlags & modeMask)
	add(unix.XDP_FLAGS_DRV_MODE)
	add(unix.XDP_FLAGS_SKB_MODE)
	add(unix.XDP_FLAGS_HW_MODE)
	return candidates
}

func detachTIXTCPXDP(link netlink.Link, attachFlags int) error {
	var errs []string
	for _, flags := range tixTCPXDPDetachFlags(attachFlags) {
		if err := netlink.LinkSetXdpFdWithFlags(link, -1, flags); err != nil {
			if isNotFound(err) || errors.Is(err, unix.EINVAL) {
				continue
			}
			errs = append(errs, fmt.Sprintf("flags=%d: %v", flags, err))
			continue
		}
		return nil
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

func tixTCPQueueCount(link netlink.Link) int {
	return tixTCPQueueCountWithOptions(link, tixTCPFastPathOptions{})
}

func tixTCPQueueCountWithOptions(link netlink.Link, options tixTCPFastPathOptions) int {
	queueCount := link.Attrs().NumRxQueues
	if queueCount <= 0 {
		queueCount = 1
	}
	if txQueues := link.Attrs().NumTxQueues; txQueues > 0 && queueCount > txQueues {
		queueCount = txQueues
	}
	if runtime.NumCPU() > 0 && queueCount > runtime.NumCPU() {
		queueCount = runtime.NumCPU()
	}
	if queueCount > tixTCPDefaultMaxQueues {
		queueCount = tixTCPDefaultMaxQueues
	}
	if value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_QUEUES")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			if parsed < queueCount {
				queueCount = parsed
			}
		}
	}
	if options.limitQueues > 0 && queueCount > options.limitQueues {
		queueCount = options.limitQueues
	}
	if queueCount <= 0 {
		return 1
	}
	return queueCount
}

func tixTCPVirtioNetSafetyRequired(link netlink.Link) bool {
	if !tixTCPVirtioNetSafetyEnabled() {
		return false
	}
	return isVirtioNetLink(link)
}

func tixTCPVirtioNetSafetyEnabled() bool {
	return !envTruthy(
		"TRUSTIX_AF_XDP_ALLOW_UNSAFE_VIRTIO_NET",
		"TRUSTIX_TIX_TCP_ALLOW_UNSAFE_VIRTIO_NET",
	)
}

func isVirtioNetLink(link netlink.Link) bool {
	if link == nil || link.Attrs() == nil {
		return false
	}
	name := strings.TrimSpace(link.Attrs().Name)
	if name == "" {
		return false
	}
	driverPath := filepath.Join("/sys/class/net", name, "device", "driver")
	target, err := os.Readlink(driverPath)
	if err != nil {
		return false
	}
	return filepath.Base(target) == "virtio_net"
}

func tixTCPTXBackpressureWaitDuration() time.Duration {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_AF_XDP_TX_BACKPRESSURE_WAIT")))
	switch value {
	case "":
		return tixTCPTXBackpressureWait
	case "0", "off", "false", "no", "disabled":
		return 0
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 0 {
		return tixTCPTXBackpressureWait
	}
	return parsed
}

func tixTCPTXKickBatch() uint32 {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_TX_KICK_BATCH"))
	if value == "" {
		return tixTCPDefaultTXKickBatch
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return tixTCPDefaultTXKickBatch
	}
	if parsed <= 1 {
		return 1
	}
	if parsed > 8192 {
		return 8192
	}
	return uint32(parsed)
}

func tixTCPTXFlushInterval() time.Duration {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_AF_XDP_TX_FLUSH_INTERVAL")))
	switch value {
	case "":
		return tixTCPDefaultTXFlushInterval
	case "0", "off", "false", "no", "disabled":
		return 0
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 0 {
		return tixTCPDefaultTXFlushInterval
	}
	if parsed > 50*time.Millisecond {
		return 50 * time.Millisecond
	}
	return parsed
}

func tixTCPTXDeferFlush() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_TX_DEFER_FLUSH"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func tixTCPTXDeferFlushDelay() time.Duration {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_AF_XDP_TX_DEFER_FLUSH_DELAY")))
	switch value {
	case "":
		return 50 * time.Microsecond
	case "0", "off", "false", "no", "disabled":
		return 0
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 0 {
		return 50 * time.Microsecond
	}
	if parsed > 5*time.Millisecond {
		return 5 * time.Millisecond
	}
	return parsed
}

func tixTCPTXSoftKickBackoff() time.Duration {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_AF_XDP_TX_SOFT_KICK_BACKOFF")))
	switch value {
	case "":
		return tixTCPDefaultTXSoftKickBackoff
	case "0", "off", "false", "no", "disabled":
		return 0
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 0 {
		return tixTCPDefaultTXSoftKickBackoff
	}
	if parsed > time.Millisecond {
		return time.Millisecond
	}
	return parsed
}

func tixTCPTXReclaimIdleInterval() time.Duration {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_AF_XDP_TX_RECLAIM_IDLE_INTERVAL")))
	switch value {
	case "":
		return tixTCPDefaultTXReclaimIdleInterval
	case "0", "off", "false", "no", "disabled":
		return time.Millisecond
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < time.Millisecond {
		return tixTCPDefaultTXReclaimIdleInterval
	}
	if parsed > time.Second {
		return time.Second
	}
	return parsed
}

func tixTCPTXCoalesceCopyMode() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_TX_COALESCE_COPY_MODE"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func tixTCPTXMultiFrameEnabled() bool {
	return envTruthy(
		"TRUSTIX_TIX_TCP_TX_MULTI_FRAME",
		"TRUSTIX_TIX_TCP_TX_STREAM_COALESCE",
		"TRUSTIX_TIXT_TX_MULTI_FRAME",
	)
}

func tixTCPTXMultiFrameEncryptedEnabled() bool {
	return envTruthy(
		"TRUSTIX_TIX_TCP_TX_MULTI_FRAME_ENCRYPTED",
		"TRUSTIX_TIXT_TX_MULTI_FRAME_ENCRYPTED",
	)
}

func tixTCPTXMultiFrameMaxFrames() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_MAX_FRAMES"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_TIXT_TX_MULTI_FRAME_MAX_FRAMES"))
	}
	if value == "" {
		return tixTCPDefaultTXMultiFrameMaxFrames
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 2 {
		return tixTCPDefaultTXMultiFrameMaxFrames
	}
	if parsed > 16 {
		return 16
	}
	return parsed
}

func tixTCPTXMultiFrameMaxIPv4Len() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_MAX_IPV4_LEN"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_TIXT_TX_MULTI_FRAME_MAX_IPV4_LEN"))
	}
	if value == "" {
		return tixTCPDefaultTXMultiFrameMaxIPv4Len
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 128 {
		return tixTCPDefaultTXMultiFrameMaxIPv4Len
	}
	if parsed > 0xffff {
		return 0xffff
	}
	return parsed
}

func tixTCPTXInnerAffinityEnabled() bool {
	return !envFalsey("TRUSTIX_AF_XDP_TX_INNER_AFFINITY", "TRUSTIX_AF_XDP_TX_INNER_HASH")
}

func tixTCPTXFragmentAffinityEnabled() bool {
	return envTruthy("TRUSTIX_AF_XDP_TX_FRAGMENT_AFFINITY", "TRUSTIX_TIX_TCP_TX_FRAGMENT_AFFINITY")
}

func tixTCPAFXDPTXFrameTailroomBytes() int {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_AF_XDP_TX_FRAME_TAILROOM")))
	switch value {
	case "":
		return tixTCPAFXDPTXFrameTailroom
	case "0", "off", "false", "no", "disabled":
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return tixTCPAFXDPTXFrameTailroom
	}
	if parsed > 4096 {
		return 4096
	}
	return parsed
}

func tixTCPAFXDPRingEntries() uint32 {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_RING_ENTRIES"))
	if value == "" || strings.EqualFold(value, "auto") || strings.EqualFold(value, "default") {
		return tixTCPDefaultRingEntries
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 64 {
		return tixTCPDefaultRingEntries
	}
	if parsed > 32768 {
		parsed = 32768
	}
	return uint32(nextPowerOfTwo(parsed))
}

func tixTCPAFXDPRingEntriesForFrameSize(frameSize uint32) uint32 {
	return tixTCPAFXDPRingEntriesForFrameSizeWithOptions(frameSize, tixTCPFastPathOptions{})
}

func tixTCPAFXDPRingEntriesForFrameSizeWithOptions(frameSize uint32, options tixTCPFastPathOptions) uint32 {
	ringEntries := tixTCPAFXDPRingEntries()
	if tixTCPAFXDPRingEntriesExplicit() {
		return ringEntries
	}
	if options.directOnlyControlPlane && ringEntries > tixTCPDirectOnlyControlRingEntries {
		ringEntries = tixTCPDirectOnlyControlRingEntries
	}
	switch {
	case frameSize >= 32768 && ringEntries > 1024:
		return 1024
	case frameSize >= 16384 && ringEntries > 2048:
		return 2048
	case frameSize >= 8192 && ringEntries > 4096:
		return 4096
	default:
		return ringEntries
	}
}

func tixTCPAFXDPUMEMFrameSize() uint32 {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_UMEM_FRAME_SIZE"))
	if value == "" || strings.EqualFold(value, "auto") {
		if envTruthy("TRUSTIX_AF_XDP_AUTO_UMEM_JUMBO", "TRUSTIX_TIX_TCP_AUTO_UMEM_JUMBO") {
			return 4096
		}
		return tixTCPDefaultUMEMFrameSize
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < tixTCPMinUMEMFrameSize {
		return tixTCPDefaultUMEMFrameSize
	}
	if parsed > tixTCPMaxUMEMFrameSize {
		parsed = tixTCPMaxUMEMFrameSize
	}
	return uint32(nextPowerOfTwo(parsed))
}

func tixTCPAFXDPUMEMFrameSizeCandidates(requested uint32) []uint32 {
	if requested < tixTCPMinUMEMFrameSize {
		requested = tixTCPMinUMEMFrameSize
	}
	if requested > tixTCPMaxUMEMFrameSize {
		requested = tixTCPMaxUMEMFrameSize
	}
	requested = uint32(nextPowerOfTwo(int(requested)))
	candidates := make([]uint32, 0, 8)
	seen := make(map[uint32]struct{}, 8)
	for size := requested; size >= tixTCPMinUMEMFrameSize; size /= 2 {
		if _, ok := seen[size]; !ok {
			candidates = append(candidates, size)
			seen[size] = struct{}{}
		}
		if size == tixTCPMinUMEMFrameSize {
			break
		}
	}
	if _, ok := seen[tixTCPDefaultUMEMFrameSize]; !ok {
		candidates = append(candidates, tixTCPDefaultUMEMFrameSize)
	}
	return candidates
}

func tixTCPAFXDPUMEMFrames(ringEntries uint32, frameSize uint32) uint32 {
	return tixTCPAFXDPUMEMFramesWithOptions(ringEntries, frameSize, tixTCPFastPathOptions{})
}

func tixTCPAFXDPUMEMFramesWithOptions(ringEntries uint32, frameSize uint32, options tixTCPFastPathOptions) uint32 {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_UMEM_FRAMES"))
	defaultFrames := uint32(tixTCPDefaultUMEMFrames)
	if !tixTCPAFXDPUMEMFramesExplicit() && options.directOnlyControlPlane && defaultFrames > tixTCPDirectOnlyControlUMEMFrames {
		defaultFrames = tixTCPDirectOnlyControlUMEMFrames
	}
	if ringEntries > defaultFrames/2 {
		defaultFrames = ringEntries * 2
	}
	if frameSize > tixTCPDefaultUMEMFrameSize {
		targetBytes := uint64(64 << 20)
		if frameSize >= 32768 {
			targetBytes = 128 << 20
		}
		sized := uint32(targetBytes / uint64(frameSize))
		if sized < ringEntries*2 {
			sized = ringEntries * 2
		}
		if sized < defaultFrames {
			defaultFrames = sized
		}
	}
	if value == "" || strings.EqualFold(value, "auto") || strings.EqualFold(value, "default") {
		return defaultFrames
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < int(ringEntries)+1 {
		return defaultFrames
	}
	if parsed > 262144 {
		parsed = 262144
	}
	out := uint32(nextPowerOfTwo(parsed))
	if out <= ringEntries {
		out = ringEntries * 2
	}
	return out
}

func tixTCPAFXDPRingEntriesExplicit() bool {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_RING_ENTRIES"))
	return value != "" && !strings.EqualFold(value, "auto") && !strings.EqualFold(value, "default")
}

func tixTCPAFXDPUMEMFramesExplicit() bool {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_UMEM_FRAMES"))
	return value != "" && !strings.EqualFold(value, "auto") && !strings.EqualFold(value, "default")
}

func closeAFXDPSockets(sockets []*afXDPSocket) {
	for _, socket := range sockets {
		if socket != nil {
			_ = socket.Close()
		}
	}
}

func tixTCPRXBurst() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_RX_BURST"))
	if value == "" {
		return tixTCPDefaultRXBurst
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return tixTCPDefaultRXBurst
	}
	if parsed > kernelCryptoDeviceBatchMax {
		parsed = kernelCryptoDeviceBatchMax
	}
	return parsed
}

func tixTCPRXPollTimeout() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_RX_POLL_TIMEOUT_MS"))
	if value == "" {
		return tixTCPDefaultRXPollTimeoutMS
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return tixTCPDefaultRXPollTimeoutMS
	}
	if parsed > 1000 {
		return 1000
	}
	return parsed
}

func tixTCPRXIdlePollTimeout(baseTimeoutMS int) int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_AF_XDP_RX_IDLE_POLL_TIMEOUT_MS"))
	if value == "" {
		if baseTimeoutMS > tixTCPDefaultRXIdlePollTimeoutMS {
			return baseTimeoutMS
		}
		return tixTCPDefaultRXIdlePollTimeoutMS
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		if baseTimeoutMS > tixTCPDefaultRXIdlePollTimeoutMS {
			return baseTimeoutMS
		}
		return tixTCPDefaultRXIdlePollTimeoutMS
	}
	if parsed > 1000 {
		parsed = 1000
	}
	if parsed < baseTimeoutMS {
		return baseTimeoutMS
	}
	return parsed
}

func tixTCPRXPollConfigFromEnv() tixTCPRXPollConfig {
	baseTimeoutMS := tixTCPRXPollTimeout()
	return tixTCPRXPollConfig{
		BaseTimeoutMS: baseTimeoutMS,
		IdleTimeoutMS: tixTCPRXIdlePollTimeout(baseTimeoutMS),
	}
}

func nextPowerOfTwo(value int) int {
	if value <= 1 {
		return 1
	}
	value--
	for shift := 1; shift < strconv.IntSize; shift <<= 1 {
		value |= value >> shift
	}
	return value + 1
}

func (fastPath *tixTCPFastPath) Provider() string {
	if fastPath == nil {
		return "none"
	}
	return fastPath.provider
}

func (fastPath *tixTCPFastPath) Ready() bool {
	return fastPath != nil && fastPath.ready.Load() && len(fastPath.sockets) > 0
}

func (fastPath *tixTCPFastPath) QueueCount() int {
	if fastPath == nil {
		return 0
	}
	return len(fastPath.sockets)
}

func (fastPath *tixTCPFastPath) UnderlayMTU() int {
	if fastPath == nil {
		return 0
	}
	mtu := 0
	for _, socket := range fastPath.sockets {
		if socket == nil || socket.linkMTU <= 0 {
			continue
		}
		if mtu == 0 || socket.linkMTU < mtu {
			mtu = socket.linkMTU
		}
	}
	return mtu
}

func (fastPath *tixTCPFastPath) TIXTCPPayloadMax(placement dataplane.CryptoPlacement, encrypted bool) int {
	if fastPath == nil || len(fastPath.sockets) == 0 {
		return 0
	}
	overhead := tixTCPAFXDPBaseOverhead
	if placement == dataplane.CryptoPlacementKernel || encrypted {
		overhead += tixTCPKernelCryptoOverhead
	}
	payloadMax := fastPath.afXDPPayloadMax(overhead)
	if placement == dataplane.CryptoPlacementKernel || encrypted {
		payloadMax = min(payloadMax, tixTCPXDPKernelCryptoPlainMax)
	}
	return payloadMax
}

func (fastPath *tixTCPFastPath) KernelUDPPayloadMax(placement dataplane.CryptoPlacement, encrypted bool) int {
	if fastPath == nil || len(fastPath.sockets) == 0 {
		return 0
	}
	overhead := kernelUDPAFXDPBaseOverhead
	if placement == dataplane.CryptoPlacementKernel || encrypted {
		overhead += tixTCPKernelCryptoOverhead
	}
	payloadMax := fastPath.afXDPPayloadMax(overhead)
	if placement == dataplane.CryptoPlacementKernel || encrypted {
		payloadMax = min(payloadMax, kernelCryptoFrameMaxPlain)
	}
	return payloadMax
}

func (fastPath *tixTCPFastPath) KernelUDPPayloadMaxWithDeviceCrypto() int {
	if fastPath == nil || len(fastPath.sockets) == 0 {
		return 0
	}
	overhead := kernelUDPAFXDPBaseOverhead + tixTCPKernelCryptoOverhead
	payloadMax := fastPath.afXDPPayloadMax(overhead)
	return min(payloadMax, kernelCryptoDeviceSecureMaxPlain)
}

func (fastPath *tixTCPFastPath) afXDPPayloadMax(overhead int) int {
	if fastPath == nil || len(fastPath.sockets) == 0 {
		return 0
	}
	frameSize := int(fastPath.sockets[0].umemFrameSize)
	if frameSize <= 0 {
		return 0
	}
	wireMax := frameSize - tixTCPAFXDPTXFrameTailroomBytes()
	if wireMax < overhead {
		wireMax = frameSize
	}
	return max(0, wireMax-overhead)
}

func (fastPath *tixTCPFastPath) XDPAttachMode() string {
	if fastPath == nil {
		return ""
	}
	return fastPath.xdpAttachMode
}

func (fastPath *tixTCPFastPath) AFXDPBindMode() string {
	if fastPath == nil {
		return ""
	}
	return fastPath.afXDPBindMode
}

func (fastPath *tixTCPFastPath) KernelUDPXDPRXSecureDirectEnabled() bool {
	return fastPath != nil && fastPath.kernelUDPXDPRXSecureDirect
}

func (fastPath *tixTCPFastPath) BPFConfigStats() map[string]uint64 {
	stats := map[string]uint64{
		"xdp_config_raw":                                    0,
		"xdp_config_skip_tcp_checksum":                      0,
		"xdp_config_kernel_udp_tc_rx_direct":                0,
		"xdp_config_kernel_udp_xdp_open":                    0,
		"xdp_config_kernel_udp_xdp_pass_opened":             0,
		"xdp_config_hot_path_stats":                         0,
		"xdp_config_kernel_udp_xdp_rx_direct":               0,
		"xdp_config_kernel_udp_xdp_rx_direct_ifindex":       0,
		"xdp_config_kernel_udp_tc_rx_secure_direct":         0,
		"xdp_config_kernel_udp_xdp_rx_secure_direct":        0,
		"xdp_config_kernel_udp_xdp_rx_direct_fixed_l2":      0,
		"xdp_config_fallback_pass":                          0,
		"xdp_config_kernel_udp_xdp_rx_trust_inner_checksum": 0,
		"xdp_config_queue_count":                            0,
	}
	if fastPath == nil || fastPath.xdpObject == nil || fastPath.xdpObject.configMap == nil {
		return stats
	}
	key := uint32(0)
	var config uint32
	if err := fastPath.xdpObject.configMap.Lookup(key, &config); err != nil {
		return stats
	}
	stats["xdp_config_raw"] = uint64(config)
	stats["xdp_config_skip_tcp_checksum"] = boolCounter(config&tixTCPConfigSkipTCPChecksum != 0)
	stats["xdp_config_kernel_udp_tc_rx_direct"] = boolCounter(config&tixTCPConfigKernelUDPTCRXDirect != 0)
	stats["xdp_config_kernel_udp_xdp_open"] = boolCounter(config&tixTCPConfigKernelUDPXDPOpen != 0)
	stats["xdp_config_kernel_udp_xdp_pass_opened"] = boolCounter(config&tixTCPConfigKernelUDPXDPPassOpened != 0)
	stats["xdp_config_hot_path_stats"] = boolCounter(config&tixTCPConfigHotPathStats != 0)
	stats["xdp_config_kernel_udp_xdp_rx_direct"] = boolCounter(config&tixTCPConfigKernelUDPXDPRXDirect != 0)
	stats["xdp_config_kernel_udp_xdp_rx_direct_ifindex"] = boolCounter(config&tixTCPConfigKernelUDPXDPRXDirectIfindex != 0)
	stats["xdp_config_kernel_udp_tc_rx_secure_direct"] = boolCounter(config&tixTCPConfigKernelUDPTCRXSecureDirect != 0)
	stats["xdp_config_kernel_udp_xdp_rx_secure_direct"] = boolCounter(config&tixTCPConfigKernelUDPXDPRXSecureDirect != 0)
	stats["xdp_config_kernel_udp_xdp_rx_direct_fixed_l2"] = boolCounter(config&tixTCPConfigKernelUDPXDPRXDirectFixedL2 != 0)
	stats["xdp_config_fallback_pass"] = boolCounter(config&tixTCPConfigXDPFallbackPass != 0)
	stats["xdp_config_kernel_udp_xdp_rx_trust_inner_checksum"] = boolCounter(config&tixTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum != 0)
	stats["xdp_config_queue_count"] = uint64(config >> tixTCPConfigQueueCountShift)
	return stats
}

func (fastPath *tixTCPFastPath) ZeroCopyEnabled() bool {
	return fastPath != nil && fastPath.afXDPBindMode == tixTCPAFXDPBindZeroCopy
}

func (fastPath *tixTCPFastPath) ModeFallbackReason() string {
	if fastPath == nil {
		return ""
	}
	return fastPath.modeFallback
}

func (fastPath *tixTCPFastPath) AllowDestinationPort(port uint16) error {
	if fastPath == nil || fastPath.portMap == nil {
		return nil
	}
	key := tixTCPPortMapKey(port)
	value := uint8(1)
	return fastPath.portMap.Update(key, value, cebpf.UpdateAny)
}

func (fastPath *tixTCPFastPath) DeleteAllowedDestinationPort(port uint16) error {
	if fastPath == nil || fastPath.portMap == nil {
		return nil
	}
	key := tixTCPPortMapKey(port)
	if err := fastPath.portMap.Delete(key); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (fastPath *tixTCPFastPath) SendFrame(packet tixtcp.TCPPacket, wireFrame tixtcp.Frame, resolve func(int, netip.Addr) (net.HardwareAddr, error)) error {
	fastPath.mu.RLock()
	defer fastPath.mu.RUnlock()
	if !fastPath.Ready() {
		return fmt.Errorf("tix_tcp AF_XDP fast path is not ready")
	}
	socket := fastPath.selectTXSocket(packet, wireFrame)
	dstMAC, err := resolve(socket.linkIndex, packet.DestinationIP)
	if err != nil {
		socket.stats.neighborMisses.Add(1)
		return err
	}
	socket.stats.neighborHits.Add(1)
	return socket.SendFrame(packet, wireFrame, dstMAC)
}

func (fastPath *tixTCPFastPath) SendFrames(packet tixtcp.TCPPacket, wireFrames []tixtcp.Frame, resolve func(int, netip.Addr) (net.HardwareAddr, error)) error {
	if len(wireFrames) == 0 {
		return nil
	}
	fastPath.mu.RLock()
	defer fastPath.mu.RUnlock()
	if !fastPath.Ready() {
		return fmt.Errorf("tix_tcp AF_XDP fast path is not ready")
	}
	socket := fastPath.selectTXSocket(packet, wireFrames[0])
	dstMAC, err := resolve(socket.linkIndex, packet.DestinationIP)
	if err != nil {
		socket.stats.neighborMisses.Add(1)
		return err
	}
	socket.stats.neighborHits.Add(uint64(len(wireFrames)))
	return socket.SendFrames(packet, wireFrames, dstMAC)
}

func (fastPath *tixTCPFastPath) SendUDPFrame(packet kerneludp.UDPPacket, wireFrame kerneludp.Frame, resolve func(int, netip.Addr) (net.HardwareAddr, error)) error {
	fastPath.mu.RLock()
	defer fastPath.mu.RUnlock()
	if !fastPath.Ready() {
		return fmt.Errorf("UDP AF_XDP fast path is not ready")
	}
	socket := fastPath.selectUDPTXSocket(packet, wireFrame)
	dstMAC, err := resolve(socket.linkIndex, packet.DestinationIP)
	if err != nil {
		socket.stats.neighborMisses.Add(1)
		return err
	}
	socket.stats.neighborHits.Add(1)
	return socket.SendUDPFrame(packet, wireFrame, dstMAC)
}

func (fastPath *tixTCPFastPath) SendPreparedUDPFrames(frames []preparedKernelUDPTXFrame, resolve func(int, netip.Addr) (net.HardwareAddr, error)) error {
	if len(frames) == 0 {
		return nil
	}
	fastPath.mu.RLock()
	defer fastPath.mu.RUnlock()
	if !fastPath.Ready() {
		return fmt.Errorf("UDP AF_XDP fast path is not ready")
	}
	if len(fastPath.sockets) == 1 && fastPath.afXDPBindMode == tixTCPAFXDPBindCopy && tixTCPTXCoalesceCopyMode() {
		socket := fastPath.sockets[0]
		dstIP := frames[0].packet.DestinationIP
		sameDst := true
		for i := 1; i < len(frames); i++ {
			if frames[i].packet.DestinationIP != dstIP {
				sameDst = false
				break
			}
		}
		if sameDst {
			dstMAC, err := resolve(socket.linkIndex, dstIP)
			if err != nil {
				socket.stats.neighborMisses.Add(1)
				return err
			}
			socket.stats.neighborHits.Add(uint64(len(frames)))
			return socket.SendPreparedUDPFrames(frames, dstMAC)
		}
	}
	firstSocket := fastPath.selectPreparedUDPTXSocket(frames[0])
	firstDstIP := frames[0].packet.DestinationIP
	if len(fastPath.sockets) > 1 {
		sameSocketAndDst := true
		for i := 1; i < len(frames); i++ {
			if frames[i].packet.DestinationIP != firstDstIP || fastPath.selectPreparedUDPTXSocket(frames[i]) != firstSocket {
				sameSocketAndDst = false
				break
			}
		}
		if sameSocketAndDst {
			dstMAC, err := resolve(firstSocket.linkIndex, firstDstIP)
			if err != nil {
				firstSocket.stats.neighborMisses.Add(1)
				return err
			}
			firstSocket.stats.neighborHits.Add(uint64(len(frames)))
			return firstSocket.SendPreparedUDPFrames(frames, dstMAC)
		}
	}
	type socketBatch struct {
		socket *afXDPSocket
		dstIP  netip.Addr
		dstMAC net.HardwareAddr
		items  []preparedKernelUDPTXFrame
	}
	if len(fastPath.sockets) == 1 {
		socket := fastPath.sockets[0]
		dstIP := frames[0].packet.DestinationIP
		sameDst := true
		for i := 1; i < len(frames); i++ {
			if frames[i].packet.DestinationIP != dstIP {
				sameDst = false
				break
			}
		}
		if sameDst {
			dstMAC, err := resolve(socket.linkIndex, dstIP)
			if err != nil {
				socket.stats.neighborMisses.Add(1)
				return err
			}
			socket.stats.neighborHits.Add(uint64(len(frames)))
			return socket.SendPreparedUDPFrames(frames, dstMAC)
		}
	}
	batches := make([]socketBatch, 0, len(frames))
	for _, frame := range frames {
		socket := fastPath.selectPreparedUDPTXSocket(frame)
		batchIndex := -1
		for i := range batches {
			if batches[i].socket == socket && batches[i].dstIP == frame.packet.DestinationIP {
				batchIndex = i
				break
			}
		}
		if batchIndex < 0 {
			dstMAC, err := resolve(socket.linkIndex, frame.packet.DestinationIP)
			if err != nil {
				socket.stats.neighborMisses.Add(1)
				return err
			}
			batches = append(batches, socketBatch{socket: socket, dstIP: frame.packet.DestinationIP, dstMAC: dstMAC})
			batchIndex = len(batches) - 1
		}
		batches[batchIndex].items = append(batches[batchIndex].items, frame)
	}
	for _, batch := range batches {
		batch.socket.stats.neighborHits.Add(uint64(len(batch.items)))
		if err := batch.socket.SendPreparedUDPFrames(batch.items, batch.dstMAC); err != nil {
			return err
		}
	}
	return nil
}

func (fastPath *tixTCPFastPath) SendKernelCryptoFrame(packet tixtcp.TCPPacket, wireFrame tixtcp.Frame, resolve func(int, netip.Addr) (net.HardwareAddr, error)) error {
	fastPath.mu.RLock()
	defer fastPath.mu.RUnlock()
	if !fastPath.Ready() {
		return fmt.Errorf("tix_tcp AF_XDP fast path is not ready")
	}
	if fastPath.txSealObject == nil {
		return fmt.Errorf("tix_tcp TX packet kernel seal is not ready")
	}
	socket := fastPath.selectTXSocket(packet, wireFrame)
	dstMAC, err := resolve(socket.linkIndex, packet.DestinationIP)
	if err != nil {
		socket.stats.neighborMisses.Add(1)
		return err
	}
	socket.stats.neighborHits.Add(1)
	return socket.SendKernelCryptoFrame(packet, wireFrame, dstMAC, fastPath.txSealObject)
}

func (fastPath *tixTCPFastPath) SendKernelCryptoFrames(packet tixtcp.TCPPacket, wireFrames []tixtcp.Frame, resolve func(int, netip.Addr) (net.HardwareAddr, error)) error {
	if len(wireFrames) == 0 {
		return nil
	}
	fastPath.mu.RLock()
	defer fastPath.mu.RUnlock()
	if !fastPath.Ready() {
		return fmt.Errorf("tix_tcp AF_XDP fast path is not ready")
	}
	if fastPath.txSealObject == nil {
		return fmt.Errorf("tix_tcp TX packet kernel seal is not ready")
	}
	socket := fastPath.selectTXSocket(packet, wireFrames[0])
	dstMAC, err := resolve(socket.linkIndex, packet.DestinationIP)
	if err != nil {
		socket.stats.neighborMisses.Add(1)
		return err
	}
	socket.stats.neighborHits.Add(uint64(len(wireFrames)))
	return socket.SendKernelCryptoFrames(packet, wireFrames, dstMAC, fastPath.txSealObject)
}

func (fastPath *tixTCPFastPath) SendPreparedTIXTCPFrames(frames []preparedTIXTCPTXFrame, resolve func(int, netip.Addr) (net.HardwareAddr, error)) error {
	if len(frames) == 0 {
		return nil
	}
	fastPath.mu.RLock()
	defer fastPath.mu.RUnlock()
	if !fastPath.Ready() {
		return fmt.Errorf("tix_tcp AF_XDP fast path is not ready")
	}
	var affinity tixTCPTXAffinityStats
	defer func() {
		fastPath.addTXAffinityStats(affinity)
	}()
	firstSocket := fastPath.selectPreparedTXSocketNoStats(frames[0], &affinity)
	firstDst := frames[0].packet.DestinationIP
	firstKernelTX := frames[0].kernelTX
	sameBatch := true
	for i := 1; i < len(frames); i++ {
		if frames[i].kernelTX != firstKernelTX || frames[i].packet.DestinationIP != firstDst || fastPath.selectPreparedTXSocketNoStats(frames[i], &affinity) != firstSocket {
			sameBatch = false
			break
		}
	}
	if sameBatch {
		dstMAC, err := resolve(firstSocket.linkIndex, firstDst)
		if err != nil {
			firstSocket.stats.neighborMisses.Add(1)
			return err
		}
		firstSocket.stats.neighborHits.Add(uint64(len(frames)))
		if firstKernelTX {
			if fastPath.txSealObject == nil {
				return fmt.Errorf("tix_tcp TX packet kernel seal is not ready")
			}
			return firstSocket.SendPreparedKernelCryptoFrames(frames, dstMAC, fastPath.txSealObject)
		}
		return firstSocket.SendPreparedFrames(frames, dstMAC)
	}
	type socketBatch struct {
		socket   *afXDPSocket
		dstIP    netip.Addr
		dstMAC   net.HardwareAddr
		items    []preparedTIXTCPTXFrame
		kernelTX bool
	}
	batches := make([]socketBatch, 0, len(frames))
	for _, frame := range frames {
		socket := fastPath.selectPreparedTXSocketNoStats(frame, &affinity)
		batchIndex := -1
		for i := range batches {
			if batches[i].socket == socket && batches[i].kernelTX == frame.kernelTX && batches[i].dstIP == frame.packet.DestinationIP {
				batchIndex = i
				break
			}
		}
		if batchIndex < 0 {
			dstMAC, err := resolve(socket.linkIndex, frame.packet.DestinationIP)
			if err != nil {
				socket.stats.neighborMisses.Add(1)
				return err
			}
			batches = append(batches, socketBatch{socket: socket, dstIP: frame.packet.DestinationIP, dstMAC: dstMAC, kernelTX: frame.kernelTX})
			batchIndex = len(batches) - 1
		}
		batches[batchIndex].items = append(batches[batchIndex].items, frame)
	}
	for _, batch := range batches {
		batch.socket.stats.neighborHits.Add(uint64(len(batch.items)))
		if batch.kernelTX {
			if fastPath.txSealObject == nil {
				return fmt.Errorf("tix_tcp TX packet kernel seal is not ready")
			}
			if err := batch.socket.SendPreparedKernelCryptoFrames(batch.items, batch.dstMAC, fastPath.txSealObject); err != nil {
				return err
			}
			continue
		}
		if err := batch.socket.SendPreparedFrames(batch.items, batch.dstMAC); err != nil {
			return err
		}
	}
	return nil
}

func (fastPath *tixTCPFastPath) selectTXSocket(packet tixtcp.TCPPacket, wireFrame tixtcp.Frame) *afXDPSocket {
	return fastPath.selectTXSocketNoStats(packet, wireFrame, nil)
}

func (fastPath *tixTCPFastPath) selectTXSocketNoStats(packet tixtcp.TCPPacket, wireFrame tixtcp.Frame, stats *tixTCPTXAffinityStats) *afXDPSocket {
	if len(fastPath.sockets) == 1 {
		return fastPath.sockets[0]
	}
	if wireFrame.FlowID != 0 {
		addTXAffinityFlow(fastPath, stats)
		return fastPath.sockets[tixTCPTXQueueIndex(tixTCPMix64(wireFrame.FlowID), len(fastPath.sockets))]
	}
	if hash, ok := tixTCPTupleHash(packet); ok {
		addTXAffinityTuple(fastPath, stats)
		return fastPath.sockets[tixTCPTXQueueIndex(hash, len(fastPath.sockets))]
	}
	addTXAffinityCursor(fastPath, stats)
	return fastPath.sockets[int(fastPath.txCursor.Add(1)-1)%len(fastPath.sockets)]
}

func (fastPath *tixTCPFastPath) selectPreparedTXSocket(frame preparedTIXTCPTXFrame) *afXDPSocket {
	return fastPath.selectPreparedTXSocketNoStats(frame, nil)
}

func (fastPath *tixTCPFastPath) selectPreparedTXSocketNoStats(frame preparedTIXTCPTXFrame, stats *tixTCPTXAffinityStats) *afXDPSocket {
	if len(fastPath.sockets) == 1 {
		return fastPath.sockets[0]
	}
	if tixTCPTXInnerAffinityEnabled() && frame.txInnerHashValid {
		addTXAffinityTuple(fastPath, stats)
		return fastPath.sockets[tixTCPTXQueueIndex(frame.txInnerHash, len(fastPath.sockets))]
	}
	if tixTCPTXFragmentAffinityEnabled() && frame.wireFrame.FragmentCount > 1 {
		addTXAffinityFragment(fastPath, stats)
		return fastPath.sockets[tixTCPTXQueueIndex(tixTCPPreparedFragmentHash(frame), len(fastPath.sockets))]
	}
	return fastPath.selectTXSocketNoStats(frame.packet, frame.wireFrame, stats)
}

func (fastPath *tixTCPFastPath) selectUDPTXSocket(packet kerneludp.UDPPacket, wireFrame kerneludp.Frame) *afXDPSocket {
	return fastPath.selectUDPTXSocketNoStats(packet, wireFrame, nil)
}

func (fastPath *tixTCPFastPath) selectUDPTXSocketNoStats(packet kerneludp.UDPPacket, wireFrame kerneludp.Frame, stats *tixTCPTXAffinityStats) *afXDPSocket {
	if len(fastPath.sockets) == 1 {
		return fastPath.sockets[0]
	}
	if wireFrame.FlowID != 0 {
		addTXAffinityFlow(fastPath, stats)
		return fastPath.sockets[tixTCPTXQueueIndex(tixTCPMix64(wireFrame.FlowID), len(fastPath.sockets))]
	}
	if hash, ok := kernelUDPTupleHash(packet); ok {
		addTXAffinityTuple(fastPath, stats)
		return fastPath.sockets[tixTCPTXQueueIndex(hash, len(fastPath.sockets))]
	}
	addTXAffinityCursor(fastPath, stats)
	return fastPath.sockets[int(fastPath.txCursor.Add(1)-1)%len(fastPath.sockets)]
}

func (fastPath *tixTCPFastPath) selectPreparedUDPTXSocket(frame preparedKernelUDPTXFrame) *afXDPSocket {
	return fastPath.selectPreparedUDPTXSocketNoStats(frame, nil)
}

func (fastPath *tixTCPFastPath) selectPreparedUDPTXSocketNoStats(frame preparedKernelUDPTXFrame, stats *tixTCPTXAffinityStats) *afXDPSocket {
	if len(fastPath.sockets) == 1 {
		return fastPath.sockets[0]
	}
	if tixTCPTXInnerAffinityEnabled() && frame.txInnerHashValid {
		addTXAffinityTuple(fastPath, stats)
		return fastPath.sockets[tixTCPTXQueueIndex(frame.txInnerHash, len(fastPath.sockets))]
	}
	return fastPath.selectUDPTXSocketNoStats(frame.packet, frame.wireFrame, stats)
}

func addTXAffinityFlow(fastPath *tixTCPFastPath, stats *tixTCPTXAffinityStats) {
	if stats != nil {
		stats.flow++
		return
	}
	fastPath.txAffinityFlow.Add(1)
}

func addTXAffinityTuple(fastPath *tixTCPFastPath, stats *tixTCPTXAffinityStats) {
	if stats != nil {
		stats.tuple++
		return
	}
	fastPath.txAffinityTuple.Add(1)
}

func addTXAffinityFragment(fastPath *tixTCPFastPath, stats *tixTCPTXAffinityStats) {
	if stats != nil {
		stats.fragment++
		return
	}
	fastPath.txAffinityFragment.Add(1)
}

func addTXAffinityCursor(fastPath *tixTCPFastPath, stats *tixTCPTXAffinityStats) {
	if stats != nil {
		stats.cursor++
		return
	}
	fastPath.txAffinityCursor.Add(1)
}

func (fastPath *tixTCPFastPath) addTXAffinityStats(stats tixTCPTXAffinityStats) {
	if stats.flow > 0 {
		fastPath.txAffinityFlow.Add(stats.flow)
	}
	if stats.tuple > 0 {
		fastPath.txAffinityTuple.Add(stats.tuple)
	}
	if stats.fragment > 0 {
		fastPath.txAffinityFragment.Add(stats.fragment)
	}
	if stats.cursor > 0 {
		fastPath.txAffinityCursor.Add(stats.cursor)
	}
}

func (fastPath *tixTCPFastPath) start(manager *Manager) {
	for _, socket := range fastPath.sockets {
		fastPath.wg.Add(2)
		go func(socket *afXDPSocket) {
			defer fastPath.wg.Done()
			fastPath.readLoop(manager, socket)
		}(socket)
		go func(socket *afXDPSocket) {
			defer fastPath.wg.Done()
			socket.reclaimCompletionLoop(fastPath.done)
		}(socket)
	}
}

func (fastPath *tixTCPFastPath) readLoop(manager *Manager, socket *afXDPSocket) {
	rxBurst := tixTCPRXBurst()
	pollConfig := tixTCPRXPollConfigFromEnv()
	expBatch := make([]receivedTIXTCPFrame, 0, rxBurst)
	udpBatch := make([]receivedKernelUDPFrame, 0, rxBurst)
	rxFrames := make([]afXDPRXFrame, 0, rxBurst)
	rxDescs := make([]unix.XDPDesc, rxBurst)
	heldRXFrames := make([]afXDPRXFrame, 0, rxBurst)
	idlePollTimeout := pollConfig.BaseTimeoutMS
	deliver := func() {
		if len(expBatch) > 0 {
			manager.deliverTIXTCPFrames(expBatch)
			expBatch = expBatch[:0]
		}
		if len(udpBatch) > 0 {
			manager.deliverKernelUDPFrames(udpBatch)
			udpBatch = udpBatch[:0]
		}
		socket.recycleRXFrames(heldRXFrames)
		heldRXFrames = heldRXFrames[:0]
	}
	for {
		select {
		case <-fastPath.done:
			deliver()
			return
		default:
		}
		rxFrames = rxFrames[:0]
		var err error
		rxFrames, err = socket.RecvFrames(rxFrames, rxDescs)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				deliver()
				socket.pollRX(idlePollTimeout)
				nextTimeout := nextAFXDPRXIdlePollTimeout(idlePollTimeout, pollConfig)
				if nextTimeout != idlePollTimeout {
					socket.stats.rxPollIdleBackoffs.Add(1)
				}
				idlePollTimeout = nextTimeout
				continue
			}
			if fastPath.Ready() {
				manager.mu.Lock()
				manager.warnings = append(manager.warnings, "tix_tcp AF_XDP receive stopped: "+err.Error())
				manager.mu.Unlock()
			}
			return
		}
		if idlePollTimeout != pollConfig.BaseTimeoutMS {
			socket.stats.rxPollIdleResets.Add(1)
			idlePollTimeout = pollConfig.BaseTimeoutMS
		}
		for i := range rxFrames {
			select {
			case <-fastPath.done:
				deliver()
				socket.recycleRXFrames(rxFrames[i:])
				return
			default:
			}
			recycleMode, err := fastPath.decodeRXFrame(manager, socket, &rxFrames[i], &expBatch, &udpBatch)
			if err != nil {
				if fastPath.Ready() {
					manager.mu.Lock()
					manager.warnings = append(manager.warnings, "tix_tcp AF_XDP receive stopped: "+err.Error())
					manager.mu.Unlock()
				}
				_ = rxFrames[i].Recycle()
				socket.recycleRXFrames(rxFrames[i+1:])
				return
			}
			if recycleMode == afXDPRXRecycleAfterDeliver {
				heldRXFrames = append(heldRXFrames, rxFrames[i])
			}
		}
		socket.stats.rxBatches.Add(1)
		socket.stats.rxBatchFrames.Add(uint64(len(rxFrames)))
		if len(expBatch)+len(udpBatch) >= rxBurst || len(heldRXFrames) >= rxBurst {
			deliver()
		}
	}
}

func nextAFXDPRXIdlePollTimeout(current int, config tixTCPRXPollConfig) int {
	if config.IdleTimeoutMS <= config.BaseTimeoutMS {
		return config.BaseTimeoutMS
	}
	if current <= 0 {
		if config.IdleTimeoutMS > 1 {
			return 1
		}
		return config.IdleTimeoutMS
	}
	if current < config.BaseTimeoutMS {
		current = config.BaseTimeoutMS
	}
	next := current * 2
	if next < current || next > config.IdleTimeoutMS {
		return config.IdleTimeoutMS
	}
	return next
}

func (fastPath *tixTCPFastPath) handleRXFrame(manager *Manager, socket *afXDPSocket, rxFrame *afXDPRXFrame) (err error) {
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame
	recycleMode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		return err
	}
	manager.deliverTIXTCPFrames(expBatch)
	manager.deliverKernelUDPFrames(udpBatch)
	if recycleMode == afXDPRXRecycleAfterDeliver {
		return rxFrame.Recycle()
	}
	return nil
}

func (fastPath *tixTCPFastPath) decodeRXFrame(manager *Manager, socket *afXDPSocket, rxFrame *afXDPRXFrame, expBatch *[]receivedTIXTCPFrame, udpBatch *[]receivedKernelUDPFrame) (recycleMode afXDPRXRecycleMode, err error) {
	defer func() {
		if recycleMode != afXDPRXRecycleNow {
			return
		}
		if recycleErr := rxFrame.Recycle(); recycleErr != nil && err == nil {
			err = recycleErr
		}
	}()
	defer func() {
		if recovered := recover(); recovered != nil {
			if expBatch != nil {
				*expBatch = (*expBatch)[:0]
			}
			if udpBatch != nil {
				*udpBatch = (*udpBatch)[:0]
			}
			if socket != nil {
				socket.stats.rxParseErrors.Add(1)
			}
			if manager != nil {
				manager.recordDrop(observability.DropInvalidOverlayHeader)
				stack := string(debug.Stack())
				if len(stack) > 4096 {
					stack = stack[:4096]
				}
				manager.mu.Lock()
				manager.warnings = append(manager.warnings, fmt.Sprintf("tix_tcp AF_XDP RX decode recovered: %v\n%s", recovered, stack))
				manager.mu.Unlock()
			}
			recycleMode = afXDPRXRecycleNow
			err = nil
		}
	}()
	if rxFrame == nil {
		return afXDPRXRecycleNow, nil
	}
	if socket == nil {
		return afXDPRXRecycleNow, fmt.Errorf("tix_tcp AF_XDP RX decode missing socket")
	}
	packet, srcMAC, ok := parseEthernetIPv4Frame(rxFrame.Bytes())
	if !ok {
		return afXDPRXRecycleNow, nil
	}
	protocol, ok := ipv4Protocol(packet)
	if !ok {
		socket.stats.rxParseErrors.Add(1)
		manager.recordDrop(observability.DropInvalidOverlayHeader)
		return afXDPRXRecycleNow, nil
	}
	if protocol == unix.IPPROTO_UDP {
		return fastPath.decodeUDPFrame(manager, socket, rxFrame, packet, srcMAC, nil, udpBatch)
	}
	if protocol != unix.IPPROTO_TCP {
		return afXDPRXRecycleNow, nil
	}
	parseTCP := tixtcp.ParseTCPShapedIPv4NoCopy
	if fastPath.skipTCPChecksum {
		parseTCP = tixtcp.ParseTCPShapedIPv4NoCopySkipTCPChecksum
	}
	tcpPacket, err := parseTCP(packet)
	if err != nil {
		return fastPath.decodeUDPFrame(manager, socket, rxFrame, packet, srcMAC, err, udpBatch)
	}
	return fastPath.decodeTCPFrame(manager, socket, rxFrame, tcpPacket, srcMAC, expBatch)
}

func (fastPath *tixTCPFastPath) handleTCPFrame(manager *Manager, socket *afXDPSocket, tcpPacket tixtcp.TCPPacket, srcMAC net.HardwareAddr) error {
	var batch []receivedTIXTCPFrame
	if _, err := fastPath.decodeTCPFrame(manager, socket, nil, tcpPacket, srcMAC, &batch); err != nil {
		return err
	}
	manager.deliverTIXTCPFrames(batch)
	return nil
}

func (fastPath *tixTCPFastPath) decodeTCPFrame(manager *Manager, socket *afXDPSocket, rxFrame *afXDPRXFrame, tcpPacket tixtcp.TCPPacket, srcMAC net.HardwareAddr, batch *[]receivedTIXTCPFrame) (afXDPRXRecycleMode, error) {
	if len(tcpPacket.Payload) == 0 {
		socket.stats.rxParseErrors.Add(1)
		return afXDPRXRecycleNow, nil
	}
	socket.learnRXNeighbor(manager, tcpPacket.SourceIP, srcMAC)
	var wireFrameScratch [4]tixtcp.Frame
	wireFrames, err := tixtcp.ParseFrameStreamNoCopyInto(tcpPacket.Payload, wireFrameScratch[:0])
	if err != nil {
		socket.stats.rxParseErrors.Add(1)
		manager.recordDrop(observability.DropInvalidOverlayHeader)
		return afXDPRXRecycleNow, nil
	}
	if len(wireFrames) == 0 {
		socket.stats.rxParseErrors.Add(1)
		manager.recordDrop(observability.DropInvalidOverlayHeader)
		return afXDPRXRecycleNow, nil
	}
	if len(wireFrames) > 1 {
		socket.stats.rxMultiFrameBatches.Add(1)
		socket.stats.rxMultiFrameFrames.Add(uint64(len(wireFrames)))
	}
	var borrowedIndexScratch [4]int
	borrowedIndexes := borrowedIndexScratch[:0]
	for i := range wireFrames {
		borrowed, err := fastPath.decodeTCPWireFrame(manager, socket, rxFrame, tcpPacket, wireFrames[i], batch)
		if err != nil {
			return afXDPRXRecycleNow, err
		}
		if borrowed {
			borrowedIndexes = append(borrowedIndexes, len(*batch)-1)
		}
	}
	if len(borrowedIndexes) == 0 || rxFrame == nil {
		return afXDPRXRecycleNow, nil
	}
	release := func() {
		_ = rxFrame.Recycle()
	}
	if len(borrowedIndexes) > 1 {
		release = kernelUDPRefCountRelease(release, len(borrowedIndexes))
	}
	for _, index := range borrowedIndexes {
		(*batch)[index].frame.Release = release
	}
	return afXDPRXRecycleByRelease, nil
}

func (fastPath *tixTCPFastPath) decodeTCPWireFrame(manager *Manager, socket *afXDPSocket, rxFrame *afXDPRXFrame, tcpPacket tixtcp.TCPPacket, wireFrame tixtcp.Frame, batch *[]receivedTIXTCPFrame) (bool, error) {
	payload := wireFrame.Payload
	placement := dataplane.CryptoPlacementUserspace
	encrypted := wireFrame.Flags&tixtcp.FlagEncrypted != 0
	kernelOpened := wireFrame.Flags&tixtcp.FlagKernelOpened != 0
	cryptoFragment := wireFrame.Flags&tixtcp.FlagCryptoFragment != 0
	innerIPv4 := wireFrame.Flags&tixtcp.FlagInnerIPv4 != 0
	openInPlace := encrypted && !kernelOpened && !cryptoFragment && rxFrame != nil && socket != nil && socket.kernelOpenInPlace
	borrowedRX := false
	if kernelOpened {
		placement = dataplane.CryptoPlacementKernel
		innerIPv4 = innerIPv4 && kernelUDPInnerIPv4Eligible(payload)
		manager.recordTIXTCPKernelFrameOpened()
		if rxFrame != nil && wireFrame.FragmentCount == 0 && wireFrame.FragmentIndex == 0 {
			borrowedRX = true
		} else {
			payload = append([]byte(nil), payload...)
		}
	} else if encrypted {
		if !cryptoFragment || wireFrame.FragmentIndex == 0 {
			if _, _, _, err := kernelCryptoSecureFrameMetadata(payload, wireFrame.Sequence); err != nil {
				socket.stats.rxParseErrors.Add(1)
				manager.recordDrop(observability.DropCryptoFailed)
				return false, nil
			}
		}
		if cryptoFragment && (wireFrame.FragmentCount <= 1 || wireFrame.FragmentIndex >= wireFrame.FragmentCount) {
			socket.stats.rxParseErrors.Add(1)
			manager.recordDrop(observability.DropInvalidOverlayHeader)
			return false, nil
		}
		placement = dataplane.CryptoPlacementKernel
		if openInPlace {
			borrowedRX = true
		} else {
			payload = append([]byte(nil), payload...)
		}
	} else if rxFrame != nil && wireFrame.FragmentCount == 0 && wireFrame.FragmentIndex == 0 {
		if tixTCPUserspaceSecurePayload(wireFrame.Payload) {
			payload = append([]byte(nil), wireFrame.Payload...)
		} else {
			borrowedRX = true
			payload = wireFrame.Payload
		}
		innerIPv4 = innerIPv4 && kernelUDPInnerIPv4Eligible(payload)
	} else {
		payload = append([]byte(nil), payload...)
		innerIPv4 = innerIPv4 && kernelUDPInnerIPv4Eligible(payload)
	}
	openPlain, openRelease := kernelUDPOpenPlainBuffer(encrypted && !kernelOpened && !cryptoFragment && !openInPlace, len(payload))
	*batch = append(*batch, receivedTIXTCPFrame{
		frame: dataplane.TIXTCPFrame{
			FlowID:          wireFrame.FlowID,
			Direction:       dataplane.TIXTCPInbound,
			Epoch:           wireFrame.Epoch,
			Sequence:        wireFrame.Sequence,
			FragmentIndex:   wireFrame.FragmentIndex,
			FragmentCount:   wireFrame.FragmentCount,
			Payload:         payload,
			Encrypted:       encrypted || kernelOpened,
			InnerIPv4:       innerIPv4,
			CryptoPlacement: placement,
		},
		kernelOpenPlain:         openPlain,
		kernelOpenPlainRelease:  openRelease,
		kernelOpenPlainInPlace:  openInPlace,
		packet:                  tcpPacket,
		encryptedKernelPayload:  encrypted && !kernelOpened,
		encryptedKernelFragment: encrypted && cryptoFragment && !kernelOpened,
	})
	return borrowedRX, nil
}

func tixTCPUserspaceSecurePayload(payload []byte) bool {
	return len(payload) >= 4 &&
		payload[0] == 'T' &&
		payload[1] == 'I' &&
		payload[2] == 'X' &&
		(payload[3] == 'D' || payload[3] == 'H')
}

func (fastPath *tixTCPFastPath) handleUDPFrame(manager *Manager, socket *afXDPSocket, packet []byte, srcMAC net.HardwareAddr, tcpErr error) error {
	var batch []receivedKernelUDPFrame
	if _, err := fastPath.decodeUDPFrame(manager, socket, nil, packet, srcMAC, tcpErr, &batch); err != nil {
		return err
	}
	manager.deliverKernelUDPFrames(batch)
	return nil
}

func (fastPath *tixTCPFastPath) decodeUDPFrame(manager *Manager, socket *afXDPSocket, rxFrame *afXDPRXFrame, packet []byte, srcMAC net.HardwareAddr, tcpErr error, batch *[]receivedKernelUDPFrame) (afXDPRXRecycleMode, error) {
	parseUDP := kerneludp.ParseUDPIPv4NoCopy
	if fastPath.skipUDPChecksum || (socket != nil && socket.skipUDPChecksum) {
		parseUDP = kerneludp.ParseUDPIPv4NoCopySkipChecksum
	}
	udpPacket, err := parseUDP(packet)
	if err != nil {
		if errors.Is(tcpErr, tixtcp.ErrChecksum) || errors.Is(err, kerneludp.ErrChecksum) {
			socket.stats.rxChecksumErrors.Add(1)
			manager.recordDrop(observability.DropChecksumError)
		} else {
			socket.stats.rxParseErrors.Add(1)
			manager.recordDrop(observability.DropInvalidOverlayHeader)
		}
		return afXDPRXRecycleNow, nil
	}
	if len(udpPacket.Payload) == 0 {
		socket.stats.rxParseErrors.Add(1)
		return afXDPRXRecycleNow, nil
	}
	socket.learnRXNeighbor(manager, udpPacket.SourceIP, srcMAC)
	wireFrame, err := kerneludp.ParseFrameNoCopy(udpPacket.Payload)
	if err != nil {
		socket.stats.rxParseErrors.Add(1)
		manager.recordDrop(observability.DropInvalidOverlayHeader)
		return afXDPRXRecycleNow, nil
	}
	recycleMode := afXDPRXRecycleNow
	payload := wireFrame.Payload
	placement := dataplane.CryptoPlacementUserspace
	encrypted := wireFrame.Flags&kerneludp.FlagEncrypted != 0
	kernelOpened := wireFrame.Flags&kerneludp.FlagKernelOpened != 0
	cryptoFragment := wireFrame.Flags&kerneludp.FlagCryptoFragment != 0
	innerIPv4 := wireFrame.Flags&kerneludp.FlagInnerIPv4 != 0
	var suite string
	var epoch uint64
	if kernelOpened {
		placement = dataplane.CryptoPlacementKernel
		manager.recordTIXTCPKernelFrameOpened()
		if rxFrame != nil && wireFrame.FragmentCount == 0 && wireFrame.FragmentIndex == 0 {
			recycleMode = afXDPRXRecycleByRelease
		} else {
			payload = append([]byte(nil), payload...)
		}
		innerIPv4 = innerIPv4 && kernelUDPInnerIPv4Eligible(payload)
	} else if encrypted && cryptoFragment {
		*batch = append(*batch, receivedKernelUDPFrame{
			frame: dataplane.KernelUDPFrame{
				FlowID:          wireFrame.FlowID,
				Direction:       dataplane.KernelTransportInbound,
				Sequence:        wireFrame.Sequence,
				FragmentIndex:   wireFrame.FragmentIndex,
				FragmentCount:   wireFrame.FragmentCount,
				Payload:         payload,
				Encrypted:       true,
				InnerIPv4:       innerIPv4,
				CryptoPlacement: dataplane.CryptoPlacementKernel,
			},
			packet:                  udpPacket,
			encryptedKernelPayload:  true,
			encryptedKernelFragment: true,
		})
		return afXDPRXRecycleAfterDeliver, nil
	} else if encrypted {
		_, openedSuite, openedEpoch, err := kernelCryptoSecureFrameMetadata(payload, wireFrame.Sequence)
		if err != nil {
			socket.stats.rxParseErrors.Add(1)
			manager.recordDrop(observability.DropCryptoFailed)
			return afXDPRXRecycleNow, nil
		}
		plainLen := len(payload) - kernelCryptoSecureHeaderLen - kernelCryptoFrameTagLen
		if plainLen < 0 {
			socket.stats.rxParseErrors.Add(1)
			manager.recordDrop(observability.DropCryptoFailed)
			return afXDPRXRecycleNow, nil
		}
		suite = openedSuite
		epoch = openedEpoch
		placement = dataplane.CryptoPlacementKernel
		if rxFrame != nil {
			recycleMode = afXDPRXRecycleAfterDeliver
		}
	} else if rxFrame != nil && wireFrame.FragmentCount == 0 && wireFrame.FragmentIndex == 0 {
		recycleMode = afXDPRXRecycleByRelease
		innerIPv4 = innerIPv4 && kernelUDPInnerIPv4Eligible(payload)
	} else {
		payload = append([]byte(nil), payload...)
		innerIPv4 = innerIPv4 && kernelUDPInnerIPv4Eligible(payload)
	}
	openPlain, openRelease := kernelUDPOpenPlainBuffer(encrypted && !kernelOpened && !cryptoFragment, len(payload))
	*batch = append(*batch, receivedKernelUDPFrame{
		frame: dataplane.KernelUDPFrame{
			FlowID:          wireFrame.FlowID,
			Direction:       dataplane.KernelTransportInbound,
			Epoch:           epoch,
			Sequence:        wireFrame.Sequence,
			FragmentIndex:   wireFrame.FragmentIndex,
			FragmentCount:   wireFrame.FragmentCount,
			Payload:         payload,
			Encrypted:       encrypted || kernelOpened,
			InnerIPv4:       innerIPv4,
			CryptoSuite:     suite,
			CryptoPlacement: placement,
			Release:         openRelease,
		},
		packet:                  udpPacket,
		kernelOpenPlain:         openPlain,
		kernelOpenPlainRelease:  openRelease,
		encryptedKernelPayload:  encrypted && !kernelOpened,
		encryptedKernelFragment: encrypted && cryptoFragment && !kernelOpened,
	})
	if recycleMode == afXDPRXRecycleByRelease {
		rxFrameRef := rxFrame
		(*batch)[len(*batch)-1].frame.Release = func() {
			_ = rxFrameRef.Recycle()
		}
	}
	return recycleMode, nil
}

type kernelUDPOpenPlainPool struct {
	size int
	pool sync.Pool
}

var kernelUDPOpenPlainPools = []kernelUDPOpenPlainPool{
	{size: 1024},
	{size: 2048},
	{size: 4096},
	{size: 8192},
	{size: 16384},
	{size: 32768},
	{size: 65536},
}

func kernelUDPOpenPlainBuffer(enabled bool, payloadLen int) ([]byte, func()) {
	if !enabled {
		return nil, nil
	}
	plainLen := payloadLen - kernelCryptoSecureHeaderLen - kernelCryptoFrameTagLen
	if plainLen <= 0 {
		return nil, nil
	}
	for i := range kernelUDPOpenPlainPools {
		pool := &kernelUDPOpenPlainPools[i]
		if plainLen > pool.size {
			continue
		}
		var buf []byte
		if value := pool.pool.Get(); value != nil {
			buf = value.([]byte)
		}
		if cap(buf) < pool.size {
			buf = make([]byte, pool.size)
		}
		buf = buf[:plainLen]
		released := false
		release := func() {
			if released {
				return
			}
			released = true
			pool.pool.Put(buf[:pool.size])
		}
		return buf, release
	}
	return make([]byte, plainLen), nil
}

func tixTCPKernelOpenInPlaceEnabled() bool {
	return envTruthy(
		"TRUSTIX_TIX_TCP_KERNEL_OPEN_INPLACE",
		"TRUSTIX_TIX_TCP_KERNEL_OPEN_IN_PLACE",
	)
}

func (fastPath *tixTCPFastPath) Close() error {
	var errs []string
	fastPath.closeOnce.Do(func() {
		fastPath.mu.Lock()
		defer fastPath.mu.Unlock()
		fastPath.ready.Store(false)
		close(fastPath.done)
		fastPath.wg.Wait()
		if fastPath.attachedXDP {
			if err := detachTIXTCPXDP(fastPath.link, fastPath.xdpAttachFlags); err != nil && !isNotFound(err) {
				errs = append(errs, "detach tix_tcp XDP program: "+err.Error())
			}
			fastPath.attachedXDP = false
		}
		if fastPath.xdpObject != nil {
			if err := fastPath.xdpObject.Close(); err != nil {
				errs = append(errs, "close tix_tcp XDP object: "+err.Error())
			}
			fastPath.xdpObject = nil
			fastPath.xdpProg = nil
			fastPath.xskMap = nil
			fastPath.portMap = nil
			fastPath.xdpStatsMap = nil
		}
		if fastPath.xdpProg != nil {
			if err := fastPath.xdpProg.Close(); err != nil {
				errs = append(errs, "close tix_tcp XDP program: "+err.Error())
			}
			fastPath.xdpProg = nil
		}
		if fastPath.txSealObject != nil {
			if err := fastPath.txSealObject.Close(); err != nil {
				errs = append(errs, "close tix_tcp TX seal XDP object: "+err.Error())
			}
			fastPath.txSealObject = nil
		}
		if fastPath.xskMap != nil {
			if err := fastPath.xskMap.Close(); err != nil {
				errs = append(errs, "close tix_tcp XSK map: "+err.Error())
			}
			fastPath.xskMap = nil
		}
		if fastPath.portMap != nil {
			if err := fastPath.portMap.Close(); err != nil {
				errs = append(errs, "close tix_tcp port map: "+err.Error())
			}
			fastPath.portMap = nil
		}
		if fastPath.xdpStatsMap != nil {
			if err := fastPath.xdpStatsMap.Close(); err != nil {
				errs = append(errs, "close tix_tcp XDP stats map: "+err.Error())
			}
			fastPath.xdpStatsMap = nil
		}
		for _, socket := range fastPath.sockets {
			if err := socket.Close(); err != nil {
				errs = append(errs, fmt.Sprintf("close tix_tcp AF_XDP socket queue=%d: %v", socket.queueID, err))
			}
		}
		fastPath.sockets = nil
	})
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (fastPath *tixTCPFastPath) Stats() map[string]uint64 {
	if fastPath == nil {
		return nil
	}
	var ringEntries uint32
	var umemFrames uint32
	var umemFrameSize uint32
	var requestedUMEMFrameSize uint32
	if len(fastPath.sockets) > 0 {
		ringEntries = fastPath.sockets[0].ringEntries
		umemFrames = fastPath.sockets[0].umemFrames
		umemFrameSize = fastPath.sockets[0].umemFrameSize
		requestedUMEMFrameSize = fastPath.sockets[0].requestedUMEMFrameSize
	} else {
		ringEntries = tixTCPDefaultRingEntries
		umemFrames = tixTCPDefaultUMEMFrames
		umemFrameSize = tixTCPDefaultUMEMFrameSize
		requestedUMEMFrameSize = tixTCPDefaultUMEMFrameSize
	}
	stats := map[string]uint64{
		"queues":                          uint64(len(fastPath.sockets)),
		"ring_entries_per_queue":          uint64(ringEntries),
		"umem_frames_per_queue":           uint64(umemFrames),
		"umem_frame_size_bytes":           uint64(umemFrameSize),
		"umem_frame_size_requested_bytes": uint64(requestedUMEMFrameSize),
		"umem_frame_size_fallback":        boolCounter(requestedUMEMFrameSize != 0 && requestedUMEMFrameSize != umemFrameSize),
		"tx_frame_tailroom_bytes":         uint64(tixTCPAFXDPTXFrameTailroomBytes()),
		"tix_tcp_payload_max":             uint64(fastPath.TIXTCPPayloadMax(dataplane.CryptoPlacementUserspace, false)),
		"kernel_udp_payload_max":          uint64(fastPath.KernelUDPPayloadMax(dataplane.CryptoPlacementUserspace, false)),
		"umem_bytes_per_queue":            uint64(umemFrames * umemFrameSize),
		"umem_bytes_total":                uint64(len(fastPath.sockets)) * uint64(umemFrames) * uint64(umemFrameSize),
		"kernel_crypto_rx_attached":       boolCounter(fastPath.kernelCryptoRX),
		"kernel_crypto_tx_packet":         boolCounter(fastPath.kernelCryptoTX),
		"kernel_udp_xdp_open":             boolCounter(fastPath.kernelUDPXDPOpen),
		"kernel_udp_xdp_pass_opened":      boolCounter(fastPath.kernelUDPXDPPassOpened),
		"kernel_udp_xdp_rx_direct":        boolCounter(fastPath.kernelUDPXDPRXDirect),
		"kernel_udp_xdp_rx_secure_direct": boolCounter(fastPath.kernelUDPXDPRXSecureDirect),
		"direct_only_control_plane":       boolCounter(fastPath.directOnlyControlPlane),
		"virtio_net_safety":               boolCounter(fastPath.virtioNetSafety),
		"skip_tcp_checksum":               boolCounter(fastPath.skipTCPChecksum),
		"skip_udp_checksum":               boolCounter(fastPath.skipUDPChecksum),
		"xdp_attach_native":               boolCounter(fastPath.xdpAttachMode == tixTCPXDPAttachNative),
		"xdp_attach_skb":                  boolCounter(fastPath.xdpAttachMode == tixTCPXDPAttachSKB),
		"af_xdp_bind_zerocopy":            boolCounter(fastPath.afXDPBindMode == tixTCPAFXDPBindZeroCopy),
		"af_xdp_bind_copy":                boolCounter(fastPath.afXDPBindMode == tixTCPAFXDPBindCopy),
		"zerocopy_enabled":                boolCounter(fastPath.ZeroCopyEnabled()),
		"tx_affinity_flow":                fastPath.txAffinityFlow.Load(),
		"tx_affinity_tuple":               fastPath.txAffinityTuple.Load(),
		"tx_affinity_fragment":            fastPath.txAffinityFragment.Load(),
		"tx_affinity_cursor":              fastPath.txAffinityCursor.Load(),
		"tx_coalesce_copy_mode":           boolCounter(fastPath.afXDPBindMode == tixTCPAFXDPBindCopy && tixTCPTXCoalesceCopyMode()),
		"rx_burst_config":                 uint64(tixTCPRXBurst()),
	}
	rxPollConfig := tixTCPRXPollConfigFromEnv()
	stats["rx_poll_timeout_ms"] = uint64(rxPollConfig.BaseTimeoutMS)
	stats["rx_idle_poll_timeout_ms"] = uint64(rxPollConfig.IdleTimeoutMS)
	if len(fastPath.sockets) > 0 && fastPath.sockets[0].txBackpressureWait > 0 {
		stats["tx_backpressure_wait_ns"] = uint64(fastPath.sockets[0].txBackpressureWait.Nanoseconds())
	}
	if len(fastPath.sockets) > 0 {
		stats["tx_kick_batch"] = uint64(fastPath.sockets[0].txKickBatch)
		stats["tx_flush_interval_ns"] = uint64(fastPath.sockets[0].txFlushInterval.Nanoseconds())
		stats["tx_reclaim_idle_interval_ns"] = uint64(tixTCPTXReclaimIdleInterval().Nanoseconds())
		stats["tx_soft_kick_backoff_ns"] = uint64(fastPath.sockets[0].txSoftKickBackoff.Nanoseconds())
	}
	for _, socket := range fastPath.sockets {
		freeFrames, capacityFrames := socket.txFreeCounts()
		stats["tx_free_frames_total"] += uint64(freeFrames)
		stats["tx_capacity_frames_total"] += uint64(capacityFrames)
		socketStats := socket.Stats()
		queuePrefix := fmt.Sprintf("queue_%d_", socket.queueID)
		stats[queuePrefix+"tx_free_frames"] = uint64(freeFrames)
		stats[queuePrefix+"tx_capacity_frames"] = uint64(capacityFrames)
		for name, value := range socketStats {
			stats[name] += value
			stats[queuePrefix+name] = value
		}
	}
	for name, value := range fastPath.XDPStats() {
		stats[name] = value
	}
	for name, value := range fastPath.BPFConfigStats() {
		stats[name] = value
	}
	for name, value := range fastPath.TXSealStats() {
		stats[name] = value
	}
	return stats
}

func (fastPath *tixTCPFastPath) XDPStats() map[string]uint64 {
	if fastPath == nil {
		return tixTCPXDPStatsFromMap(nil)
	}
	return tixTCPXDPStatsFromMap(fastPath.xdpStatsMap)
}

func tixTCPXDPStatsFromMap(xdpStatsMap *cebpf.Map) map[string]uint64 {
	keys := []struct {
		key  uint32
		name string
	}{
		{key: 0, name: "xdp_redirected"},
		{key: 1, name: "xdp_unauthorized_drops"},
		{key: 2, name: "xdp_pass"},
		{key: 3, name: "xdp_parse_errors"},
		{key: 4, name: "xdp_kernel_crypto_open_attempts"},
		{key: 5, name: "xdp_kernel_crypto_open_successes"},
		{key: 6, name: "xdp_kernel_crypto_open_errors"},
		{key: 7, name: "xdp_kernel_crypto_replay_drops"},
		{key: 8, name: "xdp_kernel_crypto_no_context_drops"},
		{key: 9, name: "xdp_kernel_crypto_header_errors"},
		{key: 10, name: "xdp_kernel_crypto_deferred_to_userspace"},
		{key: 11, name: "xdp_kernel_crypto_tcp_checksum_skipped"},
		{key: 12, name: "xdp_queue_fallback"},
		{key: 13, name: "xdp_allowed_invalid_drops"},
		{key: 14, name: "xdp_kernel_udp_tc_rx_direct_pass"},
		{key: 15, name: "xdp_kernel_udp_plaintext_candidates"},
		{key: 16, name: "xdp_kernel_udp_inner_ipv4_misses"},
		{key: 17, name: "xdp_kernel_udp_inner_ipv4_at88"},
		{key: 18, name: "xdp_kernel_udp_rx_direct_redirects"},
		{key: 19, name: "xdp_kernel_udp_rx_direct_neighbor_misses"},
		{key: 20, name: "xdp_kernel_udp_rx_direct_errors"},
		{key: 21, name: "xdp_kernel_udp_rx_direct_candidates"},
		{key: 22, name: "xdp_kernel_udp_rx_direct_neighbor_hits"},
		{key: 23, name: "xdp_kernel_udp_rx_direct_broadcasts"},
		{key: 24, name: "xdp_kernel_udp_rx_direct_adjust_head_errors"},
		{key: 25, name: "xdp_kernel_udp_rx_direct_tail_errors"},
		{key: 26, name: "xdp_kernel_udp_rx_direct_post_adjust_errors"},
		{key: 27, name: "xdp_kernel_udp_rx_direct_len_errors"},
		{key: 28, name: "xdp_kernel_udp_rx_direct_ifindex_redirects"},
		{key: 29, name: "xdp_kernel_udp_rx_direct_devmap_redirects"},
		{key: 30, name: "xdp_kernel_udp_rx_direct_config_misses"},
		{key: 31, name: "xdp_kernel_crypto_direct_open_successes"},
		{key: 32, name: "xdp_kernel_crypto_direct_open_fallbacks"},
		{key: 33, name: "xdp_kernel_crypto_fallback_open_successes"},
		{key: 34, name: "xdp_kernel_crypto_payload_len_errors"},
		{key: 35, name: "xdp_kernel_crypto_secure_header_errors"},
		{key: 36, name: "xdp_kernel_crypto_frame_header_errors"},
		{key: 37, name: "xdp_kernel_crypto_epoch_sequence_mismatches"},
		{key: 38, name: "xdp_kernel_crypto_cipher_len_errors"},
		{key: 39, name: "xdp_kernel_crypto_cipher_load_errors"},
		{key: 40, name: "xdp_kernel_crypto_context_misses"},
		{key: 41, name: "xdp_kernel_crypto_state_misses"},
		{key: 42, name: "xdp_kernel_crypto_zero_plain_errors"},
		{key: 43, name: "xdp_kernel_crypto_context_unavailable"},
		{key: 44, name: "xdp_kernel_crypto_epoch_mismatches"},
		{key: 45, name: "xdp_kernel_crypto_suite_mismatches"},
		{key: 46, name: "xdp_kernel_crypto_dynptr_errors"},
		{key: 47, name: "xdp_kernel_crypto_decrypt_errors"},
		{key: 48, name: "xdp_kernel_crypto_replay_commit_errors"},
		{key: 49, name: "xdp_kernel_crypto_store_errors"},
		{key: 50, name: "xdp_kernel_udp_rx_direct_csum_errors"},
	}
	stats := make(map[string]uint64, len(keys))
	if xdpStatsMap == nil {
		for _, item := range keys {
			stats[item.name] = 0
		}
		return stats
	}
	for _, item := range keys {
		stats[item.name] = 0
		if value, err := bpfCounterValue(xdpStatsMap, item.key); err == nil {
			stats[item.name] = value
		}
	}
	return stats
}

func (fastPath *tixTCPFastPath) TXSealStats() map[string]uint64 {
	if fastPath == nil || fastPath.txSealObject == nil {
		var object *tixTCPTXSealObject
		return object.Stats()
	}
	return fastPath.txSealObject.Stats()
}

func tixTCPPortMapKey(port uint16) uint32 {
	var wire [2]byte
	binary.BigEndian.PutUint16(wire[:], port)
	return uint32(binary.LittleEndian.Uint16(wire[:]))
}

func tixTCPTXQueueIndex(hash uint64, queueCount int) int {
	if queueCount <= 1 {
		return 0
	}
	return int(hash % uint64(queueCount))
}

func tixTCPTupleHash(packet tixtcp.TCPPacket) (uint64, bool) {
	if !packet.SourceIP.Is4() || !packet.DestinationIP.Is4() {
		return 0, false
	}
	src := packet.SourceIP.As4()
	dst := packet.DestinationIP.As4()
	hash := uint64(0xcbf29ce484222325)
	for _, value := range src {
		hash = tixTCPHashByte(hash, value)
	}
	for _, value := range dst {
		hash = tixTCPHashByte(hash, value)
	}
	hash = tixTCPHashByte(hash, byte(packet.SourcePort>>8))
	hash = tixTCPHashByte(hash, byte(packet.SourcePort))
	hash = tixTCPHashByte(hash, byte(packet.DestinationPort>>8))
	hash = tixTCPHashByte(hash, byte(packet.DestinationPort))
	hash = tixTCPHashByte(hash, byte(unix.IPPROTO_TCP))
	return tixTCPMix64(hash), true
}

func kernelUDPTupleHash(packet kerneludp.UDPPacket) (uint64, bool) {
	if !packet.SourceIP.Is4() || !packet.DestinationIP.Is4() {
		return 0, false
	}
	src := packet.SourceIP.As4()
	dst := packet.DestinationIP.As4()
	hash := uint64(0xcbf29ce484222325)
	for _, value := range src {
		hash = tixTCPHashByte(hash, value)
	}
	for _, value := range dst {
		hash = tixTCPHashByte(hash, value)
	}
	hash = tixTCPHashByte(hash, byte(packet.SourcePort>>8))
	hash = tixTCPHashByte(hash, byte(packet.SourcePort))
	hash = tixTCPHashByte(hash, byte(packet.DestinationPort>>8))
	hash = tixTCPHashByte(hash, byte(packet.DestinationPort))
	hash = tixTCPHashByte(hash, byte(unix.IPPROTO_UDP))
	return tixTCPMix64(hash), true
}

func innerIPv4TXHash(packet []byte) (uint64, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || ihl > len(packet) {
		return 0, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || totalLen > len(packet) {
		return 0, false
	}
	return innerIPv4TXHashFromHeader(packet, ihl, totalLen)
}

func innerIPv4TXHashPartial(packet []byte) (uint64, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || ihl > len(packet) {
		return 0, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl {
		return 0, false
	}
	availableTotalLen := totalLen
	if availableTotalLen > len(packet) {
		availableTotalLen = len(packet)
	}
	return innerIPv4TXHashFromHeader(packet, ihl, availableTotalLen)
}

func innerIPv4TXHashFromHeader(packet []byte, ihl int, totalLen int) (uint64, bool) {
	protocol := packet[9]
	hash := uint64(0xcbf29ce484222325)
	for _, value := range packet[12:16] {
		hash = tixTCPHashByte(hash, value)
	}
	for _, value := range packet[16:20] {
		hash = tixTCPHashByte(hash, value)
	}
	payload := packet[ihl:totalLen]
	switch protocol {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
		if len(payload) < 4 {
			return 0, false
		}
		hash = tixTCPHashByte(hash, payload[0])
		hash = tixTCPHashByte(hash, payload[1])
		hash = tixTCPHashByte(hash, payload[2])
		hash = tixTCPHashByte(hash, payload[3])
	case unix.IPPROTO_ICMP:
		if len(payload) >= 4 {
			hash = tixTCPHashByte(hash, payload[0])
			hash = tixTCPHashByte(hash, payload[1])
			hash = tixTCPHashByte(hash, payload[2])
			hash = tixTCPHashByte(hash, payload[3])
		}
	default:
		if len(payload) >= 4 {
			hash = tixTCPHashByte(hash, payload[0])
			hash = tixTCPHashByte(hash, payload[1])
			hash = tixTCPHashByte(hash, payload[2])
			hash = tixTCPHashByte(hash, payload[3])
		}
	}
	hash = tixTCPHashByte(hash, protocol)
	return tixTCPMix64(hash), true
}

func dataSessionBatchFirstInnerIPv4TXHash(packet []byte) (uint64, bool) {
	const (
		batchHeaderLen     = 8
		batchItemHeaderLen = 2
		batchMaxPackets    = 256
	)
	if len(packet) < batchHeaderLen ||
		packet[0] != 'T' || packet[1] != 'I' || packet[2] != 'X' || packet[3] != 'B' ||
		packet[4] != 1 {
		return 0, false
	}
	count := int(binary.BigEndian.Uint16(packet[6:8]))
	if count <= 0 || count > batchMaxPackets {
		return 0, false
	}
	offset := batchHeaderLen
	for i := 0; i < count; i++ {
		if len(packet)-offset < batchItemHeaderLen {
			return 0, false
		}
		size := int(binary.BigEndian.Uint16(packet[offset : offset+batchItemHeaderLen]))
		offset += batchItemHeaderLen
		if size <= 0 || len(packet)-offset < size {
			return 0, false
		}
		if hash, ok := innerIPv4TXHash(packet[offset : offset+size]); ok {
			return hash, true
		}
		offset += size
	}
	return 0, false
}

func dataSessionBatchFirstInnerIPv4TXHashFromFragment(packet []byte, offset int) (uint64, bool) {
	const batchHeaderLen = 8
	if offset < 0 || offset >= len(packet) || len(packet)-offset < batchHeaderLen {
		return 0, false
	}
	fragment := packet[offset:]
	if fragment[0] != 'T' || fragment[1] != 'I' || fragment[2] != 'X' || fragment[3] != 'B' ||
		fragment[4] != 1 {
		return 0, false
	}
	count := int(binary.BigEndian.Uint16(fragment[6:8]))
	if count <= 0 || count > 256 || len(fragment) < batchHeaderLen+2 {
		return 0, false
	}
	size := int(binary.BigEndian.Uint16(fragment[batchHeaderLen : batchHeaderLen+2]))
	if size <= 0 {
		return 0, false
	}
	payloadStart := batchHeaderLen + 2
	if len(fragment)-payloadStart >= size {
		return innerIPv4TXHash(fragment[payloadStart : payloadStart+size])
	}
	return innerIPv4TXHashPartial(fragment[payloadStart:])
}

func fragmentedTIXTCPInnerHash(frames []dataplane.TIXTCPFrame, index int) (uint64, bool) {
	if index < 0 || index >= len(frames) {
		return 0, false
	}
	frame := frames[index]
	count := int(frame.FragmentCount)
	if count <= 1 || int(frame.FragmentIndex) >= count {
		return 0, false
	}
	groupStart := index - int(frame.FragmentIndex)
	if groupStart < 0 || groupStart >= len(frames) {
		return 0, false
	}
	first := frames[groupStart]
	if first.FlowID != frame.FlowID || first.FragmentIndex != 0 || int(first.FragmentCount) != count {
		return 0, false
	}
	if first.InnerIPv4 {
		if hash, ok := innerIPv4TXHash(first.Payload); ok {
			return hash, true
		}
	}
	return dataSessionBatchFirstInnerIPv4TXHashFromFragment(first.Payload, 0)
}

func fragmentedPreparedTIXTCPInnerHash(frames []preparedTIXTCPTXFrame, index int) (uint64, bool) {
	if index < 0 || index >= len(frames) {
		return 0, false
	}
	frame := frames[index]
	count := int(frame.wireFrame.FragmentCount)
	if count <= 1 || int(frame.wireFrame.FragmentIndex) >= count {
		return 0, false
	}
	groupStart := index - int(frame.wireFrame.FragmentIndex)
	if groupStart < 0 || groupStart >= len(frames) {
		return 0, false
	}
	first := frames[groupStart]
	if first.wireFrame.FlowID != frame.wireFrame.FlowID || first.wireFrame.FragmentIndex != 0 || int(first.wireFrame.FragmentCount) != count {
		return 0, false
	}
	if first.txInnerHashValid {
		return first.txInnerHash, true
	}
	if first.wireFrame.Flags&tixtcp.FlagInnerIPv4 != 0 {
		if hash, ok := innerIPv4TXHash(first.wireFrame.Payload); ok {
			return hash, true
		}
	}
	return dataSessionBatchFirstInnerIPv4TXHashFromFragment(first.wireFrame.Payload, 0)
}

func tixTCPPreparedFragmentHash(frame preparedTIXTCPTXFrame) uint64 {
	wire := frame.wireFrame
	hash := uint64(0xcbf29ce484222325)
	hash = tixTCPHashUint64(hash, wire.FlowID)
	hash = tixTCPHashUint64(hash, wire.Sequence)
	hash = tixTCPHashByte(hash, byte(wire.FragmentIndex>>8))
	hash = tixTCPHashByte(hash, byte(wire.FragmentIndex))
	hash = tixTCPHashByte(hash, byte(wire.FragmentCount>>8))
	hash = tixTCPHashByte(hash, byte(wire.FragmentCount))
	return tixTCPMix64(hash)
}

func tixTCPHashUint64(hash uint64, value uint64) uint64 {
	hash = tixTCPHashByte(hash, byte(value>>56))
	hash = tixTCPHashByte(hash, byte(value>>48))
	hash = tixTCPHashByte(hash, byte(value>>40))
	hash = tixTCPHashByte(hash, byte(value>>32))
	hash = tixTCPHashByte(hash, byte(value>>24))
	hash = tixTCPHashByte(hash, byte(value>>16))
	hash = tixTCPHashByte(hash, byte(value>>8))
	return tixTCPHashByte(hash, byte(value))
}

func tixTCPHashByte(hash uint64, value byte) uint64 {
	hash ^= uint64(value)
	return hash * 0x100000001b3
}

func tixTCPMix64(value uint64) uint64 {
	value ^= value >> 30
	value *= 0xbf58476d1ce4e5b9
	value ^= value >> 27
	value *= 0x94d049bb133111eb
	value ^= value >> 31
	return value
}

func (socket *afXDPSocket) learnRXNeighbor(manager *Manager, addr netip.Addr, mac net.HardwareAddr) {
	if socket == nil || manager == nil || !addr.Is4() || len(mac) != 6 {
		return
	}
	if socket.rxNeighborValid &&
		socket.rxNeighborAddr == addr &&
		socket.rxNeighborMAC[0] == mac[0] &&
		socket.rxNeighborMAC[1] == mac[1] &&
		socket.rxNeighborMAC[2] == mac[2] &&
		socket.rxNeighborMAC[3] == mac[3] &&
		socket.rxNeighborMAC[4] == mac[4] &&
		socket.rxNeighborMAC[5] == mac[5] {
		return
	}
	manager.learnNeighbor(socket.linkIndex, addr, mac)
	socket.rxNeighborAddr = addr
	copy(socket.rxNeighborMAC[:], mac[:6])
	socket.rxNeighborValid = true
}

type afXDPSocket struct {
	fd              int
	linkIndex       int
	linkMAC         net.HardwareAddr
	linkMTU         int
	queueID         uint32
	rxNeighborAddr  netip.Addr
	rxNeighborMAC   [6]byte
	rxNeighborValid bool

	umem []byte
	rx   xdpDescRing
	tx   xdpDescRing
	fill xdpUint64Ring
	comp xdpUint64Ring

	txFree                 []uint64
	txBatchDescs           []unix.XDPDesc
	txBatchAddrs           []uint64
	rxRecycleState         []atomic.Uint64
	rxRecycleBatch         []uint64
	rxRecyclePending       []uint64
	txBackpressureWait     time.Duration
	txBackpressurePoll     time.Duration
	txFlushInterval        time.Duration
	txSoftKickBackoff      time.Duration
	txKickBatch            uint32
	txDeferFlush           bool
	txDeferFlushDelay      time.Duration
	ringEntries            uint32
	umemFrames             uint32
	umemFrameSize          uint32
	requestedUMEMFrameSize uint32
	needWakeup             bool
	txMu                   sync.Mutex
	txNotify               chan struct{}
	txPendingKick          uint32
	txBatchActive          bool
	txLastKick             time.Time
	txLastSoftKick         time.Time
	txSocketGSOFD          int
	txSocketGSOFDValid     bool
	txSocketGSODisabled    bool
	skipTCPChecksum        bool
	skipUDPChecksum        bool
	kernelOpenInPlace      bool
	txMultiFrameMaxFrames  int
	txMultiFrameMaxIPv4Len int
	txMultiFrameEncrypted  bool

	stats     afXDPSocketStats
	closeOnce sync.Once
}

type afXDPSocketStats struct {
	rxFrames                         atomic.Uint64
	rxBatches                        atomic.Uint64
	rxBatchFrames                    atomic.Uint64
	rxUMEMDirectFrames               atomic.Uint64
	rxInvalid                        atomic.Uint64
	rxParseErrors                    atomic.Uint64
	rxChecksumErrors                 atomic.Uint64
	rxRecycleErrors                  atomic.Uint64
	rxRecycleDeferred                atomic.Uint64
	rxRecycleFlushes                 atomic.Uint64
	rxPolls                          atomic.Uint64
	rxPollWakeups                    atomic.Uint64
	rxPollIdleBackoffs               atomic.Uint64
	rxPollIdleResets                 atomic.Uint64
	rxPollSoftErrors                 atomic.Uint64
	rxMultiFrameBatches              atomic.Uint64
	rxMultiFrameFrames               atomic.Uint64
	rxNeedWakeupSeen                 atomic.Uint64
	fillNeedWakeupSeen               atomic.Uint64
	txNeedWakeupSeen                 atomic.Uint64
	ringNeedWakeupEnabled            atomic.Uint64
	txFrames                         atomic.Uint64
	txBatchSubmissions               atomic.Uint64
	txBatchFrames                    atomic.Uint64
	txMultiFrameBatches              atomic.Uint64
	txMultiFrameInputFrames          atomic.Uint64
	txMultiFrameAttempts             atomic.Uint64
	txMultiFrameSingletons           atomic.Uint64
	txMultiFrameDisabled             atomic.Uint64
	txMultiFrameRejectFirst          atomic.Uint64
	txMultiFrameRejectNext           atomic.Uint64
	txMultiFrameRejectTuple          atomic.Uint64
	txMultiFrameRejectMTU            atomic.Uint64
	txMultiFrameRejectMax            atomic.Uint64
	txMultiFrameRejectError          atomic.Uint64
	txMultiFrameRejectKernelTX       atomic.Uint64
	txMultiFrameRejectEncrypted      atomic.Uint64
	txMultiFrameRejectCryptoFragment atomic.Uint64
	txMultiFrameRejectFlags          atomic.Uint64
	txMultiFrameRejectFragment       atomic.Uint64
	txSocketGSOAttempts              atomic.Uint64
	txSocketGSOSuccesses             atomic.Uint64
	txSocketGSOMessages              atomic.Uint64
	txSocketGSOInputFrames           atomic.Uint64
	txSocketGSOSegments              atomic.Uint64
	txSocketGSOSingles               atomic.Uint64
	txSocketGSOFallbacks             atomic.Uint64
	txSocketGSOUnsupported           atomic.Uint64
	txSocketGSOErrors                atomic.Uint64
	txSocketGSORejectIneligible      atomic.Uint64
	txSocketGSORejectNoBenefit       atomic.Uint64
	txSocketGSORejectKernelTX        atomic.Uint64
	txSocketGSORejectKernelOpened    atomic.Uint64
	txSocketGSORejectNotSecure       atomic.Uint64
	txSocketGSORejectFlags           atomic.Uint64
	txSocketGSORejectFragment        atomic.Uint64
	txSocketGSORejectFrameLen        atomic.Uint64
	txSocketGSORejectTuple           atomic.Uint64
	txSocketGSORejectSequence        atomic.Uint64
	txSocketGSORejectPacketLen       atomic.Uint64
	txSocketGSORejectMaxSegments     atomic.Uint64
	txSocketGSORejectMaxIPv4Len      atomic.Uint64
	txUMEMDirectBuild                atomic.Uint64
	txCompletions                    atomic.Uint64
	txPoolExhausted                  atomic.Uint64
	txRingFull                       atomic.Uint64
	txKickErrors                     atomic.Uint64
	txKickSoftErrors                 atomic.Uint64
	txKicks                          atomic.Uint64
	txKickNeedWakeupSkips            atomic.Uint64
	txKickDeferred                   atomic.Uint64
	txDeferredFlushes                atomic.Uint64
	txBackpressureWaits              atomic.Uint64
	txBackpressureReclaims           atomic.Uint64
	txBackpressureTimeouts           atomic.Uint64
	mtuExceeded                      atomic.Uint64
	neighborHits                     atomic.Uint64
	neighborMisses                   atomic.Uint64
}

type afXDPRXFrame struct {
	socket       *afXDPSocket
	addr         uint64
	data         []byte
	recycleIndex uint32
	recycleToken uint64
	recycled     *atomic.Bool
}

func newAFXDPSocket(link netlink.Link, queueID uint32, bindFlags uint16, config afXDPSocketConfig) (*afXDPSocket, error) {
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open AF_XDP socket: %w", err)
	}
	if config.umemFrameSize == 0 {
		config.umemFrameSize = tixTCPAFXDPUMEMFrameSize()
	}
	if config.ringEntries == 0 {
		config.ringEntries = tixTCPAFXDPRingEntriesForFrameSize(config.umemFrameSize)
	}
	if config.umemFrames == 0 {
		config.umemFrames = tixTCPAFXDPUMEMFrames(config.ringEntries, config.umemFrameSize)
	}
	if config.requestedUMEMFrameSize == 0 {
		config.requestedUMEMFrameSize = config.umemFrameSize
	}
	socket := &afXDPSocket{
		fd:                     fd,
		linkIndex:              link.Attrs().Index,
		linkMAC:                append(net.HardwareAddr(nil), link.Attrs().HardwareAddr...),
		linkMTU:                link.Attrs().MTU,
		queueID:                queueID,
		txSocketGSOFD:          -1,
		txFree:                 make([]uint64, 0, int(config.umemFrames-config.ringEntries)),
		rxRecycleState:         make([]atomic.Uint64, int(config.umemFrames)),
		rxRecycleBatch:         make([]uint64, 0, int(config.ringEntries)),
		txBackpressureWait:     tixTCPTXBackpressureWaitDuration(),
		txBackpressurePoll:     tixTCPTXBackpressurePoll,
		txFlushInterval:        tixTCPTXFlushInterval(),
		txSoftKickBackoff:      tixTCPTXSoftKickBackoff(),
		txKickBatch:            tixTCPTXKickBatch(),
		txDeferFlush:           tixTCPTXDeferFlush(),
		txDeferFlushDelay:      tixTCPTXDeferFlushDelay(),
		txNotify:               make(chan struct{}, 1),
		ringEntries:            config.ringEntries,
		umemFrames:             config.umemFrames,
		umemFrameSize:          config.umemFrameSize,
		requestedUMEMFrameSize: config.requestedUMEMFrameSize,
		needWakeup:             bindFlags&uint16(unix.XDP_USE_NEED_WAKEUP) != 0,
	}
	if socket.needWakeup {
		socket.stats.ringNeedWakeupEnabled.Store(1)
	}
	if err := socket.configure(bindFlags); err != nil {
		_ = socket.Close()
		return nil, err
	}
	return socket, nil
}

func (socket *afXDPSocket) configure(bindFlags uint16) error {
	umemSize := int(socket.umemFrames * socket.umemFrameSize)
	umem, err := unix.Mmap(-1, 0, umemSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("allocate AF_XDP UMEM: %w", err)
	}
	socket.umem = umem

	reg := unix.XDPUmemReg{
		Addr: uint64(uintptr(unsafe.Pointer(&socket.umem[0]))),
		Len:  uint64(len(socket.umem)),
		Size: socket.umemFrameSize,
	}
	if err := setsockoptXDPUmemReg(socket.fd, &reg); err != nil {
		return fmt.Errorf("register AF_XDP UMEM: %w", err)
	}
	for _, item := range []struct {
		opt  int
		name string
	}{
		{opt: unix.XDP_UMEM_FILL_RING, name: "fill"},
		{opt: unix.XDP_UMEM_COMPLETION_RING, name: "completion"},
		{opt: unix.XDP_RX_RING, name: "rx"},
		{opt: unix.XDP_TX_RING, name: "tx"},
	} {
		if err := unix.SetsockoptInt(socket.fd, unix.SOL_XDP, item.opt, int(socket.ringEntries)); err != nil {
			return fmt.Errorf("configure AF_XDP %s ring: %w", item.name, err)
		}
	}
	offsets, err := getsockoptXDPMmapOffsets(socket.fd)
	if err != nil {
		return fmt.Errorf("read AF_XDP mmap offsets: %w", err)
	}
	if err := socket.mmapRings(offsets); err != nil {
		return err
	}
	for i := uint64(0); i < uint64(socket.ringEntries); i++ {
		if err := socket.fill.Push(i * uint64(socket.umemFrameSize)); err != nil {
			return fmt.Errorf("prime AF_XDP fill ring: %w", err)
		}
	}
	for i := uint64(socket.ringEntries); i < uint64(socket.umemFrames); i++ {
		socket.txFree = append(socket.txFree, i*uint64(socket.umemFrameSize))
	}
	if err := unix.Bind(socket.fd, &unix.SockaddrXDP{Flags: bindFlags, Ifindex: uint32(socket.linkIndex), QueueID: socket.queueID}); err != nil {
		return fmt.Errorf("bind AF_XDP socket to ifindex=%d queue=%d: %w", socket.linkIndex, socket.queueID, err)
	}
	return nil
}

func (socket *afXDPSocket) mmapRings(offsets unix.XDPMmapOffsets) error {
	var err error
	socket.rx, err = newXDPDescRing(socket.fd, unix.XDP_PGOFF_RX_RING, offsets.Rx, socket.ringEntries)
	if err != nil {
		return fmt.Errorf("mmap AF_XDP rx ring: %w", err)
	}
	socket.tx, err = newXDPDescRing(socket.fd, unix.XDP_PGOFF_TX_RING, offsets.Tx, socket.ringEntries)
	if err != nil {
		return fmt.Errorf("mmap AF_XDP tx ring: %w", err)
	}
	socket.fill, err = newXDPUint64Ring(socket.fd, unix.XDP_UMEM_PGOFF_FILL_RING, offsets.Fr, socket.ringEntries)
	if err != nil {
		return fmt.Errorf("mmap AF_XDP fill ring: %w", err)
	}
	socket.comp, err = newXDPUint64Ring(socket.fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING, offsets.Cr, socket.ringEntries)
	if err != nil {
		return fmt.Errorf("mmap AF_XDP completion ring: %w", err)
	}
	return nil
}

func (socket *afXDPSocket) RecvFrame() (afXDPRXFrame, error) {
	socket.drainRXRecyclePending()
	desc, ok := socket.rx.Pop()
	if !ok {
		socket.recordNeedWakeupSnapshot()
		return afXDPRXFrame{}, unix.EAGAIN
	}
	return socket.rxFrameFromDesc(desc)
}

func (socket *afXDPSocket) RecvFrames(frames []afXDPRXFrame, descs []unix.XDPDesc) ([]afXDPRXFrame, error) {
	socket.drainRXRecyclePending()
	if len(descs) == 0 {
		socket.recordNeedWakeupSnapshot()
		return frames, unix.EAGAIN
	}
	n := socket.rx.PopBatch(descs)
	if n == 0 {
		socket.recordNeedWakeupSnapshot()
		return frames, unix.EAGAIN
	}
	descs = descs[:n]
	for i, desc := range descs {
		frame, err := socket.rxFrameFromDesc(desc)
		if err != nil {
			for j := range frames {
				_ = frames[j].Recycle()
			}
			for _, remaining := range descs[i+1:] {
				_ = socket.recycleRXAddr(remaining.Addr)
			}
			return frames[:0], err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func (socket *afXDPSocket) rxFrameFromDesc(desc unix.XDPDesc) (afXDPRXFrame, error) {
	start := int(desc.Addr)
	end := start + int(desc.Len)
	if start < 0 || end < start || end > len(socket.umem) {
		socket.stats.rxInvalid.Add(1)
		_ = socket.fill.Push(desc.Addr)
		return afXDPRXFrame{}, fmt.Errorf("AF_XDP rx descriptor out of bounds addr=%d len=%d", desc.Addr, desc.Len)
	}
	socket.stats.rxFrames.Add(1)
	socket.stats.rxUMEMDirectFrames.Add(1)
	recycleIndex := uint32(0)
	if socket.umemFrameSize > 0 {
		recycleIndex = uint32(desc.Addr / uint64(socket.umemFrameSize))
	}
	var recycleToken uint64
	if int(recycleIndex) < len(socket.rxRecycleState) {
		state := &socket.rxRecycleState[recycleIndex]
		recycleToken = (state.Load() &^ uint64(1)) + 2
		state.Store(recycleToken)
	}
	return afXDPRXFrame{socket: socket, addr: desc.Addr, data: socket.umem[start:end], recycleIndex: recycleIndex, recycleToken: recycleToken}, nil
}

func (socket *afXDPSocket) pollRX(timeoutMS int) {
	socket.drainRXRecyclePending()
	socket.recordNeedWakeupSnapshot()
	socket.stats.rxPolls.Add(1)
	n, err := unix.Poll([]unix.PollFd{{Fd: int32(socket.fd), Events: unix.POLLIN}}, timeoutMS)
	if err != nil {
		socket.stats.rxPollSoftErrors.Add(1)
		return
	}
	if n > 0 {
		socket.stats.rxPollWakeups.Add(1)
	}
}

func (frame *afXDPRXFrame) Bytes() []byte {
	if frame == nil {
		return nil
	}
	return frame.data
}

func (frame *afXDPRXFrame) Recycle() error {
	if frame == nil || frame.socket == nil {
		return nil
	}
	if !frame.markRecycled() {
		frame.data = nil
		return nil
	}
	if err := frame.socket.recycleRXAddr(frame.addr); err != nil {
		frame.socket.stats.rxRecycleErrors.Add(1)
		frame.data = nil
		return fmt.Errorf("recycle AF_XDP rx frame: %w", err)
	}
	frame.data = nil
	return nil
}

func (frame *afXDPRXFrame) markRecycled() bool {
	if frame.recycled != nil {
		return frame.recycled.CompareAndSwap(false, true)
	}
	socket := frame.socket
	if socket == nil || int(frame.recycleIndex) >= len(socket.rxRecycleState) {
		return true
	}
	token := frame.recycleToken
	if token == 0 {
		token = socket.rxRecycleState[frame.recycleIndex].Load() &^ uint64(1)
	}
	return socket.rxRecycleState[frame.recycleIndex].CompareAndSwap(token, token|1)
}

func (socket *afXDPSocket) recycleRXAddr(addr uint64) error {
	socket.drainRXRecyclePending()
	if err := socket.fill.Push(addr); err == nil {
		return nil
	} else if !errors.Is(err, errAFXDPRingFull) {
		return err
	}
	limit := int(socket.umemFrames)
	if limit <= 0 {
		limit = int(socket.ringEntries)
	}
	if len(socket.rxRecyclePending) >= limit {
		return fmt.Errorf("%w: RX recycle backlog full", errAFXDPRingFull)
	}
	socket.rxRecyclePending = append(socket.rxRecyclePending, addr)
	socket.stats.rxRecycleDeferred.Add(1)
	return nil
}

func (socket *afXDPSocket) recycleRXFrames(frames []afXDPRXFrame) {
	if len(frames) == 0 {
		return
	}
	socket.drainRXRecyclePending()
	batch := socket.rxRecycleBatch[:0]
	for i := range frames {
		frame := &frames[i]
		frameSocket := frame.socket
		if frameSocket == nil {
			continue
		}
		if !frame.markRecycled() {
			frame.data = nil
			continue
		}
		if frameSocket != socket {
			if err := frameSocket.recycleRXAddr(frame.addr); err != nil {
				frameSocket.stats.rxRecycleErrors.Add(1)
			}
			frame.data = nil
			continue
		}
		batch = append(batch, frame.addr)
		frame.data = nil
	}
	if err := socket.recycleRXAddrsNoDrain(batch); err != nil {
		socket.stats.rxRecycleErrors.Add(1)
	}
	socket.rxRecycleBatch = batch[:0]
}

func (socket *afXDPSocket) recycleRXAddrNoDrain(addr uint64) error {
	if err := socket.fill.Push(addr); err == nil {
		return nil
	} else if !errors.Is(err, errAFXDPRingFull) {
		return err
	}
	limit := int(socket.umemFrames)
	if limit <= 0 {
		limit = int(socket.ringEntries)
	}
	if len(socket.rxRecyclePending) >= limit {
		return fmt.Errorf("%w: RX recycle backlog full", errAFXDPRingFull)
	}
	socket.rxRecyclePending = append(socket.rxRecyclePending, addr)
	socket.stats.rxRecycleDeferred.Add(1)
	return nil
}

func (socket *afXDPSocket) recycleRXAddrsNoDrain(addrs []uint64) error {
	if len(addrs) == 0 {
		return nil
	}
	if err := socket.fill.PushBatch(addrs); err == nil {
		return nil
	} else if !errors.Is(err, errAFXDPRingFull) {
		return err
	}
	limit := int(socket.umemFrames)
	if limit <= 0 {
		limit = int(socket.ringEntries)
	}
	if len(socket.rxRecyclePending)+len(addrs) > limit {
		return fmt.Errorf("%w: RX recycle backlog full", errAFXDPRingFull)
	}
	socket.rxRecyclePending = append(socket.rxRecyclePending, addrs...)
	socket.stats.rxRecycleDeferred.Add(uint64(len(addrs)))
	return nil
}

func (socket *afXDPSocket) drainRXRecyclePending() {
	if len(socket.rxRecyclePending) == 0 {
		return
	}
	flushed := 0
	for flushed < len(socket.rxRecyclePending) {
		remaining := socket.rxRecyclePending[flushed:]
		producer := atomic.LoadUint32(socket.fill.producer)
		consumer := atomic.LoadUint32(socket.fill.consumer)
		available := int(socket.fill.size - (producer - consumer))
		if available <= 0 {
			break
		}
		if available > len(remaining) {
			available = len(remaining)
		}
		if err := socket.fill.PushBatch(remaining[:available]); err != nil {
			break
		}
		flushed += available
	}
	if flushed == 0 {
		return
	}
	copy(socket.rxRecyclePending, socket.rxRecyclePending[flushed:])
	socket.rxRecyclePending = socket.rxRecyclePending[:len(socket.rxRecyclePending)-flushed]
	socket.stats.rxRecycleFlushes.Add(uint64(flushed))
}

func (socket *afXDPSocket) RecvFrameCopy() ([]byte, error) {
	frame, err := socket.RecvFrame()
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), frame.Bytes()...)
	if err := frame.Recycle(); err != nil {
		return nil, err
	}
	return out, nil
}

func (socket *afXDPSocket) SendFrame(packet tixtcp.TCPPacket, wireFrame tixtcp.Frame, dstMAC net.HardwareAddr) error {
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	if err := socket.publishPreparedFrameLocked(packet, wireFrame, dstMAC); err != nil {
		return err
	}
	return socket.flushTXPendingLocked()
}

func (socket *afXDPSocket) SendFrames(packet tixtcp.TCPPacket, wireFrames []tixtcp.Frame, dstMAC net.HardwareAddr) error {
	if len(wireFrames) == 0 {
		return nil
	}
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	for _, wireFrame := range wireFrames {
		if err := socket.publishPreparedFrameLocked(packet, wireFrame, dstMAC); err != nil {
			return err
		}
	}
	return socket.flushTXPendingLocked()
}

func (socket *afXDPSocket) SendPreparedFrames(items []preparedTIXTCPTXFrame, dstMAC net.HardwareAddr) error {
	if len(items) == 0 {
		return nil
	}
	socket.txMu.Lock()
	defer func() {
		socket.txBatchActive = false
		socket.txMu.Unlock()
	}()
	socket.beginTXBatchLocked()
	if len(items) > 1 {
		if tixTCPTXSocketGSOEnabled() {
			handled, err := socket.sendPreparedTIXTCPSocketGSOBatchLocked(items, dstMAC)
			if err != nil {
				return err
			}
			if handled {
				return nil
			}
		}
		if tixTCPTXMultiFrameEnabled() {
			return socket.publishPreparedFrameMultiFrameBatchLocked(items, dstMAC)
		}
		socket.stats.txMultiFrameDisabled.Add(1)
		return socket.publishPreparedFrameBatchLocked(items, dstMAC)
	}
	for _, item := range items {
		if err := socket.publishPreparedFrameLocked(item.packet, item.wireFrame, dstMAC); err != nil {
			return err
		}
	}
	return socket.flushTXPendingLocked()
}

func (socket *afXDPSocket) publishPreparedFrameBatchLocked(items []preparedTIXTCPTXFrame, dstMAC net.HardwareAddr) (err error) {
	if len(items) == 0 {
		return nil
	}
	if cap(socket.txBatchDescs) < len(items) {
		socket.txBatchDescs = make([]unix.XDPDesc, 0, len(items))
	} else {
		socket.txBatchDescs = socket.txBatchDescs[:0]
	}
	if cap(socket.txBatchAddrs) < len(items) {
		socket.txBatchAddrs = make([]uint64, 0, len(items))
	} else {
		socket.txBatchAddrs = socket.txBatchAddrs[:0]
	}
	published := false
	defer func() {
		if err != nil && !published {
			for _, addr := range socket.txBatchAddrs {
				socket.releaseTXFrame(addr)
			}
		}
		socket.txBatchDescs = socket.txBatchDescs[:0]
		socket.txBatchAddrs = socket.txBatchAddrs[:0]
	}()
	for _, item := range items {
		packetLen := item.packetLen
		if packetLen <= 0 {
			framePayloadLen, frameErr := tixtcp.FrameWireLen(len(item.wireFrame.Payload))
			if frameErr != nil {
				return frameErr
			}
			packetLen, frameErr = tixtcp.TCPShapedIPv4WireLen(framePayloadLen)
			if frameErr != nil {
				return frameErr
			}
		}
		if packetLen+ethernetHeaderLen > int(socket.umemFrameSize) {
			socket.stats.mtuExceeded.Add(1)
			return fmt.Errorf("%w: tix_tcp AF_XDP frame size %d exceeds UMEM frame size %d", errMTUExceeded, packetLen+ethernetHeaderLen, socket.umemFrameSize)
		}
		addr, ok := socket.acquireTXFrameLocked()
		if !ok {
			socket.stats.txPoolExhausted.Add(1)
			return fmt.Errorf("%w", errAFXDPTXPoolExhausted)
		}
		socket.txBatchAddrs = append(socket.txBatchAddrs, addr)
		start := int(addr)
		end := start + ethernetHeaderLen + packetLen
		if end > len(socket.umem) {
			return fmt.Errorf("AF_XDP tx frame out of bounds addr=%d len=%d", addr, ethernetHeaderLen+packetLen)
		}
		frame := socket.umem[start:end]
		copy(frame[0:6], dstMAC)
		copy(frame[6:12], socket.linkMAC)
		binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
		if err := marshalPreparedTIXTCPIPv4FrameInto(item, frame[ethernetHeaderLen:], socket.skipTCPChecksum); err != nil {
			return err
		}
		socket.txBatchDescs = append(socket.txBatchDescs, unix.XDPDesc{Addr: addr, Len: uint32(len(frame))})
	}
	published, err = socket.publishTXFramesLocked(socket.txBatchDescs, false)
	if err != nil {
		return err
	}
	socket.stats.txBatchSubmissions.Add(1)
	socket.stats.txBatchFrames.Add(uint64(len(socket.txBatchDescs)))
	socket.stats.txUMEMDirectBuild.Add(uint64(len(socket.txBatchDescs)))
	socket.stats.txFrames.Add(uint64(len(socket.txBatchDescs)))
	return socket.finishTXBatchLocked(len(socket.txBatchDescs))
}

func (socket *afXDPSocket) publishPreparedFrameMultiFrameBatchLocked(items []preparedTIXTCPTXFrame, dstMAC net.HardwareAddr) (err error) {
	if len(items) == 0 {
		return nil
	}
	if cap(socket.txBatchDescs) < len(items) {
		socket.txBatchDescs = make([]unix.XDPDesc, 0, len(items))
	} else {
		socket.txBatchDescs = socket.txBatchDescs[:0]
	}
	if cap(socket.txBatchAddrs) < len(items) {
		socket.txBatchAddrs = make([]uint64, 0, len(items))
	} else {
		socket.txBatchAddrs = socket.txBatchAddrs[:0]
	}
	published := false
	multiBatches := uint64(0)
	multiInputFrames := uint64(0)
	multiAttempts := uint64(0)
	multiSingletons := uint64(0)
	multiDisabled := uint64(0)
	multiRejectFirst := uint64(0)
	multiRejectNext := uint64(0)
	multiRejectTuple := uint64(0)
	multiRejectMTU := uint64(0)
	multiRejectMax := uint64(0)
	multiRejectError := uint64(0)
	multiRejectKernelTX := uint64(0)
	multiRejectEncrypted := uint64(0)
	multiRejectCryptoFragment := uint64(0)
	multiRejectFlags := uint64(0)
	multiRejectFragment := uint64(0)
	defer func() {
		if err != nil && !published {
			for _, addr := range socket.txBatchAddrs {
				socket.releaseTXFrame(addr)
			}
		}
		if multiAttempts > 0 {
			socket.stats.txMultiFrameAttempts.Add(multiAttempts)
		}
		if multiSingletons > 0 {
			socket.stats.txMultiFrameSingletons.Add(multiSingletons)
		}
		if multiDisabled > 0 {
			socket.stats.txMultiFrameDisabled.Add(multiDisabled)
		}
		if multiRejectFirst > 0 {
			socket.stats.txMultiFrameRejectFirst.Add(multiRejectFirst)
		}
		if multiRejectNext > 0 {
			socket.stats.txMultiFrameRejectNext.Add(multiRejectNext)
		}
		if multiRejectTuple > 0 {
			socket.stats.txMultiFrameRejectTuple.Add(multiRejectTuple)
		}
		if multiRejectMTU > 0 {
			socket.stats.txMultiFrameRejectMTU.Add(multiRejectMTU)
		}
		if multiRejectMax > 0 {
			socket.stats.txMultiFrameRejectMax.Add(multiRejectMax)
		}
		if multiRejectError > 0 {
			socket.stats.txMultiFrameRejectError.Add(multiRejectError)
		}
		if multiRejectKernelTX > 0 {
			socket.stats.txMultiFrameRejectKernelTX.Add(multiRejectKernelTX)
		}
		if multiRejectEncrypted > 0 {
			socket.stats.txMultiFrameRejectEncrypted.Add(multiRejectEncrypted)
		}
		if multiRejectCryptoFragment > 0 {
			socket.stats.txMultiFrameRejectCryptoFragment.Add(multiRejectCryptoFragment)
		}
		if multiRejectFlags > 0 {
			socket.stats.txMultiFrameRejectFlags.Add(multiRejectFlags)
		}
		if multiRejectFragment > 0 {
			socket.stats.txMultiFrameRejectFragment.Add(multiRejectFragment)
		}
		socket.txBatchDescs = socket.txBatchDescs[:0]
		socket.txBatchAddrs = socket.txBatchAddrs[:0]
	}()
	maxFrames := socket.txMultiFrameMaxFrames
	if maxFrames == 0 {
		maxFrames = tixTCPDefaultTXMultiFrameMaxFrames
	}
	maxIPv4Len := socket.txMultiFrameMaxIPv4Len
	if maxIPv4Len == 0 {
		maxIPv4Len = tixTCPDefaultTXMultiFrameMaxIPv4Len
	}
	if umemIPv4Len := int(socket.umemFrameSize) - ethernetHeaderLen; maxIPv4Len > umemIPv4Len {
		maxIPv4Len = umemIPv4Len
	}
	linkMTU := socket.linkMTU
	if linkMTU <= 0 {
		linkMTU = tixTCPDefaultTXMultiFrameMaxIPv4Len
	}
	if maxIPv4Len > linkMTU {
		maxIPv4Len = linkMTU
	}
	for i := 0; i < len(items); {
		group, frameErr := preparedTIXTCPMultiFrameGroupWithReason(items[i:], maxFrames, maxIPv4Len, socket.txMultiFrameEncrypted)
		multiAttempts++
		if frameErr != nil {
			multiRejectError++
			return frameErr
		}
		switch group.rejectReason {
		case preparedTIXTCPMultiFrameRejectDisabled:
			multiDisabled++
		case preparedTIXTCPMultiFrameRejectFirstIneligible:
			multiRejectFirst++
		case preparedTIXTCPMultiFrameRejectNextIneligible:
			multiRejectNext++
		case preparedTIXTCPMultiFrameRejectTuple:
			multiRejectTuple++
		case preparedTIXTCPMultiFrameRejectMTU:
			multiRejectMTU++
		case preparedTIXTCPMultiFrameRejectMaxFrames:
			multiRejectMax++
		}
		switch group.eligibilityReason {
		case preparedTIXTCPMultiFrameEligibilityRejectKernelTX:
			multiRejectKernelTX++
		case preparedTIXTCPMultiFrameEligibilityRejectEncrypted:
			multiRejectEncrypted++
		case preparedTIXTCPMultiFrameEligibilityRejectCryptoFragment:
			multiRejectCryptoFragment++
		case preparedTIXTCPMultiFrameEligibilityRejectFlags:
			multiRejectFlags++
		case preparedTIXTCPMultiFrameEligibilityRejectFragment:
			multiRejectFragment++
		}
		groupLen := group.groupLen
		packetLen := group.packetLen
		if groupLen <= 0 {
			groupLen = 1
		}
		if groupLen == 1 {
			multiSingletons++
			item := items[i]
			packetLen = item.packetLen
			if packetLen <= 0 {
				framePayloadLen, frameErr := tixtcp.FrameWireLen(len(item.wireFrame.Payload))
				if frameErr != nil {
					return frameErr
				}
				packetLen, frameErr = tixtcp.TCPShapedIPv4WireLen(framePayloadLen)
				if frameErr != nil {
					return frameErr
				}
			}
		}
		if packetLen+ethernetHeaderLen > int(socket.umemFrameSize) {
			socket.stats.mtuExceeded.Add(1)
			return fmt.Errorf("%w: tix_tcp AF_XDP frame size %d exceeds UMEM frame size %d", errMTUExceeded, packetLen+ethernetHeaderLen, socket.umemFrameSize)
		}
		addr, ok := socket.acquireTXFrameLocked()
		if !ok {
			socket.stats.txPoolExhausted.Add(1)
			return fmt.Errorf("%w", errAFXDPTXPoolExhausted)
		}
		socket.txBatchAddrs = append(socket.txBatchAddrs, addr)
		start := int(addr)
		end := start + ethernetHeaderLen + packetLen
		if end > len(socket.umem) {
			return fmt.Errorf("AF_XDP tx frame out of bounds addr=%d len=%d", addr, ethernetHeaderLen+packetLen)
		}
		frame := socket.umem[start:end]
		copy(frame[0:6], dstMAC)
		copy(frame[6:12], socket.linkMAC)
		binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
		if groupLen > 1 {
			if err := marshalPreparedTIXTCPIPv4MultiFrameInto(items[i:i+groupLen], frame[ethernetHeaderLen:], socket.skipTCPChecksum, socket.txMultiFrameEncrypted); err != nil {
				return err
			}
			multiBatches++
			multiInputFrames += uint64(groupLen)
		} else if err := marshalPreparedTIXTCPIPv4FrameInto(items[i], frame[ethernetHeaderLen:], socket.skipTCPChecksum); err != nil {
			return err
		}
		socket.txBatchDescs = append(socket.txBatchDescs, unix.XDPDesc{Addr: addr, Len: uint32(len(frame))})
		i += groupLen
	}
	published, err = socket.publishTXFramesLocked(socket.txBatchDescs, false)
	if err != nil {
		return err
	}
	socket.stats.txBatchSubmissions.Add(1)
	socket.stats.txBatchFrames.Add(uint64(len(socket.txBatchDescs)))
	if multiBatches > 0 {
		socket.stats.txMultiFrameBatches.Add(multiBatches)
		socket.stats.txMultiFrameInputFrames.Add(multiInputFrames)
	}
	socket.stats.txUMEMDirectBuild.Add(uint64(len(socket.txBatchDescs)))
	socket.stats.txFrames.Add(uint64(len(socket.txBatchDescs)))
	return socket.finishTXBatchLocked(len(socket.txBatchDescs))
}

func (socket *afXDPSocket) SendUDPFrame(packet kerneludp.UDPPacket, wireFrame kerneludp.Frame, dstMAC net.HardwareAddr) error {
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	if err := socket.publishPreparedUDPFrameLocked(packet, wireFrame, dstMAC); err != nil {
		return err
	}
	return socket.flushTXPendingLocked()
}

func (socket *afXDPSocket) SendPreparedUDPFrames(items []preparedKernelUDPTXFrame, dstMAC net.HardwareAddr) error {
	if len(items) == 0 {
		return nil
	}
	socket.txMu.Lock()
	defer func() {
		socket.txBatchActive = false
		socket.txMu.Unlock()
	}()
	socket.beginTXBatchLocked()
	if len(items) > 1 {
		return socket.publishPreparedUDPFrameBatchLocked(items, dstMAC)
	}
	for _, item := range items {
		if err := socket.publishPreparedUDPFrameLocked(item.packet, item.wireFrame, dstMAC); err != nil {
			return err
		}
	}
	return socket.flushTXPendingLocked()
}

func (socket *afXDPSocket) publishPreparedUDPFrameBatchLocked(items []preparedKernelUDPTXFrame, dstMAC net.HardwareAddr) (err error) {
	if len(items) == 0 {
		return nil
	}
	if cap(socket.txBatchDescs) < len(items) {
		socket.txBatchDescs = make([]unix.XDPDesc, 0, len(items))
	} else {
		socket.txBatchDescs = socket.txBatchDescs[:0]
	}
	if cap(socket.txBatchAddrs) < len(items) {
		socket.txBatchAddrs = make([]uint64, 0, len(items))
	} else {
		socket.txBatchAddrs = socket.txBatchAddrs[:0]
	}
	published := false
	defer func() {
		if err != nil && !published {
			for _, addr := range socket.txBatchAddrs {
				socket.releaseTXFrame(addr)
			}
		}
		socket.txBatchDescs = socket.txBatchDescs[:0]
		socket.txBatchAddrs = socket.txBatchAddrs[:0]
	}()
	for _, item := range items {
		packetLen := item.packetWireLen
		if packetLen <= 0 {
			framePayloadLen, frameErr := kerneludp.FrameWireLen(len(item.wireFrame.Payload))
			if frameErr != nil {
				return frameErr
			}
			packetLen, err = kerneludp.UDPIPv4WireLen(framePayloadLen)
			if err != nil {
				return err
			}
		}
		if packetLen+ethernetHeaderLen > int(socket.umemFrameSize) {
			socket.stats.mtuExceeded.Add(1)
			return fmt.Errorf("%w: UDP AF_XDP frame size %d exceeds UMEM frame size %d", errMTUExceeded, packetLen+ethernetHeaderLen, socket.umemFrameSize)
		}
		addr, ok := socket.acquireTXFrameLocked()
		if !ok {
			socket.stats.txPoolExhausted.Add(1)
			return fmt.Errorf("%w", errAFXDPTXPoolExhausted)
		}
		socket.txBatchAddrs = append(socket.txBatchAddrs, addr)
		start := int(addr)
		end := start + ethernetHeaderLen + packetLen
		if end > len(socket.umem) {
			return fmt.Errorf("AF_XDP UDP tx frame out of bounds addr=%d len=%d", addr, ethernetHeaderLen+packetLen)
		}
		frame := socket.umem[start:end]
		copy(frame[0:6], dstMAC)
		copy(frame[6:12], socket.linkMAC)
		binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
		if socket.skipUDPChecksum {
			if err := marshalPreparedKernelUDPIPv4FrameNoChecksumInto(item, frame[ethernetHeaderLen:]); err != nil {
				return err
			}
		} else if _, err := kerneludp.MarshalUDPIPv4FrameInto(item.packet, item.wireFrame, frame[ethernetHeaderLen:]); err != nil {
			return err
		}
		socket.txBatchDescs = append(socket.txBatchDescs, unix.XDPDesc{Addr: addr, Len: uint32(len(frame))})
	}
	published, err = socket.publishTXFramesLocked(socket.txBatchDescs, false)
	if err != nil {
		return err
	}
	socket.stats.txBatchSubmissions.Add(1)
	socket.stats.txBatchFrames.Add(uint64(len(socket.txBatchDescs)))
	socket.stats.txUMEMDirectBuild.Add(uint64(len(socket.txBatchDescs)))
	socket.stats.txFrames.Add(uint64(len(socket.txBatchDescs)))
	return socket.finishTXBatchLocked(len(socket.txBatchDescs))
}

func (socket *afXDPSocket) SendKernelCryptoFrame(packet tixtcp.TCPPacket, wireFrame tixtcp.Frame, dstMAC net.HardwareAddr, sealer *tixTCPTXSealObject) error {
	if sealer == nil {
		return fmt.Errorf("tix_tcp TX packet kernel seal is not ready")
	}
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	if err := socket.publishPreparedKernelCryptoFrameLocked(packet, wireFrame, dstMAC, sealer); err != nil {
		return err
	}
	return socket.flushTXPendingLocked()
}

type tixTCPEthernetSealer interface {
	SealEthernetInPlace(frame []byte, length int) (int, error)
}

func (socket *afXDPSocket) SendKernelCryptoFrames(packet tixtcp.TCPPacket, wireFrames []tixtcp.Frame, dstMAC net.HardwareAddr, sealer *tixTCPTXSealObject) error {
	if sealer == nil {
		return fmt.Errorf("tix_tcp TX packet kernel seal is not ready")
	}
	if len(wireFrames) == 0 {
		return nil
	}
	socket.txMu.Lock()
	defer func() {
		socket.txBatchActive = false
		socket.txMu.Unlock()
	}()
	socket.beginTXBatchLocked()
	if len(wireFrames) > 1 {
		items := make([]preparedTIXTCPTXFrame, 0, len(wireFrames))
		for _, wireFrame := range wireFrames {
			items = append(items, preparedTIXTCPTXFrame{
				packet:    packet,
				wireFrame: wireFrame,
			})
		}
		return socket.publishPreparedKernelCryptoFrameBatchLocked(items, dstMAC, sealer)
	}
	for _, wireFrame := range wireFrames {
		if err := socket.publishPreparedKernelCryptoFrameLocked(packet, wireFrame, dstMAC, sealer); err != nil {
			return err
		}
	}
	return socket.flushTXPendingLocked()
}

func (socket *afXDPSocket) SendPreparedKernelCryptoFrames(items []preparedTIXTCPTXFrame, dstMAC net.HardwareAddr, sealer *tixTCPTXSealObject) error {
	if sealer == nil {
		return fmt.Errorf("tix_tcp TX packet kernel seal is not ready")
	}
	if len(items) == 0 {
		return nil
	}
	socket.txMu.Lock()
	defer func() {
		socket.txBatchActive = false
		socket.txMu.Unlock()
	}()
	socket.beginTXBatchLocked()
	if len(items) > 1 {
		return socket.publishPreparedKernelCryptoFrameBatchLocked(items, dstMAC, sealer)
	}
	for _, item := range items {
		if err := socket.publishPreparedKernelCryptoFrameLocked(item.packet, item.wireFrame, dstMAC, sealer); err != nil {
			return err
		}
	}
	return socket.flushTXPendingLocked()
}

func (socket *afXDPSocket) publishPreparedFrameLocked(packet tixtcp.TCPPacket, wireFrame tixtcp.Frame, dstMAC net.HardwareAddr) error {
	framePayloadLen, err := tixtcp.FrameWireLen(len(wireFrame.Payload))
	if err != nil {
		return err
	}
	packetLen, err := tixtcp.TCPShapedIPv4WireLen(framePayloadLen)
	if err != nil {
		return err
	}
	if packetLen+ethernetHeaderLen > int(socket.umemFrameSize) {
		socket.stats.mtuExceeded.Add(1)
		return fmt.Errorf("%w: tix_tcp AF_XDP frame size %d exceeds UMEM frame size %d", errMTUExceeded, packetLen+ethernetHeaderLen, socket.umemFrameSize)
	}
	addr, ok := socket.acquireTXFrameLocked()
	if !ok {
		socket.stats.txPoolExhausted.Add(1)
		return fmt.Errorf("%w", errAFXDPTXPoolExhausted)
	}
	start := int(addr)
	end := start + ethernetHeaderLen + packetLen
	if end > len(socket.umem) {
		socket.releaseTXFrame(addr)
		return fmt.Errorf("AF_XDP tx frame out of bounds addr=%d len=%d", addr, ethernetHeaderLen+packetLen)
	}
	frame := socket.umem[start:end]
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], socket.linkMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	item := preparedTIXTCPTXFrame{
		packet:    packet,
		wireFrame: wireFrame,
		frameLen:  framePayloadLen,
		packetLen: packetLen,
	}
	if err := marshalPreparedTIXTCPIPv4FrameInto(item, frame[ethernetHeaderLen:], socket.skipTCPChecksum); err != nil {
		socket.releaseTXFrame(addr)
		return err
	}
	if published, err := socket.publishTXFrameLocked(addr, uint32(len(frame)), false); err != nil {
		if !published {
			socket.releaseTXFrame(addr)
		}
		return err
	}
	socket.stats.txUMEMDirectBuild.Add(1)
	socket.stats.txFrames.Add(1)
	return nil
}

func (socket *afXDPSocket) publishPreparedUDPFrameLocked(packet kerneludp.UDPPacket, wireFrame kerneludp.Frame, dstMAC net.HardwareAddr) error {
	framePayloadLen, err := kerneludp.FrameWireLen(len(wireFrame.Payload))
	if err != nil {
		return err
	}
	packetLen, err := kerneludp.UDPIPv4WireLen(framePayloadLen)
	if err != nil {
		return err
	}
	if packetLen+ethernetHeaderLen > int(socket.umemFrameSize) {
		socket.stats.mtuExceeded.Add(1)
		return fmt.Errorf("%w: UDP AF_XDP frame size %d exceeds UMEM frame size %d", errMTUExceeded, packetLen+ethernetHeaderLen, socket.umemFrameSize)
	}
	addr, ok := socket.acquireTXFrameLocked()
	if !ok {
		socket.stats.txPoolExhausted.Add(1)
		return fmt.Errorf("%w", errAFXDPTXPoolExhausted)
	}
	start := int(addr)
	end := start + ethernetHeaderLen + packetLen
	if end > len(socket.umem) {
		socket.releaseTXFrame(addr)
		return fmt.Errorf("AF_XDP UDP tx frame out of bounds addr=%d len=%d", addr, ethernetHeaderLen+packetLen)
	}
	frame := socket.umem[start:end]
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], socket.linkMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	marshalUDP := kerneludp.MarshalUDPIPv4FrameInto
	if socket.skipUDPChecksum {
		if _, err := marshalKernelUDPIPv4FrameNoChecksumInto(packet, wireFrame, frame[ethernetHeaderLen:]); err != nil {
			socket.releaseTXFrame(addr)
			return err
		}
	} else if _, err := marshalUDP(packet, wireFrame, frame[ethernetHeaderLen:]); err != nil {
		socket.releaseTXFrame(addr)
		return err
	}
	if published, err := socket.publishTXFrameLocked(addr, uint32(len(frame)), false); err != nil {
		if !published {
			socket.releaseTXFrame(addr)
		}
		return err
	}
	socket.stats.txUMEMDirectBuild.Add(1)
	socket.stats.txFrames.Add(1)
	return nil
}

func marshalPreparedKernelUDPIPv4FrameNoChecksumInto(item preparedKernelUDPTXFrame, wire []byte) error {
	payloadLen := len(item.wireFrame.Payload)
	if payloadLen > kerneludp.MaxPayload {
		return fmt.Errorf("kernel_udp payload size %d exceeds max %d", payloadLen, kerneludp.MaxPayload)
	}
	frameLen := item.frameWireLen
	if frameLen <= 0 {
		frameLen = kerneludp.HeaderLen + payloadLen
	}
	udpLen := 8 + frameLen
	totalLen := item.packetWireLen
	if totalLen <= 0 {
		totalLen = 20 + udpLen
	}
	if totalLen > 0xffff || udpLen > 0xffff {
		return fmt.Errorf("kernel_udp packet size %d exceeds IPv4/UDP limit", totalLen)
	}
	if len(wire) < totalLen {
		return fmt.Errorf("kernel_udp packet buffer size %d is smaller than wire length %d", len(wire), totalLen)
	}
	src := item.sourceIP4
	dst := item.destinationIP4
	sourcePort := item.sourcePort
	destinationPort := item.destinationPort
	if sourcePort == 0 || destinationPort == 0 || src == ([4]byte{}) || dst == ([4]byte{}) {
		packet := item.packet
		if !packet.SourceIP.Is4() || !packet.DestinationIP.Is4() {
			return fmt.Errorf("kernel_udp only supports IPv4 underlay packets")
		}
		if packet.SourcePort == 0 || packet.DestinationPort == 0 {
			return fmt.Errorf("kernel_udp source and destination ports are required")
		}
		src = packet.SourceIP.As4()
		dst = packet.DestinationIP.As4()
		sourcePort = packet.SourcePort
		destinationPort = packet.DestinationPort
	}
	wire = wire[:totalLen]
	wire[0] = 0x45
	wire[1] = 0
	binary.BigEndian.PutUint16(wire[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(wire[4:6], 0)
	binary.BigEndian.PutUint16(wire[6:8], 0x4000)
	wire[8] = 64
	wire[9] = unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(wire[10:12], 0)
	copy(wire[12:16], src[:])
	copy(wire[16:20], dst[:])
	binary.BigEndian.PutUint16(wire[10:12], ipv4Checksum20(wire[:20]))

	udp := wire[20:]
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0)

	kudp := udp[8:]
	frame := item.wireFrame
	binary.BigEndian.PutUint32(kudp[0:4], kerneludp.Magic)
	kudp[4] = kerneludp.Version
	kudp[5] = frame.Flags
	binary.BigEndian.PutUint16(kudp[6:8], kerneludp.HeaderLen)
	binary.BigEndian.PutUint64(kudp[8:16], frame.FlowID)
	binary.BigEndian.PutUint64(kudp[16:24], frame.Sequence)
	binary.BigEndian.PutUint32(kudp[24:28], uint32(payloadLen))
	binary.BigEndian.PutUint16(kudp[28:30], frame.FragmentIndex)
	binary.BigEndian.PutUint16(kudp[30:32], frame.FragmentCount)
	copy(kudp[kerneludp.HeaderLen:], frame.Payload)
	return nil
}

func marshalPreparedTIXTCPIPv4FrameInto(item preparedTIXTCPTXFrame, wire []byte, skipTCPChecksum bool) error {
	payloadLen := len(item.wireFrame.Payload)
	if payloadLen > tixtcp.MaxPayload {
		return fmt.Errorf("tix_tcp payload size %d exceeds max %d", payloadLen, tixtcp.MaxPayload)
	}
	frameLen := item.frameLen
	if frameLen <= 0 {
		frameLen = tixtcp.HeaderLen + payloadLen
	}
	totalLen := item.packetLen
	if totalLen <= 0 {
		totalLen = 20 + 20 + frameLen
	}
	if totalLen > 0xffff {
		return fmt.Errorf("tix_tcp packet size %d exceeds IPv4 limit", totalLen)
	}
	if len(wire) < totalLen {
		return fmt.Errorf("tix_tcp packet buffer size %d is smaller than wire length %d", len(wire), totalLen)
	}
	if frameLen != tixtcp.HeaderLen+payloadLen || totalLen != 40+frameLen {
		return fmt.Errorf("tix_tcp prepared length mismatch: frame=%d payload=%d packet=%d", frameLen, payloadLen, totalLen)
	}
	src := item.sourceIP4
	dst := item.destinationIP4
	sourcePort := item.sourcePort
	destinationPort := item.destinationPort
	packet := item.packet
	if sourcePort == 0 || destinationPort == 0 || src == ([4]byte{}) || dst == ([4]byte{}) {
		if !packet.SourceIP.Is4() || !packet.DestinationIP.Is4() {
			return fmt.Errorf("tix_tcp only supports IPv4 underlay packets")
		}
		if packet.SourcePort == 0 || packet.DestinationPort == 0 {
			return fmt.Errorf("tix_tcp source and destination ports are required")
		}
		src = packet.SourceIP.As4()
		dst = packet.DestinationIP.As4()
		sourcePort = packet.SourcePort
		destinationPort = packet.DestinationPort
	}
	wire = wire[:totalLen]
	wire[0] = 0x45
	wire[1] = 0
	binary.BigEndian.PutUint16(wire[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(wire[4:6], 0)
	binary.BigEndian.PutUint16(wire[6:8], 0x4000)
	wire[8] = 64
	wire[9] = unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(wire[10:12], 0)
	copy(wire[12:16], src[:])
	copy(wire[16:20], dst[:])
	binary.BigEndian.PutUint16(wire[10:12], ipv4Checksum20(wire[:20]))

	tcp := wire[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], packet.Sequence)
	binary.BigEndian.PutUint32(tcp[8:12], packet.Acknowledgment)
	tcp[12] = 0x50
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)

	tixt := tcp[20:]
	if err := marshalPreparedTIXTCPTIXTFrameInto(item, tixt); err != nil {
		return err
	}
	if !skipTCPChecksum {
		binary.BigEndian.PutUint16(tcp[16:18], preparedTIXTCPTCPChecksumIPv4(src, dst, sourcePort, destinationPort, packet, item.wireFrame))
	}
	return nil
}

func marshalPreparedTIXTCPIPv4MultiFrameInto(items []preparedTIXTCPTXFrame, wire []byte, skipTCPChecksum bool, encryptedEnabled bool) error {
	if len(items) < 2 {
		return fmt.Errorf("tix_tcp multi-frame batch requires at least two frames")
	}
	src, dst, sourcePort, destinationPort, err := preparedTIXTCPIPv4Tuple(items[0])
	if err != nil {
		return err
	}
	payloadLen := 0
	for i, item := range items {
		if !preparedTIXTCPMultiFrameEligible(item, encryptedEnabled) {
			return fmt.Errorf("tix_tcp frame %d is not eligible for plaintext multi-frame TX", i)
		}
		itemSrc, itemDst, itemSourcePort, itemDestinationPort, err := preparedTIXTCPIPv4Tuple(item)
		if err != nil {
			return err
		}
		if itemSrc != src || itemDst != dst || itemSourcePort != sourcePort || itemDestinationPort != destinationPort {
			return fmt.Errorf("tix_tcp frame %d underlay tuple differs inside multi-frame TX batch", i)
		}
		frameLen, err := preparedTIXTCPFrameWireLen(item)
		if err != nil {
			return err
		}
		if payloadLen > 0xffff-frameLen {
			return fmt.Errorf("tix_tcp multi-frame payload exceeds IPv4 limit")
		}
		payloadLen += frameLen
	}
	totalLen := 20 + 20 + payloadLen
	if totalLen > 0xffff {
		return fmt.Errorf("tix_tcp packet size %d exceeds IPv4 limit", totalLen)
	}
	if len(wire) < totalLen {
		return fmt.Errorf("tix_tcp packet buffer size %d is smaller than wire length %d", len(wire), totalLen)
	}
	wire = wire[:totalLen]
	wire[0] = 0x45
	wire[1] = 0
	binary.BigEndian.PutUint16(wire[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(wire[4:6], 0)
	binary.BigEndian.PutUint16(wire[6:8], 0x4000)
	wire[8] = 64
	wire[9] = unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(wire[10:12], 0)
	copy(wire[12:16], src[:])
	copy(wire[16:20], dst[:])
	binary.BigEndian.PutUint16(wire[10:12], ipv4Checksum20(wire[:20]))

	tcp := wire[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], items[0].packet.Sequence)
	binary.BigEndian.PutUint32(tcp[8:12], items[0].packet.Acknowledgment)
	tcp[12] = 0x50
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)

	cursor := tcp[20:]
	for _, item := range items {
		frameLen, err := preparedTIXTCPFrameWireLen(item)
		if err != nil {
			return err
		}
		if err := marshalPreparedTIXTCPTIXTFrameInto(item, cursor[:frameLen]); err != nil {
			return err
		}
		cursor = cursor[frameLen:]
	}
	if !skipTCPChecksum {
		binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumIPv4(src, dst, tcp))
	}
	return nil
}

func marshalPreparedTIXTCPTIXTFrameInto(item preparedTIXTCPTXFrame, tixt []byte) error {
	payloadLen := len(item.wireFrame.Payload)
	if payloadLen > tixtcp.MaxPayload {
		return fmt.Errorf("tix_tcp payload size %d exceeds max %d", payloadLen, tixtcp.MaxPayload)
	}
	frameLen := item.frameLen
	if frameLen <= 0 {
		frameLen = tixtcp.HeaderLen + payloadLen
	}
	if frameLen != tixtcp.HeaderLen+payloadLen {
		return fmt.Errorf("tix_tcp prepared frame length %d does not match payload length %d", frameLen, payloadLen)
	}
	if len(tixt) < frameLen {
		return fmt.Errorf("tix_tcp TIXT buffer size %d is smaller than frame length %d", len(tixt), frameLen)
	}
	frame := item.wireFrame
	binary.BigEndian.PutUint32(tixt[0:4], tixtcp.Magic)
	tixt[4] = tixtcp.Version
	tixt[5] = frame.Flags
	binary.BigEndian.PutUint16(tixt[6:8], tixtcp.HeaderLen)
	binary.BigEndian.PutUint64(tixt[8:16], frame.FlowID)
	binary.BigEndian.PutUint64(tixt[16:24], frame.Epoch)
	binary.BigEndian.PutUint64(tixt[24:32], frame.Sequence)
	binary.BigEndian.PutUint32(tixt[32:36], uint32(payloadLen))
	binary.BigEndian.PutUint16(tixt[36:38], frame.FragmentIndex)
	binary.BigEndian.PutUint16(tixt[38:40], frame.FragmentCount)
	copy(tixt[tixtcp.HeaderLen:frameLen], frame.Payload)
	return nil
}

type preparedTIXTCPMultiFrameRejectReason uint8

const (
	preparedTIXTCPMultiFrameRejectNone preparedTIXTCPMultiFrameRejectReason = iota
	preparedTIXTCPMultiFrameRejectDisabled
	preparedTIXTCPMultiFrameRejectFirstIneligible
	preparedTIXTCPMultiFrameRejectNextIneligible
	preparedTIXTCPMultiFrameRejectTuple
	preparedTIXTCPMultiFrameRejectMTU
	preparedTIXTCPMultiFrameRejectMaxFrames
)

type preparedTIXTCPMultiFrameEligibilityReason uint8

const (
	preparedTIXTCPMultiFrameEligibilityOK preparedTIXTCPMultiFrameEligibilityReason = iota
	preparedTIXTCPMultiFrameEligibilityRejectKernelTX
	preparedTIXTCPMultiFrameEligibilityRejectEncrypted
	preparedTIXTCPMultiFrameEligibilityRejectCryptoFragment
	preparedTIXTCPMultiFrameEligibilityRejectFlags
	preparedTIXTCPMultiFrameEligibilityRejectFragment
)

type preparedTIXTCPMultiFrameGroupResult struct {
	groupLen          int
	packetLen         int
	rejectReason      preparedTIXTCPMultiFrameRejectReason
	eligibilityReason preparedTIXTCPMultiFrameEligibilityReason
}

func preparedTIXTCPMultiFrameGroup(items []preparedTIXTCPTXFrame, maxFrames int, maxIPv4Len int, encryptedEnabled bool) (int, int, error) {
	group, err := preparedTIXTCPMultiFrameGroupWithReason(items, maxFrames, maxIPv4Len, encryptedEnabled)
	if err != nil {
		return 0, 0, err
	}
	return group.groupLen, group.packetLen, nil
}

func preparedTIXTCPMultiFrameGroupWithReason(items []preparedTIXTCPTXFrame, maxFrames int, maxIPv4Len int, encryptedEnabled bool) (preparedTIXTCPMultiFrameGroupResult, error) {
	if len(items) == 0 {
		return preparedTIXTCPMultiFrameGroupResult{}, nil
	}
	if maxFrames < 2 || maxIPv4Len < 20+20+tixtcp.HeaderLen {
		return preparedTIXTCPMultiFrameGroupResult{
			groupLen:     1,
			rejectReason: preparedTIXTCPMultiFrameRejectDisabled,
		}, nil
	}
	first := items[0]
	if reason := preparedTIXTCPMultiFrameEligibility(first, encryptedEnabled); reason != preparedTIXTCPMultiFrameEligibilityOK {
		return preparedTIXTCPMultiFrameGroupResult{
			groupLen:          1,
			rejectReason:      preparedTIXTCPMultiFrameRejectFirstIneligible,
			eligibilityReason: reason,
		}, nil
	}
	src, dst, sourcePort, destinationPort, err := preparedTIXTCPIPv4Tuple(first)
	if err != nil {
		return preparedTIXTCPMultiFrameGroupResult{}, err
	}
	payloadLen := 0
	groupLen := 0
	rejectReason := preparedTIXTCPMultiFrameRejectNone
	eligibilityReason := preparedTIXTCPMultiFrameEligibilityOK
	for i := 0; i < len(items) && i < maxFrames; i++ {
		item := items[i]
		if reason := preparedTIXTCPMultiFrameEligibility(item, encryptedEnabled); reason != preparedTIXTCPMultiFrameEligibilityOK {
			rejectReason = preparedTIXTCPMultiFrameRejectNextIneligible
			eligibilityReason = reason
			break
		}
		if item.wireFrame.FlowID != first.wireFrame.FlowID || item.wireFrame.Epoch != first.wireFrame.Epoch {
			rejectReason = preparedTIXTCPMultiFrameRejectTuple
			break
		}
		itemSrc, itemDst, itemSourcePort, itemDestinationPort, err := preparedTIXTCPIPv4Tuple(item)
		if err != nil {
			return preparedTIXTCPMultiFrameGroupResult{}, err
		}
		if itemSrc != src || itemDst != dst || itemSourcePort != sourcePort || itemDestinationPort != destinationPort {
			rejectReason = preparedTIXTCPMultiFrameRejectTuple
			break
		}
		frameLen, err := preparedTIXTCPFrameWireLen(item)
		if err != nil {
			return preparedTIXTCPMultiFrameGroupResult{}, err
		}
		nextPayloadLen := payloadLen + frameLen
		nextPacketLen := 20 + 20 + nextPayloadLen
		if nextPacketLen > maxIPv4Len {
			rejectReason = preparedTIXTCPMultiFrameRejectMTU
			break
		}
		payloadLen = nextPayloadLen
		groupLen++
	}
	if rejectReason == preparedTIXTCPMultiFrameRejectNone && groupLen == maxFrames && len(items) > maxFrames {
		rejectReason = preparedTIXTCPMultiFrameRejectMaxFrames
	}
	if groupLen < 2 {
		return preparedTIXTCPMultiFrameGroupResult{
			groupLen:          1,
			rejectReason:      rejectReason,
			eligibilityReason: eligibilityReason,
		}, nil
	}
	return preparedTIXTCPMultiFrameGroupResult{
		groupLen:          groupLen,
		packetLen:         20 + 20 + payloadLen,
		rejectReason:      rejectReason,
		eligibilityReason: eligibilityReason,
	}, nil
}

func preparedTIXTCPMultiFrameEligible(item preparedTIXTCPTXFrame, encryptedEnabled bool) bool {
	return preparedTIXTCPMultiFrameEligibility(item, encryptedEnabled) == preparedTIXTCPMultiFrameEligibilityOK
}

func preparedTIXTCPMultiFrameEligibility(item preparedTIXTCPTXFrame, encryptedEnabled bool) preparedTIXTCPMultiFrameEligibilityReason {
	if item.kernelTX {
		return preparedTIXTCPMultiFrameEligibilityRejectKernelTX
	}
	frame := item.wireFrame
	allowedFlags := tixtcp.FlagKernelOpened | tixtcp.FlagInnerIPv4
	if frame.Flags&tixtcp.FlagEncrypted != 0 {
		if !encryptedEnabled {
			return preparedTIXTCPMultiFrameEligibilityRejectEncrypted
		}
		allowedFlags |= tixtcp.FlagEncrypted
		if frame.Flags&tixtcp.FlagCryptoFragment != 0 {
			allowedFlags |= tixtcp.FlagCryptoFragment
		}
	} else if frame.Flags&tixtcp.FlagCryptoFragment != 0 {
		return preparedTIXTCPMultiFrameEligibilityRejectCryptoFragment
	}
	if frame.Flags&^allowedFlags != 0 {
		return preparedTIXTCPMultiFrameEligibilityRejectFlags
	}
	switch {
	case frame.FragmentCount == 0:
		if frame.FragmentIndex != 0 {
			return preparedTIXTCPMultiFrameEligibilityRejectFragment
		}
	case frame.FragmentIndex >= frame.FragmentCount:
		return preparedTIXTCPMultiFrameEligibilityRejectFragment
	}
	return preparedTIXTCPMultiFrameEligibilityOK
}

func preparedTIXTCPFrameWireLen(item preparedTIXTCPTXFrame) (int, error) {
	payloadLen := len(item.wireFrame.Payload)
	if payloadLen > tixtcp.MaxPayload {
		return 0, fmt.Errorf("tix_tcp payload size %d exceeds max %d", payloadLen, tixtcp.MaxPayload)
	}
	frameLen := item.frameLen
	if frameLen <= 0 {
		frameLen = tixtcp.HeaderLen + payloadLen
	}
	if frameLen != tixtcp.HeaderLen+payloadLen {
		return 0, fmt.Errorf("tix_tcp prepared frame length %d does not match payload length %d", frameLen, payloadLen)
	}
	return frameLen, nil
}

func preparedTIXTCPIPv4Tuple(item preparedTIXTCPTXFrame) ([4]byte, [4]byte, uint16, uint16, error) {
	src := item.sourceIP4
	dst := item.destinationIP4
	sourcePort := item.sourcePort
	destinationPort := item.destinationPort
	packet := item.packet
	if sourcePort == 0 || destinationPort == 0 || src == ([4]byte{}) || dst == ([4]byte{}) {
		if !packet.SourceIP.Is4() || !packet.DestinationIP.Is4() {
			return [4]byte{}, [4]byte{}, 0, 0, fmt.Errorf("tix_tcp only supports IPv4 underlay packets")
		}
		if packet.SourcePort == 0 || packet.DestinationPort == 0 {
			return [4]byte{}, [4]byte{}, 0, 0, fmt.Errorf("tix_tcp source and destination ports are required")
		}
		src = packet.SourceIP.As4()
		dst = packet.DestinationIP.As4()
		sourcePort = packet.SourcePort
		destinationPort = packet.DestinationPort
	}
	return src, dst, sourcePort, destinationPort, nil
}

func tcpChecksumIPv4(src, dst [4]byte, tcp []byte) uint16 {
	sum := uint32(0)
	sum = checksumAddBytes16(sum, src[:])
	sum = checksumAddBytes16(sum, dst[:])
	sum += unix.IPPROTO_TCP
	sum += uint32(len(tcp))
	if len(tcp) <= 16 {
		sum = checksumAddBytes16(sum, tcp)
		return checksumFold16(sum)
	}
	sum = checksumAddBytes16(sum, tcp[:16])
	if len(tcp) > 18 {
		sum = checksumAddBytes16(sum, tcp[18:])
	}
	return checksumFold16(sum)
}

func preparedTIXTCPTCPChecksumIPv4(src, dst [4]byte, sourcePort, destinationPort uint16, packet tixtcp.TCPPacket, frame tixtcp.Frame) uint16 {
	payloadLen := len(frame.Payload)
	tcpLen := 20 + tixtcp.HeaderLen + payloadLen
	sum := uint32(0)
	sum = checksumAddBytes16(sum, src[:])
	sum = checksumAddBytes16(sum, dst[:])
	sum += unix.IPPROTO_TCP
	sum += uint32(tcpLen)
	sum += uint32(sourcePort)
	sum += uint32(destinationPort)
	sum = checksumAddUint32(sum, packet.Sequence)
	sum = checksumAddUint32(sum, packet.Acknowledgment)
	sum += 0x5018
	sum += 0xffff
	sum += uint32(uint16(uint32(tixtcp.Magic) >> 16))
	sum += uint32(uint16(uint32(tixtcp.Magic) & 0xffff))
	sum += uint32(uint16(tixtcp.Version)<<8 | uint16(frame.Flags))
	sum += uint32(tixtcp.HeaderLen)
	sum = checksumAddUint64(sum, frame.FlowID)
	sum = checksumAddUint64(sum, frame.Epoch)
	sum = checksumAddUint64(sum, frame.Sequence)
	sum = checksumAddUint32(sum, uint32(payloadLen))
	sum += uint32(frame.FragmentIndex)
	sum += uint32(frame.FragmentCount)
	sum = checksumAddBytes16(sum, frame.Payload)
	return checksumFold16(sum)
}

func checksumAddUint32(sum uint32, value uint32) uint32 {
	sum += uint32(uint16(value >> 16))
	sum += uint32(uint16(value))
	return sum
}

func checksumAddUint64(sum uint32, value uint64) uint32 {
	sum += uint32(uint16(value >> 48))
	sum += uint32(uint16(value >> 32))
	sum += uint32(uint16(value >> 16))
	sum += uint32(uint16(value))
	return sum
}

func checksumAddBytes16(sum uint32, payload []byte) uint32 {
	for len(payload) >= 32 {
		sum += uint32(binary.BigEndian.Uint16(payload[0:2]))
		sum += uint32(binary.BigEndian.Uint16(payload[2:4]))
		sum += uint32(binary.BigEndian.Uint16(payload[4:6]))
		sum += uint32(binary.BigEndian.Uint16(payload[6:8]))
		sum += uint32(binary.BigEndian.Uint16(payload[8:10]))
		sum += uint32(binary.BigEndian.Uint16(payload[10:12]))
		sum += uint32(binary.BigEndian.Uint16(payload[12:14]))
		sum += uint32(binary.BigEndian.Uint16(payload[14:16]))
		sum += uint32(binary.BigEndian.Uint16(payload[16:18]))
		sum += uint32(binary.BigEndian.Uint16(payload[18:20]))
		sum += uint32(binary.BigEndian.Uint16(payload[20:22]))
		sum += uint32(binary.BigEndian.Uint16(payload[22:24]))
		sum += uint32(binary.BigEndian.Uint16(payload[24:26]))
		sum += uint32(binary.BigEndian.Uint16(payload[26:28]))
		sum += uint32(binary.BigEndian.Uint16(payload[28:30]))
		sum += uint32(binary.BigEndian.Uint16(payload[30:32]))
		payload = payload[32:]
	}
	for len(payload) >= 8 {
		value := binary.BigEndian.Uint64(payload[:8])
		sum += uint32(value >> 48)
		sum += uint32((value >> 32) & 0xffff)
		sum += uint32((value >> 16) & 0xffff)
		sum += uint32(value & 0xffff)
		payload = payload[8:]
	}
	for len(payload) > 1 {
		sum += uint32(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	return sum
}

func checksumFold16(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (socket *afXDPSocket) publishPreparedKernelCryptoFrameBatchLocked(items []preparedTIXTCPTXFrame, dstMAC net.HardwareAddr, sealer tixTCPEthernetSealer) (err error) {
	if len(items) == 0 {
		return nil
	}
	if cap(socket.txBatchDescs) < len(items) {
		socket.txBatchDescs = make([]unix.XDPDesc, 0, len(items))
	} else {
		socket.txBatchDescs = socket.txBatchDescs[:0]
	}
	if cap(socket.txBatchAddrs) < len(items) {
		socket.txBatchAddrs = make([]uint64, 0, len(items))
	} else {
		socket.txBatchAddrs = socket.txBatchAddrs[:0]
	}
	published := false
	defer func() {
		if err != nil && !published {
			for _, addr := range socket.txBatchAddrs {
				socket.releaseTXFrame(addr)
			}
		}
		socket.txBatchDescs = socket.txBatchDescs[:0]
		socket.txBatchAddrs = socket.txBatchAddrs[:0]
	}()
	for _, item := range items {
		packetLen := item.packetLen
		if packetLen <= 0 {
			framePayloadLen, frameErr := tixtcp.FrameWireLen(len(item.wireFrame.Payload))
			if frameErr != nil {
				return frameErr
			}
			packetLen, frameErr = tixtcp.TCPShapedIPv4WireLen(framePayloadLen)
			if frameErr != nil {
				return frameErr
			}
		}
		if packetLen+ethernetHeaderLen+tixTCPKernelCryptoOverhead > int(socket.umemFrameSize) {
			socket.stats.mtuExceeded.Add(1)
			return fmt.Errorf("%w: tix_tcp AF_XDP sealed frame size %d exceeds UMEM frame size %d", errMTUExceeded, packetLen+ethernetHeaderLen+tixTCPKernelCryptoOverhead, socket.umemFrameSize)
		}
		addr, ok := socket.acquireTXFrameLocked()
		if !ok {
			socket.stats.txPoolExhausted.Add(1)
			return fmt.Errorf("%w", errAFXDPTXPoolExhausted)
		}
		socket.txBatchAddrs = append(socket.txBatchAddrs, addr)
		start := int(addr)
		maxEnd := start + ethernetHeaderLen + packetLen + tixTCPKernelCryptoOverhead
		if maxEnd > len(socket.umem) {
			return fmt.Errorf("AF_XDP tx seal frame out of bounds addr=%d len=%d", addr, ethernetHeaderLen+packetLen+tixTCPKernelCryptoOverhead)
		}
		inputLen := ethernetHeaderLen + packetLen
		frame := socket.umem[start:maxEnd]
		copy(frame[0:6], dstMAC)
		copy(frame[6:12], socket.linkMAC)
		binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
		if err := marshalPreparedTIXTCPIPv4FrameInto(item, frame[ethernetHeaderLen:inputLen], socket.skipTCPChecksum); err != nil {
			return err
		}
		sealedLen, err := sealer.SealEthernetInPlace(frame, inputLen)
		if err != nil {
			return err
		}
		socket.txBatchDescs = append(socket.txBatchDescs, unix.XDPDesc{Addr: addr, Len: uint32(sealedLen)})
	}
	published, err = socket.publishTXFramesLocked(socket.txBatchDescs, false)
	if err != nil {
		return err
	}
	socket.stats.txBatchSubmissions.Add(1)
	socket.stats.txBatchFrames.Add(uint64(len(socket.txBatchDescs)))
	socket.stats.txUMEMDirectBuild.Add(uint64(len(socket.txBatchDescs)))
	socket.stats.txFrames.Add(uint64(len(socket.txBatchDescs)))
	return socket.finishTXBatchLocked(len(socket.txBatchDescs))
}

func (socket *afXDPSocket) publishPreparedKernelCryptoFrameLocked(packet tixtcp.TCPPacket, wireFrame tixtcp.Frame, dstMAC net.HardwareAddr, sealer tixTCPEthernetSealer) error {
	framePayloadLen, err := tixtcp.FrameWireLen(len(wireFrame.Payload))
	if err != nil {
		return err
	}
	packetLen, err := tixtcp.TCPShapedIPv4WireLen(framePayloadLen)
	if err != nil {
		return err
	}
	if packetLen+ethernetHeaderLen+tixTCPKernelCryptoOverhead > int(socket.umemFrameSize) {
		socket.stats.mtuExceeded.Add(1)
		return fmt.Errorf("%w: tix_tcp AF_XDP sealed frame size %d exceeds UMEM frame size %d", errMTUExceeded, packetLen+ethernetHeaderLen+tixTCPKernelCryptoOverhead, socket.umemFrameSize)
	}
	addr, ok := socket.acquireTXFrameLocked()
	if !ok {
		socket.stats.txPoolExhausted.Add(1)
		return fmt.Errorf("%w", errAFXDPTXPoolExhausted)
	}
	start := int(addr)
	maxEnd := start + ethernetHeaderLen + packetLen + tixTCPKernelCryptoOverhead
	if maxEnd > len(socket.umem) {
		socket.releaseTXFrame(addr)
		return fmt.Errorf("AF_XDP tx seal frame out of bounds addr=%d len=%d", addr, ethernetHeaderLen+packetLen+tixTCPKernelCryptoOverhead)
	}
	inputLen := ethernetHeaderLen + packetLen
	frame := socket.umem[start:maxEnd]
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], socket.linkMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	item := preparedTIXTCPTXFrame{
		packet:    packet,
		wireFrame: wireFrame,
		frameLen:  framePayloadLen,
		packetLen: packetLen,
	}
	if err := marshalPreparedTIXTCPIPv4FrameInto(item, frame[ethernetHeaderLen:inputLen], socket.skipTCPChecksum); err != nil {
		socket.releaseTXFrame(addr)
		return err
	}
	sealedLen, err := sealer.SealEthernetInPlace(frame, inputLen)
	if err != nil {
		socket.releaseTXFrame(addr)
		return err
	}
	if published, err := socket.publishTXFrameLocked(addr, uint32(sealedLen), false); err != nil {
		if !published {
			socket.releaseTXFrame(addr)
		}
		return err
	}
	socket.stats.txUMEMDirectBuild.Add(1)
	socket.stats.txFrames.Add(1)
	return nil
}

func (socket *afXDPSocket) publishTXFrame(addr uint64, length uint32) (bool, error) {
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	return socket.publishTXFrameLocked(addr, length, false)
}

func (socket *afXDPSocket) beginTXBatchLocked() {
	socket.txBatchActive = true
	socket.reclaimCompletionsLocked()
}

func (socket *afXDPSocket) publishTXFrameLocked(addr uint64, length uint32, forceKick bool) (bool, error) {
	desc := unix.XDPDesc{Addr: addr, Len: length}
	if err := socket.tx.Push(desc); err == nil {
		return true, socket.kickTXIfNeededLocked(forceKick)
	}
	if err := socket.kickTXLocked(); err != nil {
		return false, err
	}
	if reclaimed := socket.reclaimCompletionsLocked(); reclaimed > 0 {
		socket.stats.txBackpressureReclaims.Add(uint64(reclaimed))
	}
	if err := socket.tx.Push(desc); err == nil {
		return true, socket.kickTXIfNeededLocked(forceKick)
	}
	if socket.txBackpressureWait <= 0 {
		socket.stats.txRingFull.Add(1)
		return false, fmt.Errorf("%w", errAFXDPRingFull)
	}
	socket.stats.txBackpressureWaits.Add(1)
	deadline := time.Now().Add(socket.txBackpressureWait)
	for {
		if err := socket.kickTXLocked(); err != nil {
			return false, err
		}
		if reclaimed := socket.reclaimCompletionsLocked(); reclaimed > 0 {
			socket.stats.txBackpressureReclaims.Add(uint64(reclaimed))
		}
		if err := socket.tx.Push(desc); err == nil {
			return true, socket.kickTXIfNeededLocked(forceKick)
		}
		if !time.Now().Before(deadline) {
			socket.stats.txRingFull.Add(1)
			socket.stats.txBackpressureTimeouts.Add(1)
			return false, fmt.Errorf("%w", errAFXDPRingFull)
		}
		time.Sleep(socket.txBackpressurePoll)
	}
}

func (socket *afXDPSocket) publishTXFramesLocked(descs []unix.XDPDesc, forceKick bool) (bool, error) {
	if len(descs) == 0 {
		return true, nil
	}
	if err := socket.tx.PushBatch(descs); err == nil {
		return true, socket.kickTXIfNeededBatchLocked(uint32(len(descs)), forceKick)
	}
	if err := socket.kickTXLocked(); err != nil {
		return false, err
	}
	if reclaimed := socket.reclaimCompletionsLocked(); reclaimed > 0 {
		socket.stats.txBackpressureReclaims.Add(uint64(reclaimed))
	}
	if err := socket.tx.PushBatch(descs); err == nil {
		return true, socket.kickTXIfNeededBatchLocked(uint32(len(descs)), forceKick)
	}
	if socket.txBackpressureWait <= 0 {
		socket.stats.txRingFull.Add(1)
		return false, fmt.Errorf("%w", errAFXDPRingFull)
	}
	socket.stats.txBackpressureWaits.Add(1)
	deadline := time.Now().Add(socket.txBackpressureWait)
	for {
		if err := socket.kickTXLocked(); err != nil {
			return false, err
		}
		if reclaimed := socket.reclaimCompletionsLocked(); reclaimed > 0 {
			socket.stats.txBackpressureReclaims.Add(uint64(reclaimed))
		}
		if err := socket.tx.PushBatch(descs); err == nil {
			return true, socket.kickTXIfNeededBatchLocked(uint32(len(descs)), forceKick)
		}
		if !time.Now().Before(deadline) {
			socket.stats.txRingFull.Add(1)
			socket.stats.txBackpressureTimeouts.Add(1)
			return false, fmt.Errorf("%w", errAFXDPRingFull)
		}
		time.Sleep(socket.txBackpressurePoll)
	}
}

func (socket *afXDPSocket) flushTX() error {
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	return socket.flushTXPendingLocked()
}

func (socket *afXDPSocket) flushTXPendingLocked() error {
	socket.txBatchActive = false
	if socket.txPendingKick == 0 {
		return nil
	}
	if socket.txFlushInterval > 0 &&
		socket.txPendingKick < socket.txKickBatch &&
		!socket.txLastKick.IsZero() &&
		time.Since(socket.txLastKick) < socket.txFlushInterval {
		socket.stats.txKickDeferred.Add(1)
		return nil
	}
	return socket.kickTXLocked()
}

func (socket *afXDPSocket) finishTXBatchLocked(count int) error {
	if socket.txDeferFlush && count > 1 && socket.txKickBatch > 1 && socket.txPendingKick > 0 {
		socket.txBatchActive = false
		socket.stats.txDeferredFlushes.Add(1)
		socket.notifyTX()
		return nil
	}
	return socket.flushTXPendingLocked()
}

func (socket *afXDPSocket) kickTXIfNeededLocked(force bool) error {
	return socket.kickTXIfNeededBatchLocked(1, force)
}

func (socket *afXDPSocket) kickTXIfNeededBatchLocked(count uint32, force bool) error {
	if socket.txKickBatch <= 1 {
		socket.markTXPendingLocked()
		return socket.kickTXLocked()
	}
	socket.markTXPendingBatchLocked(count)
	if force || socket.txPendingKick >= socket.txKickBatch {
		return socket.kickTXLocked()
	}
	socket.stats.txKickDeferred.Add(1)
	return nil
}

func (socket *afXDPSocket) kickTXLocked() error {
	if socket.txSoftKickBackoff > 0 && !socket.txLastSoftKick.IsZero() && time.Since(socket.txLastSoftKick) < socket.txSoftKickBackoff {
		socket.stats.txKickDeferred.Add(1)
		return nil
	}
	err := socket.kickTX()
	if errors.Is(err, errAFXDPKickDeferred) {
		if socket.txSoftKickBackoff > 0 {
			socket.txLastSoftKick = time.Now()
		}
		return nil
	}
	if err != nil {
		return err
	}
	socket.txLastSoftKick = time.Time{}
	socket.txPendingKick = 0
	if socket.txFlushInterval > 0 {
		socket.txLastKick = time.Now()
	}
	return nil
}

func (socket *afXDPSocket) markTXPendingLocked() {
	socket.markTXPendingBatchLocked(1)
}

func (socket *afXDPSocket) markTXPendingBatchLocked(count uint32) {
	if socket.txKickBatch <= 1 {
		socket.txPendingKick = 1
		return
	}
	if count == 0 {
		return
	}
	wasIdle := socket.txPendingKick == 0
	if count >= socket.txKickBatch || socket.txPendingKick > socket.txKickBatch-count {
		socket.txPendingKick = socket.txKickBatch
	} else {
		socket.txPendingKick += count
	}
	if wasIdle && socket.txPendingKick > 0 {
		socket.notifyTX()
	}
}

func (socket *afXDPSocket) notifyTX() {
	if socket.txNotify == nil {
		return
	}
	select {
	case socket.txNotify <- struct{}{}:
	default:
	}
}

func (socket *afXDPSocket) kickTX() error {
	socket.recordNeedWakeupSnapshot()
	if socket.needWakeup && !socket.tx.NeedsWakeup() {
		socket.stats.txKickNeedWakeupSkips.Add(1)
		return nil
	}
	if err := unix.Sendto(socket.fd, nil, unix.MSG_DONTWAIT, nil); err != nil {
		if isAFXDPKickSoftError(err) {
			socket.stats.txKickSoftErrors.Add(1)
			return errAFXDPKickDeferred
		}
		socket.stats.txKickErrors.Add(1)
		return fmt.Errorf("kick AF_XDP tx: %w", err)
	}
	socket.stats.txKicks.Add(1)
	return nil
}

func (socket *afXDPSocket) recordNeedWakeupSnapshot() {
	if socket == nil || !socket.needWakeup {
		return
	}
	if socket.rx.NeedsWakeup() {
		socket.stats.rxNeedWakeupSeen.Add(1)
	}
	if socket.fill.NeedsWakeup() {
		socket.stats.fillNeedWakeupSeen.Add(1)
	}
	if socket.tx.NeedsWakeup() {
		socket.stats.txNeedWakeupSeen.Add(1)
	}
}

func isAFXDPKickSoftError(err error) bool {
	return errors.Is(err, unix.EAGAIN) ||
		errors.Is(err, unix.EWOULDBLOCK) ||
		errors.Is(err, unix.EINTR) ||
		errors.Is(err, unix.EBUSY) ||
		errors.Is(err, unix.ENOBUFS)
}

func (socket *afXDPSocket) ReclaimCompletions() int {
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	return socket.reclaimCompletionsLocked()
}

func (socket *afXDPSocket) reclaimCompletionLoop(done <-chan struct{}) {
	activeInterval := 100 * time.Millisecond
	if socket.txKickBatch > 1 {
		activeInterval = time.Millisecond
	}
	notifyInterval := time.Duration(0)
	if socket.txDeferFlush && socket.txDeferFlushDelay > 0 {
		notifyInterval = socket.txDeferFlushDelay
	}
	idleInterval := tixTCPTXReclaimIdleInterval()
	if idleInterval < activeInterval {
		idleInterval = activeInterval
	}
	timer := time.NewTimer(idleInterval)
	defer timer.Stop()
	for {
		select {
		case <-done:
			_ = socket.flushTX()
			socket.ReclaimCompletions()
			return
		case <-socket.txNotify:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if notifyInterval > 0 {
				timer.Reset(notifyInterval)
				continue
			}
			_ = socket.flushTX()
			socket.ReclaimCompletions()
			timer.Reset(activeInterval)
		case <-timer.C:
			_ = socket.flushTX()
			reclaimed := socket.ReclaimCompletions()
			next := idleInterval
			if reclaimed > 0 || socket.hasTXWork() {
				next = activeInterval
			}
			timer.Reset(next)
		}
	}
}

func (socket *afXDPSocket) hasTXWork() bool {
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	return socket.txPendingKick > 0 || socket.tx.Pending() > 0 || socket.comp.Pending() > 0
}

func (socket *afXDPSocket) Stats() map[string]uint64 {
	if socket == nil {
		return nil
	}
	return map[string]uint64{
		"rx_frames":                             socket.stats.rxFrames.Load(),
		"rx_batches":                            socket.stats.rxBatches.Load(),
		"rx_batch_frames":                       socket.stats.rxBatchFrames.Load(),
		"rx_umem_direct_frames":                 socket.stats.rxUMEMDirectFrames.Load(),
		"rx_invalid":                            socket.stats.rxInvalid.Load(),
		"rx_parse_errors":                       socket.stats.rxParseErrors.Load(),
		"rx_checksum_errors":                    socket.stats.rxChecksumErrors.Load(),
		"rx_recycle_errors":                     socket.stats.rxRecycleErrors.Load(),
		"rx_recycle_deferred":                   socket.stats.rxRecycleDeferred.Load(),
		"rx_recycle_flushes":                    socket.stats.rxRecycleFlushes.Load(),
		"rx_polls":                              socket.stats.rxPolls.Load(),
		"rx_poll_wakeups":                       socket.stats.rxPollWakeups.Load(),
		"rx_poll_idle_backoffs":                 socket.stats.rxPollIdleBackoffs.Load(),
		"rx_poll_idle_resets":                   socket.stats.rxPollIdleResets.Load(),
		"rx_poll_soft_errors":                   socket.stats.rxPollSoftErrors.Load(),
		"rx_multi_frame_batches":                socket.stats.rxMultiFrameBatches.Load(),
		"rx_multi_frame_frames":                 socket.stats.rxMultiFrameFrames.Load(),
		"rx_ring_need_wakeup_seen":              socket.stats.rxNeedWakeupSeen.Load(),
		"fill_ring_need_wakeup_seen":            socket.stats.fillNeedWakeupSeen.Load(),
		"tx_ring_need_wakeup_seen":              socket.stats.txNeedWakeupSeen.Load(),
		"ring_need_wakeup_enabled":              socket.stats.ringNeedWakeupEnabled.Load(),
		"rx_ring_pending":                       uint64(socket.rx.Pending()),
		"tx_ring_pending":                       uint64(socket.tx.Pending()),
		"fill_ring_pending":                     uint64(socket.fill.Pending()),
		"completion_ring_pending":               uint64(socket.comp.Pending()),
		"tx_frames":                             socket.stats.txFrames.Load(),
		"tx_batch_submissions":                  socket.stats.txBatchSubmissions.Load(),
		"tx_batch_frames":                       socket.stats.txBatchFrames.Load(),
		"tx_multi_frame_batches":                socket.stats.txMultiFrameBatches.Load(),
		"tx_multi_frame_input_frames":           socket.stats.txMultiFrameInputFrames.Load(),
		"tx_multi_frame_attempts":               socket.stats.txMultiFrameAttempts.Load(),
		"tx_multi_frame_singletons":             socket.stats.txMultiFrameSingletons.Load(),
		"tx_multi_frame_disabled":               socket.stats.txMultiFrameDisabled.Load(),
		"tx_multi_frame_reject_first":           socket.stats.txMultiFrameRejectFirst.Load(),
		"tx_multi_frame_reject_next":            socket.stats.txMultiFrameRejectNext.Load(),
		"tx_multi_frame_reject_tuple":           socket.stats.txMultiFrameRejectTuple.Load(),
		"tx_multi_frame_reject_mtu":             socket.stats.txMultiFrameRejectMTU.Load(),
		"tx_multi_frame_reject_max":             socket.stats.txMultiFrameRejectMax.Load(),
		"tx_multi_frame_reject_error":           socket.stats.txMultiFrameRejectError.Load(),
		"tx_multi_frame_reject_kernel_tx":       socket.stats.txMultiFrameRejectKernelTX.Load(),
		"tx_multi_frame_reject_encrypted":       socket.stats.txMultiFrameRejectEncrypted.Load(),
		"tx_multi_frame_reject_crypto_fragment": socket.stats.txMultiFrameRejectCryptoFragment.Load(),
		"tx_multi_frame_reject_flags":           socket.stats.txMultiFrameRejectFlags.Load(),
		"tx_multi_frame_reject_fragment":        socket.stats.txMultiFrameRejectFragment.Load(),
		"tx_socket_gso_attempts":                socket.stats.txSocketGSOAttempts.Load(),
		"tx_socket_gso_successes":               socket.stats.txSocketGSOSuccesses.Load(),
		"tx_socket_gso_messages":                socket.stats.txSocketGSOMessages.Load(),
		"tx_socket_gso_input_frames":            socket.stats.txSocketGSOInputFrames.Load(),
		"tx_socket_gso_segments":                socket.stats.txSocketGSOSegments.Load(),
		"tx_socket_gso_singles":                 socket.stats.txSocketGSOSingles.Load(),
		"tx_socket_gso_fallbacks":               socket.stats.txSocketGSOFallbacks.Load(),
		"tx_socket_gso_unsupported":             socket.stats.txSocketGSOUnsupported.Load(),
		"tx_socket_gso_errors":                  socket.stats.txSocketGSOErrors.Load(),
		"tx_socket_gso_reject_ineligible":       socket.stats.txSocketGSORejectIneligible.Load(),
		"tx_socket_gso_reject_no_benefit":       socket.stats.txSocketGSORejectNoBenefit.Load(),
		"tx_socket_gso_reject_kernel_tx":        socket.stats.txSocketGSORejectKernelTX.Load(),
		"tx_socket_gso_reject_kernel_opened":    socket.stats.txSocketGSORejectKernelOpened.Load(),
		"tx_socket_gso_reject_not_secure":       socket.stats.txSocketGSORejectNotSecure.Load(),
		"tx_socket_gso_reject_flags":            socket.stats.txSocketGSORejectFlags.Load(),
		"tx_socket_gso_reject_fragment":         socket.stats.txSocketGSORejectFragment.Load(),
		"tx_socket_gso_reject_frame_len":        socket.stats.txSocketGSORejectFrameLen.Load(),
		"tx_socket_gso_reject_tuple":            socket.stats.txSocketGSORejectTuple.Load(),
		"tx_socket_gso_reject_sequence":         socket.stats.txSocketGSORejectSequence.Load(),
		"tx_socket_gso_reject_packet_len":       socket.stats.txSocketGSORejectPacketLen.Load(),
		"tx_socket_gso_reject_max_segments":     socket.stats.txSocketGSORejectMaxSegments.Load(),
		"tx_socket_gso_reject_max_ipv4_len":     socket.stats.txSocketGSORejectMaxIPv4Len.Load(),
		"tx_umem_direct_build_frames":           socket.stats.txUMEMDirectBuild.Load(),
		"tx_completions":                        socket.stats.txCompletions.Load(),
		"tx_pool_exhausted":                     socket.stats.txPoolExhausted.Load(),
		"tx_ring_full":                          socket.stats.txRingFull.Load(),
		"tx_kick_errors":                        socket.stats.txKickErrors.Load(),
		"tx_kick_soft_errors":                   socket.stats.txKickSoftErrors.Load(),
		"tx_kicks":                              socket.stats.txKicks.Load(),
		"tx_kick_need_wakeup_skips":             socket.stats.txKickNeedWakeupSkips.Load(),
		"tx_kick_deferred":                      socket.stats.txKickDeferred.Load(),
		"tx_defer_flush":                        boolCounter(socket.txDeferFlush),
		"tx_defer_flush_delay_ns":               uint64(socket.txDeferFlushDelay),
		"tx_deferred_flushes":                   socket.stats.txDeferredFlushes.Load(),
		"tx_backpressure_waits":                 socket.stats.txBackpressureWaits.Load(),
		"tx_backpressure_reclaims":              socket.stats.txBackpressureReclaims.Load(),
		"tx_backpressure_timeouts":              socket.stats.txBackpressureTimeouts.Load(),
		"mtu_exceeded":                          socket.stats.mtuExceeded.Load(),
		"neighbor_hits":                         socket.stats.neighborHits.Load(),
		"neighbor_misses":                       socket.stats.neighborMisses.Load(),
	}
}

func (socket *afXDPSocket) acquireTXFrame() (uint64, bool) {
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	return socket.acquireTXFrameLocked()
}

func (socket *afXDPSocket) acquireTXFrameLocked() (uint64, bool) {
	if !socket.txBatchActive {
		socket.reclaimCompletionsLocked()
	}
	if n := len(socket.txFree); n > 0 {
		addr := socket.txFree[n-1]
		socket.txFree = socket.txFree[:n-1]
		return addr, true
	}
	if socket.txBackpressureWait <= 0 {
		return 0, false
	}
	socket.stats.txBackpressureWaits.Add(1)
	deadline := time.Now().Add(socket.txBackpressureWait)
	for {
		if socket.txPendingKick > 0 || socket.tx.Pending() > 0 {
			_ = socket.kickTXLocked()
		}
		if reclaimed := socket.reclaimCompletionsLocked(); reclaimed > 0 {
			socket.stats.txBackpressureReclaims.Add(uint64(reclaimed))
		}
		if n := len(socket.txFree); n > 0 {
			addr := socket.txFree[n-1]
			socket.txFree = socket.txFree[:n-1]
			return addr, true
		}
		if !time.Now().Before(deadline) {
			socket.stats.txBackpressureTimeouts.Add(1)
			return 0, false
		}
		time.Sleep(socket.txBackpressurePoll)
	}
}

func (socket *afXDPSocket) reclaimCompletionsLocked() int {
	if socket.comp.producer == nil || socket.comp.consumer == nil || socket.comp.size == 0 {
		return 0
	}
	var reclaimed int
	for {
		addr, ok := socket.comp.Pop()
		if !ok {
			return reclaimed
		}
		reclaimed++
		socket.stats.txCompletions.Add(1)
		socket.releaseTXFrame(addr)
	}
}

func (socket *afXDPSocket) releaseTXFrame(addr uint64) {
	if len(socket.txFree) < cap(socket.txFree) {
		socket.txFree = append(socket.txFree, addr)
	}
}

func (socket *afXDPSocket) txFreeCounts() (int, int) {
	socket.txMu.Lock()
	defer socket.txMu.Unlock()
	return len(socket.txFree), cap(socket.txFree)
}

func (socket *afXDPSocket) Close() error {
	var errs []string
	socket.closeOnce.Do(func() {
		if socket.fd >= 0 {
			if err := unix.Close(socket.fd); err != nil {
				errs = append(errs, err.Error())
			}
			socket.fd = -1
		}
		if socket.txSocketGSOFDValid && socket.txSocketGSOFD >= 0 {
			if err := unix.Close(socket.txSocketGSOFD); err != nil {
				errs = append(errs, err.Error())
			}
			socket.txSocketGSOFD = -1
			socket.txSocketGSOFDValid = false
		}
		for _, ring := range []*xdpDescRing{&socket.rx, &socket.tx} {
			if len(ring.mmap) > 0 {
				if err := unix.Munmap(ring.mmap); err != nil {
					errs = append(errs, err.Error())
				}
				ring.mmap = nil
			}
		}
		for _, ring := range []*xdpUint64Ring{&socket.fill, &socket.comp} {
			if len(ring.mmap) > 0 {
				if err := unix.Munmap(ring.mmap); err != nil {
					errs = append(errs, err.Error())
				}
				ring.mmap = nil
			}
		}
		if len(socket.umem) > 0 {
			if err := unix.Munmap(socket.umem); err != nil {
				errs = append(errs, err.Error())
			}
			socket.umem = nil
		}
	})
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

type xdpDescRing struct {
	mmap     []byte
	producer *uint32
	consumer *uint32
	flags    *uint32
	descs    []unix.XDPDesc
	size     uint32
	mask     uint32
}

func newXDPDescRing(fd int, offset int64, ringOffset unix.XDPRingOffset, entries uint32) (xdpDescRing, error) {
	size := xdpRingMmapSize(ringOffset, entries, unsafe.Sizeof(unix.XDPDesc{}))
	mmap, err := unix.Mmap(fd, offset, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return xdpDescRing{}, err
	}
	return xdpDescRing{
		mmap:     mmap,
		producer: uint32Pointer(mmap, ringOffset.Producer),
		consumer: uint32Pointer(mmap, ringOffset.Consumer),
		flags:    uint32Pointer(mmap, ringOffset.Flags),
		descs:    unsafe.Slice((*unix.XDPDesc)(unsafe.Pointer(&mmap[int(ringOffset.Desc)])), int(entries)),
		size:     entries,
		mask:     entries - 1,
	}, nil
}

func (ring *xdpDescRing) Pop() (unix.XDPDesc, bool) {
	consumer := atomic.LoadUint32(ring.consumer)
	producer := atomic.LoadUint32(ring.producer)
	if producer == consumer {
		return unix.XDPDesc{}, false
	}
	desc := ring.descs[consumer&ring.mask]
	atomic.StoreUint32(ring.consumer, consumer+1)
	return desc, true
}

func (ring *xdpDescRing) PopBatch(descs []unix.XDPDesc) int {
	if len(descs) == 0 {
		return 0
	}
	consumer := atomic.LoadUint32(ring.consumer)
	producer := atomic.LoadUint32(ring.producer)
	available := producer - consumer
	if available == 0 {
		return 0
	}
	if available > uint32(len(descs)) {
		available = uint32(len(descs))
	}
	for i := uint32(0); i < available; i++ {
		descs[i] = ring.descs[(consumer+i)&ring.mask]
	}
	atomic.StoreUint32(ring.consumer, consumer+available)
	return int(available)
}

func (ring *xdpDescRing) Push(desc unix.XDPDesc) error {
	producer := atomic.LoadUint32(ring.producer)
	consumer := atomic.LoadUint32(ring.consumer)
	if producer-consumer >= ring.size {
		return fmt.Errorf("%w: descriptor ring", errAFXDPRingFull)
	}
	ring.descs[producer&ring.mask] = desc
	atomic.StoreUint32(ring.producer, producer+1)
	return nil
}

func (ring *xdpDescRing) PushBatch(descs []unix.XDPDesc) error {
	if len(descs) == 0 {
		return nil
	}
	producer := atomic.LoadUint32(ring.producer)
	consumer := atomic.LoadUint32(ring.consumer)
	if len(descs) > int(ring.size-(producer-consumer)) {
		return fmt.Errorf("%w: descriptor ring", errAFXDPRingFull)
	}
	for i, desc := range descs {
		ring.descs[(producer+uint32(i))&ring.mask] = desc
	}
	atomic.StoreUint32(ring.producer, producer+uint32(len(descs)))
	return nil
}

func (ring *xdpDescRing) Pending() uint32 {
	if ring == nil || ring.producer == nil || ring.consumer == nil {
		return 0
	}
	producer := atomic.LoadUint32(ring.producer)
	consumer := atomic.LoadUint32(ring.consumer)
	return producer - consumer
}

func (ring *xdpDescRing) NeedsWakeup() bool {
	if ring == nil || ring.flags == nil {
		return false
	}
	return atomic.LoadUint32(ring.flags)&unix.XDP_RING_NEED_WAKEUP != 0
}

type xdpUint64Ring struct {
	mmap     []byte
	producer *uint32
	consumer *uint32
	flags    *uint32
	descs    []uint64
	size     uint32
	mask     uint32
}

func newXDPUint64Ring(fd int, offset int64, ringOffset unix.XDPRingOffset, entries uint32) (xdpUint64Ring, error) {
	size := xdpRingMmapSize(ringOffset, entries, unsafe.Sizeof(uint64(0)))
	mmap, err := unix.Mmap(fd, offset, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return xdpUint64Ring{}, err
	}
	return xdpUint64Ring{
		mmap:     mmap,
		producer: uint32Pointer(mmap, ringOffset.Producer),
		consumer: uint32Pointer(mmap, ringOffset.Consumer),
		flags:    uint32Pointer(mmap, ringOffset.Flags),
		descs:    unsafe.Slice((*uint64)(unsafe.Pointer(&mmap[int(ringOffset.Desc)])), int(entries)),
		size:     entries,
		mask:     entries - 1,
	}, nil
}

func (ring *xdpUint64Ring) Pop() (uint64, bool) {
	consumer := atomic.LoadUint32(ring.consumer)
	producer := atomic.LoadUint32(ring.producer)
	if producer == consumer {
		return 0, false
	}
	addr := ring.descs[consumer&ring.mask]
	atomic.StoreUint32(ring.consumer, consumer+1)
	return addr, true
}

func (ring *xdpUint64Ring) Push(addr uint64) error {
	producer := atomic.LoadUint32(ring.producer)
	consumer := atomic.LoadUint32(ring.consumer)
	if producer-consumer >= ring.size {
		return fmt.Errorf("%w: uint64 ring", errAFXDPRingFull)
	}
	ring.descs[producer&ring.mask] = addr
	atomic.StoreUint32(ring.producer, producer+1)
	return nil
}

func (ring *xdpUint64Ring) PushBatch(addrs []uint64) error {
	if len(addrs) == 0 {
		return nil
	}
	producer := atomic.LoadUint32(ring.producer)
	consumer := atomic.LoadUint32(ring.consumer)
	if len(addrs) > int(ring.size-(producer-consumer)) {
		return fmt.Errorf("%w: uint64 ring", errAFXDPRingFull)
	}
	for i, addr := range addrs {
		ring.descs[(producer+uint32(i))&ring.mask] = addr
	}
	atomic.StoreUint32(ring.producer, producer+uint32(len(addrs)))
	return nil
}

func (ring *xdpUint64Ring) Pending() uint32 {
	if ring == nil || ring.producer == nil || ring.consumer == nil {
		return 0
	}
	producer := atomic.LoadUint32(ring.producer)
	consumer := atomic.LoadUint32(ring.consumer)
	return producer - consumer
}

func (ring *xdpUint64Ring) NeedsWakeup() bool {
	if ring == nil || ring.flags == nil {
		return false
	}
	return atomic.LoadUint32(ring.flags)&unix.XDP_RING_NEED_WAKEUP != 0
}

func xdpRingMmapSize(offset unix.XDPRingOffset, entries uint32, descSize uintptr) int {
	maxOffset := offset.Producer + 4
	for _, value := range []uint64{
		offset.Consumer + 4,
		offset.Flags + 4,
		offset.Desc + uint64(entries)*uint64(descSize),
	} {
		if value > maxOffset {
			maxOffset = value
		}
	}
	page := uint64(os.Getpagesize())
	return int((maxOffset + page - 1) & ^(page - 1))
}

func uint32Pointer(mmap []byte, offset uint64) *uint32 {
	return (*uint32)(unsafe.Pointer(&mmap[int(offset)]))
}

func setsockoptXDPUmemReg(fd int, reg *unix.XDPUmemReg) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_XDP),
		uintptr(unix.XDP_UMEM_REG),
		uintptr(unsafe.Pointer(reg)),
		unsafe.Sizeof(*reg),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func getsockoptXDPMmapOffsets(fd int) (unix.XDPMmapOffsets, error) {
	var offsets unix.XDPMmapOffsets
	size := uint32(unsafe.Sizeof(offsets))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_XDP),
		uintptr(unix.XDP_MMAP_OFFSETS),
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return unix.XDPMmapOffsets{}, errno
	}
	return offsets, nil
}

func parseEthernetIPv4Frame(frame []byte) ([]byte, net.HardwareAddr, bool) {
	if len(frame) < ethernetHeaderLen || binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv4 {
		return nil, nil, false
	}
	return frame[ethernetHeaderLen:], net.HardwareAddr(frame[6:12]), true
}

func ipv4Protocol(packet []byte) (byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return 0, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || totalLen > len(packet) {
		return 0, false
	}
	return packet[9], true
}

func marshalKernelUDPIPv4FrameNoChecksumInto(packet kerneludp.UDPPacket, frame kerneludp.Frame, wire []byte) (int, error) {
	if !packet.SourceIP.Is4() || !packet.DestinationIP.Is4() {
		return 0, fmt.Errorf("kernel_udp only supports IPv4 underlay packets")
	}
	if packet.SourcePort == 0 || packet.DestinationPort == 0 {
		return 0, fmt.Errorf("kernel_udp source and destination ports are required")
	}
	payloadLen := len(frame.Payload)
	if payloadLen > kerneludp.MaxPayload {
		return 0, fmt.Errorf("kernel_udp payload size %d exceeds max %d", payloadLen, kerneludp.MaxPayload)
	}
	frameLen := kerneludp.HeaderLen + payloadLen
	udpLen := 8 + frameLen
	totalLen := 20 + udpLen
	if totalLen > 0xffff || udpLen > 0xffff {
		return 0, fmt.Errorf("kernel_udp packet size %d exceeds IPv4/UDP limit", totalLen)
	}
	if len(wire) < totalLen {
		return 0, fmt.Errorf("kernel_udp packet buffer size %d is smaller than wire length %d", len(wire), totalLen)
	}
	wire = wire[:totalLen]
	wire[0] = 0x45
	wire[1] = 0
	binary.BigEndian.PutUint16(wire[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(wire[4:6], 0)
	binary.BigEndian.PutUint16(wire[6:8], 0x4000)
	wire[8] = 64
	wire[9] = unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(wire[10:12], 0)
	src := packet.SourceIP.As4()
	dst := packet.DestinationIP.As4()
	copy(wire[12:16], src[:])
	copy(wire[16:20], dst[:])
	binary.BigEndian.PutUint16(wire[10:12], ipv4Checksum20(wire[:20]))

	udp := wire[20:]
	binary.BigEndian.PutUint16(udp[0:2], packet.SourcePort)
	binary.BigEndian.PutUint16(udp[2:4], packet.DestinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0)

	kudp := udp[8:]
	binary.BigEndian.PutUint32(kudp[0:4], kerneludp.Magic)
	kudp[4] = kerneludp.Version
	kudp[5] = frame.Flags
	binary.BigEndian.PutUint16(kudp[6:8], kerneludp.HeaderLen)
	binary.BigEndian.PutUint64(kudp[8:16], frame.FlowID)
	binary.BigEndian.PutUint64(kudp[16:24], frame.Sequence)
	binary.BigEndian.PutUint32(kudp[24:28], uint32(payloadLen))
	binary.BigEndian.PutUint16(kudp[28:30], frame.FragmentIndex)
	binary.BigEndian.PutUint16(kudp[30:32], frame.FragmentCount)
	copy(kudp[kerneludp.HeaderLen:], frame.Payload)
	return totalLen, nil
}

func ipv4Checksum20(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipv4AddrFromIP(ip net.IP) (netip.Addr, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), true
}
