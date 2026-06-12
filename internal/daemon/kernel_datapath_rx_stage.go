package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
)

const (
	kernelDatapathRXModeStage  = "stage"
	kernelDatapathRXModeWorker = "worker"
)

type kernelDatapathRXStageDriver interface {
	Attach(ifname, targetIfname string, flags uint32) (kernelDatapathRXStageHookStatus, error)
	Detach() error
	DetachFor(ifname string) error
	Clear() (kernelDatapathRXStageResult, error)
	HookQuery() (kernelDatapathRXStageHookStatus, error)
	HookQueryFor(ifname string) (kernelDatapathRXStageHookStatus, error)
	PopInto(out []byte) (kernelDatapathRXStageResult, error)
	Query() (kernelDatapathRXStageResult, error)
	Close() error
}

type kernelDatapathRXStageHookStatus struct {
	Attached         bool
	Flags            uint32
	IfName           string
	IfIndex          int32
	TargetIfName     string
	TargetIfIndex    int32
	RXWorker         uint64
	RXWorkerErrors   uint64
	RXWorkerInjected uint64
	RXWorkerDropped  uint64
}

type kernelDatapathRXStageResult struct {
	Inner       []byte
	WrittenLen  uint32
	QueueLen    uint32
	Capacity    uint32
	Staged      uint64
	Popped      uint64
	Dropped     uint64
	Overwritten uint64
}

type kernelDatapathRXStageRuntime struct {
	mu          sync.Mutex
	cancel      context.CancelFunc
	done        chan struct{}
	driver      kernelDatapathRXStageDriver
	status      kernelDatapathRXStageStatus
	polls       atomic.Uint64
	emptyPolls  atomic.Uint64
	packets     atomic.Uint64
	batches     atomic.Uint64
	errors      atomic.Uint64
	lastError   atomic.Value
	lastStopped atomic.Value
}

type kernelDatapathRXStageStatus struct {
	Enabled          bool      `json:"enabled,omitempty"`
	Active           bool      `json:"active,omitempty"`
	Mode             string    `json:"mode,omitempty"`
	Attached         bool      `json:"attached,omitempty"`
	IfName           string    `json:"ifname,omitempty"`
	IfIndex          int32     `json:"ifindex,omitempty"`
	TargetIfName     string    `json:"target_ifname,omitempty"`
	TargetIfIndex    int32     `json:"target_ifindex,omitempty"`
	Flags            uint32    `json:"flags,omitempty"`
	QueueLen         uint32    `json:"queue_len,omitempty"`
	Capacity         uint32    `json:"capacity,omitempty"`
	Staged           uint64    `json:"staged,omitempty"`
	Popped           uint64    `json:"popped,omitempty"`
	Dropped          uint64    `json:"dropped,omitempty"`
	Overwritten      uint64    `json:"overwritten,omitempty"`
	Polls            uint64    `json:"polls,omitempty"`
	EmptyPolls       uint64    `json:"empty_polls,omitempty"`
	Packets          uint64    `json:"packets,omitempty"`
	Batches          uint64    `json:"batches,omitempty"`
	Errors           uint64    `json:"errors,omitempty"`
	RXWorker         uint64    `json:"rx_worker,omitempty"`
	RXWorkerErrors   uint64    `json:"rx_worker_errors,omitempty"`
	RXWorkerInjected uint64    `json:"rx_worker_injected,omitempty"`
	RXWorkerDropped  uint64    `json:"rx_worker_dropped,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	LastStopped      string    `json:"last_stopped,omitempty"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	DisabledReason   string    `json:"disabled_reason,omitempty"`
	InactiveReason   string    `json:"inactive_reason,omitempty"`
	BatchSize        int       `json:"batch_size,omitempty"`
	IdleDelayMillis  int64     `json:"idle_delay_ms,omitempty"`
}

var kernelDatapathRXStageOpenDriver = openKernelDatapathRXStageDriver

func (daemon *Daemon) startKernelDatapathRXStage(ctx context.Context, spec dataplane.AttachSpec) error {
	daemon.stopKernelDatapathRXStage()
	mode := kernelDatapathRXModeForDesired(daemon.desired)
	if mode == "" {
		daemon.setKernelDatapathRXStageInactive(kernelDatapathRXStageStatus{
			Enabled:        false,
			DisabledReason: kernelDatapathRXDisabledReasonForDesired(daemon.desired),
		})
		return nil
	}
	if mode == kernelDatapathRXModeWorker && !kernelDatapathRXWorkerSupportedForSpecForDesired(daemon.desired, spec) {
		daemon.setKernelDatapathRXStageInactive(kernelDatapathRXStageStatus{
			Enabled:        true,
			Mode:           mode,
			InactiveReason: "RX_WORKER is disabled for experimental_tcp TC direct; use TC/XDP RX direct or TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP=1",
		})
		return nil
	}
	if !daemon.kernelDatapathAvailable() {
		daemon.setKernelDatapathRXStageInactive(kernelDatapathRXStageStatus{
			Enabled:        true,
			InactiveReason: "trustix_datapath module is not loaded",
		})
		return nil
	}
	ifname := kernelDatapathRXStageUnderlayIface(spec)
	if ifname == "" {
		daemon.setKernelDatapathRXStageInactive(kernelDatapathRXStageStatus{
			Enabled:        true,
			InactiveReason: "no underlay interface is configured",
		})
		return nil
	}
	driver, err := kernelDatapathRXStageOpenDriver()
	if err != nil {
		daemon.setKernelDatapathRXStageInactive(kernelDatapathRXStageStatus{
			Enabled:        true,
			InactiveReason: err.Error(),
		})
		return nil
	}
	targetIfname := ""
	flags := kernelDatapathRXStageHookFlags()
	if mode == kernelDatapathRXModeWorker {
		targetIfname = kernelDatapathRXStageTargetIface(spec, ifname)
		if targetIfname == "" {
			_ = driver.Close()
			daemon.setKernelDatapathRXStageInactive(kernelDatapathRXStageStatus{
				Enabled:        true,
				Mode:           mode,
				InactiveReason: "RX_WORKER requires a configured LAN target interface",
			})
			return nil
		}
		flags = kernelDatapathRXWorkerHookFlags()
	}
	hook, err := attachKernelDatapathRXHook(driver, ifname, targetIfname, flags)
	if err != nil {
		_ = driver.Close()
		daemon.setKernelDatapathRXStageInactive(kernelDatapathRXStageStatus{
			Enabled:        true,
			Mode:           mode,
			InactiveReason: err.Error(),
		})
		return nil
	}
	if kernelDatapathFullPlaintextEnabledForDesired(daemon.desired) {
		txHook, txErr := attachKernelDatapathRXHook(
			driver, targetIfname, ifname,
			kernelDatapathTXPlaintextHookFlags(),
		)
		if txErr != nil {
			_ = driver.DetachFor(ifname)
			_ = driver.Close()
			daemon.setKernelDatapathRXStageInactive(kernelDatapathRXStageStatus{
				Enabled:        true,
				Mode:           mode,
				InactiveReason: txErr.Error(),
			})
			return nil
		}
		if txHook.Attached {
			hook.RXWorker = txHook.RXWorker
		}
	}
	stage, err := driver.Clear()
	if err != nil {
		_ = driver.DetachFor(ifname)
		if kernelDatapathFullPlaintextEnabledForDesired(daemon.desired) {
			_ = driver.DetachFor(targetIfname)
		}
		_ = driver.Close()
		daemon.setKernelDatapathRXStageInactive(kernelDatapathRXStageStatus{
			Enabled:        true,
			Mode:           mode,
			InactiveReason: err.Error(),
		})
		return nil
	}
	var pollerCtx context.Context
	var cancel context.CancelFunc
	var done chan struct{}
	if mode == kernelDatapathRXModeStage {
		pollerCtx, cancel = context.WithCancel(ctx)
		done = make(chan struct{})
	}
	status := kernelDatapathRXStageStatus{
		Enabled:          true,
		Active:           true,
		Mode:             mode,
		Attached:         hook.Attached,
		IfName:           hook.IfName,
		IfIndex:          hook.IfIndex,
		TargetIfName:     hook.TargetIfName,
		TargetIfIndex:    hook.TargetIfIndex,
		Flags:            hook.Flags,
		QueueLen:         stage.QueueLen,
		Capacity:         stage.Capacity,
		Staged:           stage.Staged,
		Popped:           stage.Popped,
		Dropped:          stage.Dropped,
		Overwritten:      stage.Overwritten,
		StartedAt:        time.Now().UTC(),
		RXWorker:         hook.RXWorker,
		RXWorkerErrors:   hook.RXWorkerErrors,
		RXWorkerInjected: hook.RXWorkerInjected,
		RXWorkerDropped:  hook.RXWorkerDropped,
	}
	if mode == kernelDatapathRXModeStage {
		status.BatchSize = kernelDatapathRXStageBatchSize()
		status.IdleDelayMillis = kernelDatapathRXStageIdleDelay().Milliseconds()
	}
	daemon.kernelRXStage.mu.Lock()
	daemon.kernelRXStage.cancel = cancel
	daemon.kernelRXStage.done = done
	daemon.kernelRXStage.driver = driver
	daemon.kernelRXStage.status = status
	daemon.kernelRXStage.mu.Unlock()
	if mode == kernelDatapathRXModeStage {
		go daemon.runKernelDatapathRXStagePoller(pollerCtx, done, driver, status.BatchSize, kernelDatapathRXStageIdleDelay(), kernelDatapathRXStageErrorDelay())
	}
	return nil
}

func attachKernelDatapathRXHook(driver kernelDatapathRXStageDriver, ifname, targetIfname string, flags uint32) (kernelDatapathRXStageHookStatus, error) {
	hook, err := driver.Attach(ifname, targetIfname, flags)
	if err == nil {
		return hook, nil
	}
	if !errors.Is(err, syscall.EALREADY) {
		return kernelDatapathRXStageHookStatus{}, err
	}
	hook, queryErr := driver.HookQueryFor(ifname)
	if queryErr == nil && kernelDatapathRXHookMatches(hook, ifname, targetIfname, flags) {
		return hook, nil
	}
	if detachErr := driver.DetachFor(ifname); detachErr != nil && !errors.Is(detachErr, syscall.ENOENT) {
		if queryErr != nil {
			return kernelDatapathRXStageHookStatus{}, fmt.Errorf("existing kernel datapath hook is busy and query failed: %w; detach failed: %v", queryErr, detachErr)
		}
		return kernelDatapathRXStageHookStatus{}, fmt.Errorf("existing kernel datapath hook does not match desired attachment and detach failed: %w", detachErr)
	}
	return driver.Attach(ifname, targetIfname, flags)
}

func kernelDatapathRXHookMatches(hook kernelDatapathRXStageHookStatus, ifname, targetIfname string, flags uint32) bool {
	if !hook.Attached {
		return false
	}
	if hook.Flags != flags {
		return false
	}
	if strings.TrimSpace(hook.IfName) != strings.TrimSpace(ifname) {
		return false
	}
	return strings.TrimSpace(hook.TargetIfName) == strings.TrimSpace(targetIfname)
}

func (daemon *Daemon) stopKernelDatapathRXStage() {
	daemon.kernelRXStage.mu.Lock()
	cancel := daemon.kernelRXStage.cancel
	done := daemon.kernelRXStage.done
	driver := daemon.kernelRXStage.driver
	daemon.kernelRXStage.cancel = nil
	daemon.kernelRXStage.done = nil
	daemon.kernelRXStage.driver = nil
	if daemon.kernelRXStage.status.Active {
		daemon.kernelRXStage.status.Active = false
		daemon.kernelRXStage.status.InactiveReason = "stopped"
	}
	daemon.kernelRXStage.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	if driver != nil {
		_ = driver.Detach()
		_, _ = driver.Clear()
		_ = driver.Close()
	}
}

func (daemon *Daemon) setKernelDatapathRXStageInactive(status kernelDatapathRXStageStatus) {
	daemon.kernelRXStage.mu.Lock()
	status.Active = false
	status.Polls = daemon.kernelRXStage.polls.Load()
	status.EmptyPolls = daemon.kernelRXStage.emptyPolls.Load()
	status.Packets = daemon.kernelRXStage.packets.Load()
	status.Batches = daemon.kernelRXStage.batches.Load()
	status.Errors = daemon.kernelRXStage.errors.Load()
	if value, ok := daemon.kernelRXStage.lastError.Load().(string); ok {
		status.LastError = value
	}
	if value, ok := daemon.kernelRXStage.lastStopped.Load().(string); ok {
		status.LastStopped = value
	}
	daemon.kernelRXStage.status = status
	daemon.kernelRXStage.mu.Unlock()
}

func (daemon *Daemon) kernelDatapathRXStageStatus() kernelDatapathRXStageStatus {
	daemon.kernelRXStage.mu.Lock()
	status := daemon.kernelRXStage.status
	driver := daemon.kernelRXStage.driver
	daemon.kernelRXStage.mu.Unlock()
	if driver != nil {
		if query, err := driver.Query(); err == nil {
			status.QueueLen = query.QueueLen
			status.Capacity = query.Capacity
			status.Staged = query.Staged
			status.Popped = query.Popped
			status.Dropped = query.Dropped
			status.Overwritten = query.Overwritten
		}
		hook, err := driver.HookQuery()
		if status.IfName != "" {
			if mainHook, mainErr := driver.HookQueryFor(status.IfName); mainErr == nil {
				hook = mainHook
				err = nil
			}
		}
		if err == nil {
			status.Attached = hook.Attached
			status.Flags = hook.Flags
			status.IfName = hook.IfName
			status.IfIndex = hook.IfIndex
			status.TargetIfName = hook.TargetIfName
			status.TargetIfIndex = hook.TargetIfIndex
			status.RXWorker = hook.RXWorker
			status.RXWorkerErrors = hook.RXWorkerErrors
			status.RXWorkerInjected = hook.RXWorkerInjected
			status.RXWorkerDropped = hook.RXWorkerDropped
		}
	}
	status.Polls = daemon.kernelRXStage.polls.Load()
	status.EmptyPolls = daemon.kernelRXStage.emptyPolls.Load()
	status.Packets = daemon.kernelRXStage.packets.Load()
	status.Batches = daemon.kernelRXStage.batches.Load()
	status.Errors = daemon.kernelRXStage.errors.Load()
	if value, ok := daemon.kernelRXStage.lastError.Load().(string); ok {
		status.LastError = value
	}
	if value, ok := daemon.kernelRXStage.lastStopped.Load().(string); ok {
		status.LastStopped = value
	}
	return status
}

func (daemon *Daemon) runKernelDatapathRXStagePoller(ctx context.Context, done chan<- struct{}, driver kernelDatapathRXStageDriver, batchSize int, idleDelay, errorDelay time.Duration) {
	defer close(done)
	injector, _ := daemon.dataplane.(dataplane.PacketInjector)
	batchInjector, _ := daemon.dataplane.(dataplane.PacketBatchInjector)
	buffers := make([][]byte, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, kernelDatapathRXStagePacketBufferLen)
	}
	packets := make([][]byte, 0, batchSize)
	var scratch dataReceiveScratch
	defer scratch.release()
	for {
		if err := ctx.Err(); err != nil {
			daemon.kernelRXStage.lastStopped.Store(err.Error())
			return
		}
		packets = packets[:0]
		var last kernelDatapathRXStageResult
		var popErr error
		for len(packets) < batchSize {
			daemon.kernelRXStage.polls.Add(1)
			daemon.dataStats.kernelRXStagePolls.Add(1)
			result, err := driver.PopInto(buffers[len(packets)])
			if err != nil {
				if errors.Is(err, errKernelDatapathRXStageEmpty) {
					if len(packets) == 0 {
						daemon.kernelRXStage.emptyPolls.Add(1)
						daemon.dataStats.kernelRXStageEmptyPolls.Add(1)
					}
					last = result
					break
				}
				popErr = err
				last = result
				break
			}
			if result.WrittenLen == 0 || int(result.WrittenLen) > len(buffers[len(packets)]) {
				popErr = fmt.Errorf("kernel RX_STAGE invalid packet length %d", result.WrittenLen)
				last = result
				break
			}
			packets = append(packets, buffers[len(packets)][:result.WrittenLen])
			last = result
		}
		if len(packets) > 0 {
			daemon.kernelRXStage.packets.Add(uint64(len(packets)))
			daemon.kernelRXStage.batches.Add(1)
			daemon.dataStats.kernelRXStagePackets.Add(uint64(len(packets)))
			daemon.dataStats.kernelRXStageBatches.Add(1)
			daemon.handleReceivedDataPathBatch(ctx, packets, injector, batchInjector, &scratch)
			scratch.release()
		}
		daemon.updateKernelDatapathRXStageQueueStatus(last)
		if popErr != nil {
			daemon.kernelRXStage.errors.Add(1)
			daemon.dataStats.kernelRXStageErrors.Add(1)
			daemon.kernelRXStage.lastError.Store(popErr.Error())
			if !sleepContext(ctx, errorDelay) {
				daemon.kernelRXStage.lastStopped.Store(ctx.Err().Error())
				return
			}
			continue
		}
		if len(packets) == 0 && !sleepContext(ctx, idleDelay) {
			daemon.kernelRXStage.lastStopped.Store(ctx.Err().Error())
			return
		}
	}
}

func (daemon *Daemon) updateKernelDatapathRXStageQueueStatus(result kernelDatapathRXStageResult) {
	daemon.kernelRXStage.mu.Lock()
	status := daemon.kernelRXStage.status
	status.QueueLen = result.QueueLen
	status.Capacity = result.Capacity
	status.Staged = result.Staged
	status.Popped = result.Popped
	status.Dropped = result.Dropped
	status.Overwritten = result.Overwritten
	daemon.kernelRXStage.status = status
	daemon.kernelRXStage.mu.Unlock()
}

func kernelDatapathRXStageUnderlayIface(spec dataplane.AttachSpec) string {
	for _, lan := range spec.LANs {
		if ifname := strings.TrimSpace(lan.UnderlayIface); ifname != "" {
			return ifname
		}
	}
	if ifname := strings.TrimSpace(spec.UnderlayIface); ifname != "" {
		return ifname
	}
	return ""
}

func kernelDatapathRXStageTargetIface(spec dataplane.AttachSpec, underlayIfname string) string {
	for _, lan := range spec.LANs {
		if strings.TrimSpace(lan.UnderlayIface) == underlayIfname {
			if ifname := strings.TrimSpace(lan.Iface); ifname != "" {
				return ifname
			}
		}
	}
	if ifname := strings.TrimSpace(spec.LANIface); ifname != "" {
		return ifname
	}
	for _, lan := range spec.LANs {
		if ifname := strings.TrimSpace(lan.Iface); ifname != "" {
			return ifname
		}
	}
	return ""
}

func kernelDatapathRXMode() string {
	return kernelDatapathRXModeForDesired(config.Desired{})
}

func kernelDatapathRXModeForDesired(desired config.Desired) string {
	if mode, ok := kernelDatapathRXStageModeFromEnv(); ok {
		if mode == "" {
			return ""
		}
		if mode == kernelDatapathRXModeWorker && !kernelDatapathRXWorkerCrashRiskAllowed() {
			return ""
		}
		if mode == kernelDatapathRXModeWorker {
			return mode
		}
		if kernelDatapathFullPlaintextRequestedForDesired(desired) {
			if kernelDatapathFullPlaintextEnabledForDesired(desired) {
				return kernelDatapathRXModeWorker
			}
			return ""
		}
		if kernelDatapathRXWorkerRequestedByEnv() {
			if kernelDatapathRXWorkerCrashRiskAllowed() {
				return kernelDatapathRXModeWorker
			}
			return ""
		}
		return mode
	}
	requestedRXStage := config.NormalizeKernelDatapathRXStage(desired.KernelModules.Datapath.RXStage)
	if requestedRXStage == config.KernelDatapathRXStageDisabled {
		return ""
	}
	if kernelDatapathFullPlaintextEnabledForDesired(desired) {
		return kernelDatapathRXModeWorker
	}
	switch requestedRXStage {
	case config.KernelDatapathRXStageAuto, config.KernelDatapathRXStageStage:
		return kernelDatapathRXModeStage
	case config.KernelDatapathRXStageWorker:
		if kernelDatapathRXWorkerCrashRiskAllowed() {
			return kernelDatapathRXModeWorker
		}
		return ""
	}
	if desired.KernelModules.Datapath.RXWorker {
		if kernelDatapathRXWorkerCrashRiskAllowed() {
			return kernelDatapathRXModeWorker
		}
		return ""
	}
	if kernelDatapathRXWorkerRequestedByEnv() {
		if kernelDatapathRXWorkerCrashRiskAllowed() {
			return kernelDatapathRXModeWorker
		}
		return ""
	}
	return ""
}

func kernelDatapathFullPlaintextEnabled() bool {
	return kernelDatapathFullPlaintextEnabledForDesired(config.Desired{})
}

func kernelDatapathFullPlaintextEnabledForDesired(desired config.Desired) bool {
	runtime := config.EffectiveKernelDatapathRuntime(desired.KernelModules)
	if runtime.FullPlaintext || runtime.TXPlaintext {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT"))) {
	case "1", "true", "yes", "on", "enabled", "full":
		return kernelDatapathFullPlaintextCrashRiskAllowed()
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_DATAPATH_TX_PLAINTEXT"))) {
	case "1", "true", "yes", "on", "enabled":
		return kernelDatapathFullPlaintextCrashRiskAllowed()
	default:
		return false
	}
}

func kernelDatapathRXWorkerSupportedForSpec(spec dataplane.AttachSpec) bool {
	return kernelDatapathRXWorkerSupportedForSpecForDesired(config.Desired{}, spec)
}

func kernelDatapathRXWorkerSupportedForSpecForDesired(desired config.Desired, spec dataplane.AttachSpec) bool {
	if !spec.ExperimentalTCPTXDirect {
		return true
	}
	runtime := config.EffectiveKernelDatapathRuntime(desired.KernelModules)
	if runtime.RXWorkerAllowExperimentalTCP &&
		(kernelDatapathFullPlaintextEnabledForDesired(desired) || kernelDatapathRXWorkerCrashRiskAllowed()) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP"))) {
	case "1", "true", "yes", "on", "enabled", "force", "unsafe":
		return true
	default:
		return false
	}
}

func kernelDatapathRXStageEnabled() bool {
	return kernelDatapathRXStageEnabledForDesired(config.Desired{})
}

func kernelDatapathRXStageEnabledForDesired(desired config.Desired) bool {
	return kernelDatapathRXModeForDesired(desired) != ""
}

func kernelDatapathRXStageModeFromEnv() (string, bool) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE"))) {
	case "":
		return "", false
	case "0", "false", "no", "off", "disabled":
		return "", true
	case "worker":
		return kernelDatapathRXModeWorker, true
	case "1", "true", "yes", "on", "enabled", "auto", "stage", "poll", "poller":
		return kernelDatapathRXModeStage, true
	default:
		return kernelDatapathRXModeStage, true
	}
}

func kernelDatapathRXDisabledReasonForDesired(desired config.Desired) string {
	if mode, ok := kernelDatapathRXStageModeFromEnv(); ok {
		if mode == "" {
			return "kernel datapath RX is disabled by TRUSTIX_KERNEL_DATAPATH_RX_STAGE"
		}
		if mode == kernelDatapathRXModeWorker && !kernelDatapathRXWorkerCrashRiskAllowed() {
			return "RX_WORKER requires TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER=1"
		}
	}
	requestedRXStage := config.NormalizeKernelDatapathRXStage(desired.KernelModules.Datapath.RXStage)
	if requestedRXStage == config.KernelDatapathRXStageDisabled {
		return "kernel datapath RX is disabled by config"
	}
	if kernelDatapathFullPlaintextRequestedByEnvOnlyForDesired(desired) && !kernelDatapathFullPlaintextCrashRiskAllowed() {
		return "full plaintext datapath requires TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT=1"
	}
	if kernelDatapathRXWorkerRequestedForDesired(desired) &&
		!kernelDatapathFullPlaintextEnabledForDesired(desired) &&
		!kernelDatapathRXWorkerCrashRiskAllowed() {
		return "RX_WORKER requires TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER=1"
	}
	return "kernel datapath RX_STAGE hook is disabled by default; set kernel_modules.datapath.rx_stage: stage or TRUSTIX_KERNEL_DATAPATH_RX_STAGE=1 to enable"
}

func kernelDatapathFullPlaintextRequestedForDesired(desired config.Desired) bool {
	runtime := config.EffectiveKernelDatapathRuntime(desired.KernelModules)
	if runtime.FullPlaintext || runtime.TXPlaintext {
		return true
	}
	return kernelDatapathFullPlaintextRequestedByEnv()
}

func kernelDatapathFullPlaintextRequestedByEnvOnlyForDesired(desired config.Desired) bool {
	runtime := config.EffectiveKernelDatapathRuntime(desired.KernelModules)
	if runtime.FullPlaintext || runtime.TXPlaintext {
		return false
	}
	return kernelDatapathFullPlaintextRequestedByEnv()
}

func kernelDatapathFullPlaintextRequestedByEnv() bool {
	return envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT",
		"TRUSTIX_KERNEL_DATAPATH_TX_PLAINTEXT",
	)
}

func kernelDatapathRXWorkerRequestedForDesired(desired config.Desired) bool {
	requestedRXStage := config.NormalizeKernelDatapathRXStage(desired.KernelModules.Datapath.RXStage)
	if requestedRXStage == config.KernelDatapathRXStageWorker || desired.KernelModules.Datapath.RXWorker {
		return true
	}
	if mode, ok := kernelDatapathRXStageModeFromEnv(); ok && mode == kernelDatapathRXModeWorker {
		return true
	}
	return kernelDatapathRXWorkerRequestedByEnv()
}

func kernelDatapathRXWorkerRequestedByEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER"))) {
	case "1", "true", "yes", "on", "worker":
		return true
	default:
		return false
	}
}

func kernelDatapathRXStageBatchSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE_BATCH"))
	if value == "" {
		return kernelDatapathRXStageDefaultBatch
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return kernelDatapathRXStageDefaultBatch
	}
	if parsed > kernelDatapathRXStageMaxBatch {
		return kernelDatapathRXStageMaxBatch
	}
	return parsed
}

func kernelDatapathRXStageIdleDelay() time.Duration {
	return kernelDatapathRXStageDurationEnv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE_IDLE_DELAY", kernelDatapathRXStageDefaultIdleDelay)
}

func kernelDatapathRXStageErrorDelay() time.Duration {
	return kernelDatapathRXStageDurationEnv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE_ERROR_DELAY", kernelDatapathRXStageDefaultErrorDelay)
}

func kernelDatapathRXStageDurationEnv(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	if parsed, err := time.ParseDuration(value); err == nil && parsed >= 0 {
		return parsed
	}
	if millis, err := strconv.Atoi(value); err == nil && millis >= 0 {
		return time.Duration(millis) * time.Millisecond
	}
	return fallback
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
