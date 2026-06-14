package daemon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
)

func TestKernelDatapathRXStagePollerInjectsStagedPackets(t *testing.T) {
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE_BATCH", "2")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE_IDLE_DELAY", "5ms")
	packetA := udpIPv4Packet([]byte("rx-stage-a"))
	packetB := udpIPv4Packet([]byte("rx-stage-b"))
	driver := &fakeKernelRXStageDriver{packets: [][]byte{packetA, packetB}}
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		return driver, nil
	}
	injector := &recordingInjector{}
	daemon := &Daemon{
		dataplane: &recordingDataplane{
			NoopManager:       dataplane.NewNoopManager(),
			recordingInjector: injector,
		},
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
		desired: config.Desired{
			LAN: config.LANConfig{Gateway: "10.0.1.1/24"},
			KernelModules: config.KernelModulesConfig{
				Datapath: config.KernelDatapathRuntimeConfig{
					RXStage: config.KernelDatapathRXStageStage,
				},
			},
		},
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := daemon.startKernelDatapathRXStage(ctx, dataplane.AttachSpec{UnderlayIface: "eth0", LANIface: "br-lan"}); err != nil {
		t.Fatalf("start RX stage: %v", err)
	}
	waitForCondition(t, time.Second, func() bool {
		driver.mu.Lock()
		defer driver.mu.Unlock()
		return driver.pops >= 2 && len(injector.batchPackets) > 0
	})
	daemon.stopKernelDatapathRXStage()
	if !driver.attachSeen || driver.attached || driver.ifname != "eth0" || driver.targetIfname != "" {
		t.Fatalf("attach seen=%t attached=%t ifname=%q target=%q, want attach on eth0 followed by detach", driver.attachSeen, driver.attached, driver.ifname, driver.targetIfname)
	}
	if driver.detaches != 1 || driver.clears < 2 || driver.closes != 1 {
		t.Fatalf("cleanup detaches=%d clears=%d closes=%d, want 1 >=2 1", driver.detaches, driver.clears, driver.closes)
	}
	if len(injector.batchPackets) == 0 || len(injector.batchPackets[0]) != 2 {
		t.Fatalf("injected batches = %#v, want one 2-packet batch", injector.batchPackets)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if status.Active {
		t.Fatal("RX stage should be inactive after stop")
	}
	if status.Packets != 2 || status.Batches != 1 {
		t.Fatalf("status packets=%d batches=%d, want 2/1", status.Packets, status.Batches)
	}
	if daemon.dataStats.kernelRXStagePackets.Load() != 2 || daemon.dataStats.kernelRXStageBatches.Load() != 1 {
		t.Fatalf("counters packets=%d batches=%d, want 2/1", daemon.dataStats.kernelRXStagePackets.Load(), daemon.dataStats.kernelRXStageBatches.Load())
	}
}

func TestKernelDatapathRXWorkerAttachesTargetLANWithoutPoller(t *testing.T) {
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	driver := &fakeKernelRXStageDriver{workerInjected: 3}
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		return driver, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	spec := dataplane.AttachSpec{
		UnderlayIface: "eth0",
		LANIface:      "br-lan",
		LANs: []dataplane.LANAttachSpec{{
			Iface:         "br-lan",
			UnderlayIface: "eth0",
		}},
	}
	if err := daemon.startKernelDatapathRXStage(context.Background(), spec); err != nil {
		t.Fatalf("start RX worker: %v", err)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if !status.Active || status.Mode != kernelDatapathRXModeWorker || status.IfName != "eth0" || status.TargetIfName != "br-lan" {
		t.Fatalf("worker status = %#v", status)
	}
	if status.Polls != 0 || status.Batches != 0 || status.RXWorkerInjected != 3 {
		t.Fatalf("worker counters = %#v, want no poller and injected counter", status)
	}
	if status.Flags != kernelDatapathRXWorkerHookFlags() {
		t.Fatalf("worker hook flags = %#x, want %#x", status.Flags, kernelDatapathRXWorkerHookFlags())
	}
	daemon.stopKernelDatapathRXStage()
	if !driver.attachSeen || driver.detaches != 1 || driver.pops != 0 || driver.targetIfname != "br-lan" {
		t.Fatalf("driver after worker stop = %#v", driver)
	}
}

func TestKernelDatapathRXWorkerEnvOverridesStageCompatibilityFlag(t *testing.T) {
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	driver := &fakeKernelRXStageDriver{workerInjected: 5}
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		return driver, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	spec := dataplane.AttachSpec{
		UnderlayIface: "eth0",
		LANIface:      "br-lan",
		LANs: []dataplane.LANAttachSpec{{
			Iface:         "br-lan",
			UnderlayIface: "eth0",
		}},
	}
	if err := daemon.startKernelDatapathRXStage(context.Background(), spec); err != nil {
		t.Fatalf("start RX worker: %v", err)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if !status.Active || status.Mode != kernelDatapathRXModeWorker || status.IfName != "eth0" || status.TargetIfName != "br-lan" {
		t.Fatalf("worker status = %#v", status)
	}
	if status.BatchSize != 0 || status.Polls != 0 || status.RXWorkerInjected != 5 {
		t.Fatalf("worker counters = %#v, want worker without poller", status)
	}
	if status.Flags != kernelDatapathRXWorkerHookFlags() {
		t.Fatalf("worker hook flags = %#x, want %#x", status.Flags, kernelDatapathRXWorkerHookFlags())
	}
	daemon.stopKernelDatapathRXStage()
}

func TestKernelDatapathRXWorkerEnvWithStageCompatibilityRequiresCrashRiskGate(t *testing.T) {
	opened := false
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		opened = true
		return &fakeKernelRXStageDriver{}, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	if err := daemon.startKernelDatapathRXStage(context.Background(), dataplane.AttachSpec{UnderlayIface: "eth0", LANIface: "br-lan"}); err != nil {
		t.Fatalf("start RX worker: %v", err)
	}
	if opened {
		t.Fatal("driver should not open when RX_WORKER lacks the crash-risk gate")
	}
	status := daemon.kernelDatapathRXStageStatus()
	if status.Active || status.Enabled || !strings.Contains(status.DisabledReason, "RX_WORKER requires") {
		t.Fatalf("status = %#v, want RX_WORKER crash-risk disabled reason", status)
	}
}

func TestKernelDatapathFullPlaintextAttachesRXAndTXHooks(t *testing.T) {
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	driver := &fakeKernelRXStageDriver{}
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		return driver, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	spec := dataplane.AttachSpec{UnderlayIface: "eth0", LANIface: "br-lan"}
	if err := daemon.startKernelDatapathRXStage(context.Background(), spec); err != nil {
		t.Fatalf("start full plaintext: %v", err)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if !status.Active || status.Mode != kernelDatapathRXModeWorker || status.IfName != "eth0" || status.TargetIfName != "br-lan" {
		t.Fatalf("full plaintext status = %#v", status)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.attachAttempts != 2 || driver.ifname != "br-lan" || driver.targetIfname != "eth0" || driver.flags != kernelDatapathTXPlaintextHookFlags() {
		t.Fatalf("driver attach attempts=%d ifname=%q target=%q flags=%#x", driver.attachAttempts, driver.ifname, driver.targetIfname, driver.flags)
	}
}

func TestKernelDatapathFullPlaintextOverridesStageCompatibilityFlag(t *testing.T) {
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	driver := &fakeKernelRXStageDriver{}
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		return driver, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	spec := dataplane.AttachSpec{UnderlayIface: "eth0", LANIface: "br-lan"}
	if err := daemon.startKernelDatapathRXStage(context.Background(), spec); err != nil {
		t.Fatalf("start full plaintext: %v", err)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if !status.Active || status.Mode != kernelDatapathRXModeWorker || status.IfName != "eth0" || status.TargetIfName != "br-lan" {
		t.Fatalf("full plaintext status = %#v", status)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.attachAttempts != 2 || driver.ifname != "br-lan" || driver.targetIfname != "eth0" || driver.flags != kernelDatapathTXPlaintextHookFlags() {
		t.Fatalf("driver attach attempts=%d ifname=%q target=%q flags=%#x", driver.attachAttempts, driver.ifname, driver.targetIfname, driver.flags)
	}
}

func TestKernelDatapathFullPlaintextProfileAllowsExperimentalTCPAndAttachesTXHook(t *testing.T) {
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	driver := &fakeKernelRXStageDriver{}
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		return driver, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
		desired: config.Desired{
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
		},
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	spec := dataplane.AttachSpec{
		UnderlayIface:           "eth0",
		LANIface:                "br-lan",
		ExperimentalTCPTXDirect: true,
	}
	if err := daemon.startKernelDatapathRXStage(context.Background(), spec); err != nil {
		t.Fatalf("start full plaintext profile: %v", err)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if !status.Active || status.Mode != kernelDatapathRXModeWorker || status.IfName != "eth0" || status.TargetIfName != "br-lan" {
		t.Fatalf("full plaintext profile status = %#v", status)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.attachAttempts != 2 || driver.ifname != "br-lan" || driver.targetIfname != "eth0" || driver.flags != kernelDatapathTXPlaintextHookFlags() {
		t.Fatalf("driver attach attempts=%d ifname=%q target=%q flags=%#x", driver.attachAttempts, driver.ifname, driver.targetIfname, driver.flags)
	}
}

func TestKernelDatapathRXWorkerSkipsExperimentalTCPTXDirectByDefault(t *testing.T) {
	opened := false
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		opened = true
		return &fakeKernelRXStageDriver{}, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	spec := dataplane.AttachSpec{
		UnderlayIface:           "eth0",
		LANIface:                "br-lan",
		ExperimentalTCPTXDirect: true,
	}
	if err := daemon.startKernelDatapathRXStage(context.Background(), spec); err != nil {
		t.Fatalf("start RX worker: %v", err)
	}
	if opened {
		t.Fatal("driver should not open when RX worker is disabled for experimental TCP")
	}
	status := daemon.kernelDatapathRXStageStatus()
	if status.Active || !status.Enabled || status.Mode != kernelDatapathRXModeWorker ||
		!strings.Contains(status.InactiveReason, "experimental_tcp TC direct") {
		t.Fatalf("status = %#v, want inactive worker with experimental TCP reason", status)
	}
}

func TestKernelDatapathRXWorkerEnvKeptForFullPlaintext(t *testing.T) {
	opened := false
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		opened = true
		return &fakeKernelRXStageDriver{}, nil
	}
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
	}
	if mode := kernelDatapathRXModeForDesired(desired); mode != kernelDatapathRXModeWorker {
		t.Fatalf("full plaintext should keep RX worker mode, got %q", mode)
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
		desired:        desired,
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	if err := daemon.startKernelDatapathRXStage(context.Background(), dataplane.AttachSpec{
		UnderlayIface: "eth0",
		LANIface:      "br-lan",
	}); err != nil {
		t.Fatalf("start RX worker: %v", err)
	}
	if !opened {
		t.Fatal("driver should open for full plaintext RX worker")
	}
	status := daemon.kernelDatapathRXStageStatus()
	if !status.Active || !status.Enabled || status.Mode != kernelDatapathRXModeWorker {
		t.Fatalf("status = %#v, want active RX worker", status)
	}
}

func TestKernelDatapathRXWorkerAllowsExperimentalTCPTXDirectWithOverride(t *testing.T) {
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP", "1")
	driver := &fakeKernelRXStageDriver{}
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		return driver, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	spec := dataplane.AttachSpec{
		UnderlayIface:           "eth0",
		LANIface:                "br-lan",
		ExperimentalTCPTXDirect: true,
	}
	if err := daemon.startKernelDatapathRXStage(context.Background(), spec); err != nil {
		t.Fatalf("start RX worker: %v", err)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if !status.Active || status.Mode != kernelDatapathRXModeWorker ||
		status.IfName != "eth0" || status.TargetIfName != "br-lan" {
		t.Fatalf("status = %#v, want active overridden worker", status)
	}
	daemon.stopKernelDatapathRXStage()
	if !driver.attachSeen || driver.detaches != 1 {
		t.Fatalf("driver after overridden worker stop = %#v", driver)
	}
}

func TestKernelDatapathRXWorkerAdoptsExistingHookAfterDaemonCrash(t *testing.T) {
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	driver := &fakeKernelRXStageDriver{
		ifname:         "eth0",
		targetIfname:   "br-lan",
		flags:          kernelDatapathRXWorkerHookFlags(),
		attached:       true,
		attachErr:      syscall.EALREADY,
		workerInjected: 7,
	}
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		return driver, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	spec := dataplane.AttachSpec{UnderlayIface: "eth0", LANIface: "br-lan"}
	if err := daemon.startKernelDatapathRXStage(context.Background(), spec); err != nil {
		t.Fatalf("start RX worker with existing hook: %v", err)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if !status.Active || status.Mode != kernelDatapathRXModeWorker || status.IfName != "eth0" || status.TargetIfName != "br-lan" {
		t.Fatalf("adopted worker status = %#v", status)
	}
	if status.RXWorkerInjected != 7 || driver.attachAttempts != 1 || driver.detaches != 0 || driver.clears != 1 {
		t.Fatalf("adopt counters status=%#v driver=%#v", status, driver)
	}
	daemon.stopKernelDatapathRXStage()
	if driver.detaches != 1 || driver.closes != 1 {
		t.Fatalf("driver cleanup after adopted hook = %#v", driver)
	}
}

func TestKernelDatapathRXWorkerReattachesMismatchedExistingHook(t *testing.T) {
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	driver := &fakeKernelRXStageDriver{
		ifname:       "old0",
		targetIfname: "old-br",
		flags:        kernelDatapathRXWorkerHookFlags(),
		attached:     true,
		attachErr:    syscall.EALREADY,
	}
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		return driver, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	spec := dataplane.AttachSpec{UnderlayIface: "eth0", LANIface: "br-lan"}
	if err := daemon.startKernelDatapathRXStage(context.Background(), spec); err != nil {
		t.Fatalf("start RX worker with mismatched existing hook: %v", err)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if !status.Active || status.IfName != "eth0" || status.TargetIfName != "br-lan" {
		t.Fatalf("reattached worker status = %#v", status)
	}
	if driver.attachAttempts != 2 || driver.detaches != 1 {
		t.Fatalf("reattach counters = %#v, want two attach attempts and one detach before cleanup", driver)
	}
	daemon.stopKernelDatapathRXStage()
	if driver.detaches != 2 || driver.closes != 1 {
		t.Fatalf("driver cleanup after reattach = %#v", driver)
	}
}

func TestKernelDatapathRXStageSkipsWithoutLoadedModule(t *testing.T) {
	opened := false
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		opened = true
		return &fakeKernelRXStageDriver{}, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
		desired: config.Desired{
			KernelModules: config.KernelModulesConfig{
				Datapath: config.KernelDatapathRuntimeConfig{
					RXStage: config.KernelDatapathRXStageStage,
				},
			},
		},
	}
	if err := daemon.startKernelDatapathRXStage(context.Background(), dataplane.AttachSpec{UnderlayIface: "eth0"}); err != nil {
		t.Fatalf("start RX stage: %v", err)
	}
	if opened {
		t.Fatal("driver should not open when module is not loaded")
	}
	status := daemon.kernelDatapathRXStageStatus()
	if status.Active || !status.Enabled || status.InactiveReason == "" {
		t.Fatalf("status = %#v, want enabled inactive with reason", status)
	}
}

func TestKernelDatapathRXStageDefaultOffEvenWhenModuleIsLoaded(t *testing.T) {
	opened := false
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		opened = true
		return &fakeKernelRXStageDriver{}, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	if err := daemon.startKernelDatapathRXStage(context.Background(), dataplane.AttachSpec{UnderlayIface: "eth0"}); err != nil {
		t.Fatalf("start RX stage: %v", err)
	}
	if opened {
		t.Fatal("driver should not open when RX_STAGE was not explicitly requested")
	}
	status := daemon.kernelDatapathRXStageStatus()
	if status.Active || status.Enabled || !strings.Contains(status.DisabledReason, "disabled by default") {
		t.Fatalf("status = %#v, want default-off disabled reason", status)
	}
}

func TestKernelDatapathRXWorkerRequiresCrashRiskGate(t *testing.T) {
	opened := false
	oldOpen := kernelDatapathRXStageOpenDriver
	t.Cleanup(func() { kernelDatapathRXStageOpenDriver = oldOpen })
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	kernelDatapathRXStageOpenDriver = func() (kernelDatapathRXStageDriver, error) {
		opened = true
		return &fakeKernelRXStageDriver{}, nil
	}
	daemon := &Daemon{
		dataplane:      dataplane.NewNoopManager(),
		kernelDatapath: kernelmodule.NewTrustIXDatapathManager(),
	}
	daemon.kernelDatapath.SetStatusForTest(kernelmodule.Status{
		Name:   "trustix_datapath",
		Mode:   kernelmodule.ModeAuto,
		Loaded: true,
		State:  "loaded",
	})
	if err := daemon.startKernelDatapathRXStage(context.Background(), dataplane.AttachSpec{UnderlayIface: "eth0", LANIface: "br-lan"}); err != nil {
		t.Fatalf("start RX worker: %v", err)
	}
	if opened {
		t.Fatal("driver should not open when RX_WORKER lacks the crash-risk gate")
	}
	status := daemon.kernelDatapathRXStageStatus()
	if status.Active || status.Enabled || !strings.Contains(status.DisabledReason, "RX_WORKER requires") {
		t.Fatalf("status = %#v, want RX_WORKER crash-risk disabled reason", status)
	}
}

func TestKernelDatapathRXStageDisabledByEnv(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_STAGE", "0")
	daemon := &Daemon{dataplane: dataplane.NewNoopManager()}
	if err := daemon.startKernelDatapathRXStage(context.Background(), dataplane.AttachSpec{UnderlayIface: "eth0"}); err != nil {
		t.Fatalf("start RX stage: %v", err)
	}
	status := daemon.kernelDatapathRXStageStatus()
	if status.Enabled || status.DisabledReason == "" {
		t.Fatalf("status = %#v, want disabled", status)
	}
}

type fakeKernelRXStageDriver struct {
	mu             sync.Mutex
	ifname         string
	targetIfname   string
	flags          uint32
	attached       bool
	attachSeen     bool
	packets        [][]byte
	pops           int
	detaches       int
	clears         int
	closes         int
	attachAttempts int
	attachErr      error
	workerInjected uint64
	hooks          map[string]kernelDatapathRXStageHookStatus
}

func (driver *fakeKernelRXStageDriver) Attach(ifname, targetIfname string, flags uint32) (kernelDatapathRXStageHookStatus, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.attachAttempts++
	if driver.attachErr != nil {
		err := driver.attachErr
		driver.attachErr = nil
		driver.attachSeen = true
		return driver.hookStatusLocked(driver.flags), err
	}
	if driver.hooks == nil {
		driver.hooks = make(map[string]kernelDatapathRXStageHookStatus)
	}
	driver.ifname = ifname
	driver.targetIfname = targetIfname
	driver.flags = flags
	driver.attached = true
	driver.attachSeen = true
	status := driver.hookStatusLocked(flags)
	driver.hooks[ifname] = status
	return status, nil
}

func (driver *fakeKernelRXStageDriver) Detach() error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.detaches++
	driver.attached = false
	driver.hooks = nil
	return nil
}

func (driver *fakeKernelRXStageDriver) DetachFor(ifname string) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.detaches++
	if ifname == "" {
		driver.attached = false
		driver.hooks = nil
		return nil
	}
	if driver.hooks != nil {
		delete(driver.hooks, ifname)
		driver.attached = len(driver.hooks) > 0
		return nil
	}
	if driver.ifname == ifname {
		driver.attached = false
	}
	return nil
}

func (driver *fakeKernelRXStageDriver) Clear() (kernelDatapathRXStageResult, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.clears++
	return driver.statusLocked(), nil
}

func (driver *fakeKernelRXStageDriver) HookQuery() (kernelDatapathRXStageHookStatus, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	for _, hook := range driver.hooks {
		return hook, nil
	}
	return driver.hookStatusLocked(driver.flags), nil
}

func (driver *fakeKernelRXStageDriver) HookQueryFor(ifname string) (kernelDatapathRXStageHookStatus, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.hooks != nil {
		if hook, ok := driver.hooks[ifname]; ok {
			return hook, nil
		}
		return kernelDatapathRXStageHookStatus{}, syscall.ENOENT
	}
	if driver.attached && driver.ifname == ifname {
		return driver.hookStatusLocked(driver.flags), nil
	}
	return kernelDatapathRXStageHookStatus{}, syscall.ENOENT
}

func (driver *fakeKernelRXStageDriver) PopInto(out []byte) (kernelDatapathRXStageResult, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.pops >= len(driver.packets) {
		return driver.statusLocked(), errKernelDatapathRXStageEmpty
	}
	packet := driver.packets[driver.pops]
	if len(out) < len(packet) {
		return driver.statusLocked(), errors.New("small output")
	}
	copy(out, packet)
	driver.pops++
	status := driver.statusLocked()
	status.WrittenLen = uint32(len(packet))
	return status, nil
}

func (driver *fakeKernelRXStageDriver) Query() (kernelDatapathRXStageResult, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return driver.statusLocked(), nil
}

func (driver *fakeKernelRXStageDriver) Close() error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.closes++
	return nil
}

func (driver *fakeKernelRXStageDriver) statusLocked() kernelDatapathRXStageResult {
	return kernelDatapathRXStageResult{
		QueueLen: uint32(len(driver.packets) - driver.pops),
		Capacity: uint32(len(driver.packets)),
		Staged:   uint64(len(driver.packets)),
		Popped:   uint64(driver.pops),
	}
}

func (driver *fakeKernelRXStageDriver) hookStatusLocked(flags uint32) kernelDatapathRXStageHookStatus {
	status := kernelDatapathRXStageHookStatus{
		Attached:         driver.attached,
		Flags:            flags,
		IfName:           driver.ifname,
		IfIndex:          7,
		TargetIfName:     driver.targetIfname,
		RXWorkerInjected: driver.workerInjected,
	}
	if driver.targetIfname != "" {
		status.TargetIfIndex = 9
	}
	return status
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
