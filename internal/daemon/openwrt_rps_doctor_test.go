package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
)

func TestOpenWrtRPSUnderlayInterfacesCollectsConfiguredHints(t *testing.T) {
	desired := config.Desired{
		LAN: config.LANConfig{UnderlayIface: "eth1"},
		LANs: []config.LANConfig{
			{ID: "secondary", UnderlayIface: "eth2"},
			{ID: "duplicate", UnderlayIface: "eth1"},
		},
		Endpoints: []config.EndpointConfig{{LocalBind: config.EndpointLocalBindConfig{Iface: "eth3"}}},
		Peers: []config.PeerConfig{{Endpoints: []config.EndpointConfig{
			{LocalBind: config.EndpointLocalBindConfig{Iface: "eth2"}},
			{LocalBind: config.EndpointLocalBindConfig{Iface: "../invalid"}},
		}}},
	}
	got := openWrtRPSUnderlayInterfaces(desired)
	want := []string{"eth1", "eth2", "eth3"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("underlay interfaces = %v, want %v", got, want)
	}
}

func TestOpenWrtRPSDoctorWarnsForSharedNonzeroVirtioMask(t *testing.T) {
	check, ok := openWrtRPSDoctorCheckForStates([]openWrtRPSInterfaceState{{
		Name:         "eth1",
		Driver:       "virtio_net",
		RXQueueMasks: []string{"000000ff", "ff", "00000000,000000ff", "FF"},
	}})
	if !ok || check.Status != "warn" || check.Name != "openwrt_rps" {
		t.Fatalf("doctor check = %#v, want warning", check)
	}
	for _, want := range []string{"eth1", "mask ff", "packet_steering='0'"} {
		if !strings.Contains(check.Detail, want) {
			t.Fatalf("doctor detail %q does not contain %q", check.Detail, want)
		}
	}
}

func TestOpenWrtRPSDoctorAcceptsDisabledOrQueueSpecificRPS(t *testing.T) {
	for name, masks := range map[string][]string{
		"disabled":       {"0", "00000000", "0", "0"},
		"queue-specific": {"1", "2", "4", "8"},
	} {
		t.Run(name, func(t *testing.T) {
			check, ok := openWrtRPSDoctorCheckForStates([]openWrtRPSInterfaceState{{
				Name:         "eth1",
				Driver:       "virtio_net",
				RXQueueMasks: masks,
			}})
			if !ok || check.Status != "ok" {
				t.Fatalf("doctor check = %#v, want ok", check)
			}
		})
	}
}

func TestOpenWrtRPSDoctorSkipsNonVirtioAndSingleQueueInterfaces(t *testing.T) {
	for name, state := range map[string]openWrtRPSInterfaceState{
		"physical":     {Name: "eth1", Driver: "ixgbe", RXQueueMasks: []string{"ff", "ff"}},
		"single-queue": {Name: "eth1", Driver: "virtio_net", RXQueueMasks: []string{"ff"}},
	} {
		t.Run(name, func(t *testing.T) {
			if check, ok := openWrtRPSDoctorCheckForStates([]openWrtRPSInterfaceState{state}); ok {
				t.Fatalf("unexpected doctor check: %#v", check)
			}
		})
	}
}

func TestNormalizeRPSMaskRejectsMalformedValues(t *testing.T) {
	for _, raw := range []string{"", "0x1", "g", "1-2"} {
		if got, ok := normalizeRPSMask(raw); ok {
			t.Fatalf("normalizeRPSMask(%q) = %q, want invalid", raw, got)
		}
	}
}

func TestOpenWrtFullPlaintextRPSTuningDefaultsAndOptOut(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH", "1")
	desired := config.Desired{KernelModules: config.KernelModulesConfig{
		CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
	}}
	if !openWrtFullPlaintextRPSTuningEnabledForDesired(desired) {
		t.Fatal("OpenWrt full plaintext RPS tuning should default on")
	}
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_OPENWRT_RPS_TUNING", "0")
	if openWrtFullPlaintextRPSTuningEnabledForDesired(desired) {
		t.Fatal("OpenWrt RPS tuning opt-out was ignored")
	}
}

func TestApplyOpenWrtFullPlaintextRPSStatesRestoresSharedMask(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 4)
	for index := range paths {
		paths[index] = filepath.Join(dir, fmt.Sprintf("rx-%d-rps_cpus", index))
		if err := os.WriteFile(paths[index], []byte("04\n"), 0o644); err != nil {
			t.Fatalf("write RPS fixture: %v", err)
		}
	}
	daemon := &Daemon{}
	state := openWrtRPSInterfaceState{
		Name:         "eth1",
		Driver:       "virtio_net",
		RXQueuePaths: paths,
		RXQueueMasks: []string{"04", "04", "04", "04"},
	}
	if err := daemon.applyOpenWrtFullPlaintextRPSStates([]openWrtRPSInterfaceState{state}); err != nil {
		t.Fatalf("apply RPS tuning: %v", err)
	}
	for _, path := range paths {
		if got := readTrimmedTestFile(t, path); got != "0" {
			t.Fatalf("RPS mask %q = %q, want 0", path, got)
		}
	}
	if len(daemon.kernelRPSRestore) != len(paths) {
		t.Fatalf("RPS restore entries = %d, want %d", len(daemon.kernelRPSRestore), len(paths))
	}
	if err := daemon.restoreOpenWrtFullPlaintextRPS(); err != nil {
		t.Fatalf("restore RPS tuning: %v", err)
	}
	for _, path := range paths {
		if got := readTrimmedTestFile(t, path); got != "04" {
			t.Fatalf("restored RPS mask %q = %q, want 04", path, got)
		}
	}
	if len(daemon.kernelRPSRestore) != 0 {
		t.Fatalf("RPS restore map = %#v, want empty", daemon.kernelRPSRestore)
	}
}

func TestApplyOpenWrtFullPlaintextRPSStatesKeepsQueueSpecificMasks(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "rx-0-rps_cpus"), filepath.Join(dir, "rx-1-rps_cpus")}
	for index, path := range paths {
		if err := os.WriteFile(path, []byte(fmt.Sprintf("%d", index+1)), 0o644); err != nil {
			t.Fatalf("write RPS fixture: %v", err)
		}
	}
	daemon := &Daemon{}
	state := openWrtRPSInterfaceState{
		Name:         "eth1",
		Driver:       "virtio_net",
		RXQueuePaths: paths,
		RXQueueMasks: []string{"1", "2"},
	}
	if err := daemon.applyOpenWrtFullPlaintextRPSStates([]openWrtRPSInterfaceState{state}); err != nil {
		t.Fatalf("apply RPS tuning: %v", err)
	}
	for index, path := range paths {
		want := fmt.Sprintf("%d", index+1)
		if got := readTrimmedTestFile(t, path); got != want {
			t.Fatalf("RPS mask %q = %q, want %q", path, got, want)
		}
	}
	if len(daemon.kernelRPSRestore) != 0 {
		t.Fatalf("RPS restore map = %#v, want empty", daemon.kernelRPSRestore)
	}
}

func TestRestoreOpenWrtFullPlaintextRPSExceptKeepsActivePaths(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "active-rps_cpus")
	stale := filepath.Join(dir, "stale-rps_cpus")
	for _, path := range []string{active, stale} {
		if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
			t.Fatalf("write RPS fixture: %v", err)
		}
	}
	daemon := &Daemon{kernelRPSRestore: map[string]string{
		active: "04",
		stale:  "08",
	}}
	if err := daemon.restoreOpenWrtFullPlaintextRPSExcept(map[string]struct{}{active: {}}); err != nil {
		t.Fatalf("restore stale RPS tuning: %v", err)
	}
	if got := readTrimmedTestFile(t, active); got != "0" {
		t.Fatalf("active RPS mask = %q, want 0", got)
	}
	if got := readTrimmedTestFile(t, stale); got != "08" {
		t.Fatalf("stale RPS mask = %q, want 08", got)
	}
	if len(daemon.kernelRPSRestore) != 1 || daemon.kernelRPSRestore[active] != "04" {
		t.Fatalf("RPS restore map = %#v, want only active path", daemon.kernelRPSRestore)
	}
}

func TestRestoreOpenWrtFullPlaintextRPSDropsMissingPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-rps_cpus")
	daemon := &Daemon{kernelRPSRestore: map[string]string{path: "04"}}
	if err := daemon.restoreOpenWrtFullPlaintextRPS(); err != nil {
		t.Fatalf("restore missing RPS path: %v", err)
	}
	if len(daemon.kernelRPSRestore) != 0 {
		t.Fatalf("RPS restore map = %#v, want empty", daemon.kernelRPSRestore)
	}
}

func readTrimmedTestFile(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return strings.TrimSpace(string(payload))
}
