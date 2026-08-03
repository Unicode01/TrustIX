package daemon

import (
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
