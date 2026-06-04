package daemon

import (
	"testing"
	"time"

	"trustix.local/trustix/internal/transport"
)

func TestEndpointSupportsPassiveProbeIncludesNativeTunnels(t *testing.T) {
	for _, protocol := range []transport.Protocol{
		transport.ProtocolQUIC,
		transport.ProtocolUDP,
		transport.ProtocolGRE,
		transport.ProtocolIPIP,
		transport.ProtocolVXLAN,
	} {
		if !endpointSupportsPassiveProbe(protocol) {
			t.Fatalf("%s should support passive endpoint probe", protocol)
		}
	}
}

func TestEndpointProbeIntervalTimeoutAndTTLDefaultsAndEnv(t *testing.T) {
	t.Setenv("TRUSTIX_ENDPOINT_PROBE_INTERVAL", "")
	t.Setenv("TRUSTIX_ENDPOINT_PROBE_TIMEOUT", "")
	t.Setenv("TRUSTIX_ENDPOINT_HEALTH_TTL", "")
	if got := endpointProbeInterval(); got != defaultEndpointProbeInterval {
		t.Fatalf("default endpoint probe interval = %s, want %s", got, defaultEndpointProbeInterval)
	}
	if got := endpointProbeTimeout(); got != defaultEndpointProbeTimeout {
		t.Fatalf("default endpoint probe timeout = %s, want %s", got, defaultEndpointProbeTimeout)
	}
	if got := endpointHealthTTL(); got != defaultEndpointHealthTTL {
		t.Fatalf("default endpoint health ttl = %s, want %s", got, defaultEndpointHealthTTL)
	}

	t.Setenv("TRUSTIX_ENDPOINT_PROBE_INTERVAL", "2.5")
	t.Setenv("TRUSTIX_ENDPOINT_PROBE_TIMEOUT", "750ms")
	t.Setenv("TRUSTIX_ENDPOINT_HEALTH_TTL", "20s")
	if got := endpointProbeInterval(); got != 2500*time.Millisecond {
		t.Fatalf("numeric endpoint probe interval = %s, want 2.5s", got)
	}
	if got := endpointProbeTimeout(); got != 750*time.Millisecond {
		t.Fatalf("duration endpoint probe timeout = %s, want 750ms", got)
	}
	if got := endpointHealthTTL(); got != 20*time.Second {
		t.Fatalf("duration endpoint health ttl = %s, want 20s", got)
	}
}

func TestEndpointHealthTTLDoesNotExpireBeforeThreeProbeIntervals(t *testing.T) {
	t.Setenv("TRUSTIX_ENDPOINT_PROBE_INTERVAL", "30s")
	t.Setenv("TRUSTIX_ENDPOINT_HEALTH_TTL", "10s")
	if got := endpointHealthTTL(); got != 90*time.Second {
		t.Fatalf("short endpoint health ttl = %s, want 90s", got)
	}
}
