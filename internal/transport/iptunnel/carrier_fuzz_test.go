package iptunnel

import "testing"

func FuzzParseTunnelConfigRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"local=198.18.0.1,remote=198.18.0.2,local_carrier=100.64.0.1/30,remote_carrier=100.64.0.2",
		"vxlan://local=198.18.0.1,remote=198.18.0.2,local_carrier=100.64.0.1/30,remote_carrier=100.64.0.2,vni=5527625,queues=4",
		"",
		"local=invalid",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		cfg, err := parseTunnelConfig(raw)
		if err != nil {
			return
		}
		normalized := normalizeTunnelConfigFields(cfg)
		roundTrip, err := parseTunnelConfig(normalized)
		if err != nil {
			t.Fatalf("parse normalized config %q: %v", normalized, err)
		}
		if got := normalizeTunnelConfigFields(roundTrip); got != normalized {
			t.Fatalf("normalized round trip = %q, want %q", got, normalized)
		}
	})
}
