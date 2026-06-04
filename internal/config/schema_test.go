package config

import (
	"strings"
	"testing"

	"trustix.local/trustix/internal/core"
)

func TestEndpointLocalBindValidation(t *testing.T) {
	cfg := Desired{
		Domain: DomainConfig{ID: core.DomainID("lab.local")},
		IX:     IXConfig{ID: core.IXID("ix-a")},
		Endpoints: []EndpointConfig{{
			Name:      core.EndpointID("wan-tcp"),
			Mode:      EndpointModePassive,
			Listen:    "127.0.0.1:7000",
			Transport: "tcp",
			LocalBind: EndpointLocalBindConfig{SourceIP: "192.0.2.10", Iface: "eth0"},
			Enabled:   true,
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate local bind: %v", err)
	}
	cfg.Endpoints[0].LocalBind.SourceIP = "not-an-ip"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected invalid local_bind source_ip error")
	}
	if !strings.Contains(err.Error(), "local_bind source_ip") {
		t.Fatalf("error = %v, want local_bind source_ip", err)
	}
}
