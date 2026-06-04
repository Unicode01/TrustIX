package daemon

import (
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/transport"
)

func TestTransportEndpointFromConfigCarriesLocalBind(t *testing.T) {
	endpoint := transportEndpointFromConfig(config.EndpointConfig{
		Name:      core.EndpointID("wan-tcp"),
		Mode:      config.EndpointModeActive,
		Address:   "203.0.113.10:7000",
		Transport: string(transport.ProtocolTCP),
		LocalBind: config.EndpointLocalBindConfig{
			SourceIP: "192.0.2.10",
			Iface:    "eth1",
		},
		Enabled: true,
	})
	if endpoint.LocalBind.SourceIP != "192.0.2.10" || endpoint.LocalBind.Iface != "eth1" {
		t.Fatalf("local bind = %#v", endpoint.LocalBind)
	}
}

func TestEndpointLocalBindSurfaceIsTrimmed(t *testing.T) {
	surface := endpointLocalBindSurface(config.EndpointLocalBindConfig{
		SourceIP: " 192.0.2.10 ",
		Iface:    " eth1 ",
	})
	if surface.SourceIP != "192.0.2.10" || surface.Iface != "eth1" {
		t.Fatalf("surface = %#v", surface)
	}
}
