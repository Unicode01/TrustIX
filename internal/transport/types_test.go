package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
)

func TestTIXTCPProtocolAliases(t *testing.T) {
	for _, alias := range []Protocol{ProtocolTIXTCP, ProtocolExperimentalTCP, "tix-tcp", "experimental-tcp", "ackless_tcp"} {
		if got := RuntimeProtocol(alias); got != ProtocolExperimentalTCP {
			t.Fatalf("RuntimeProtocol(%q) = %q, want %q", alias, got, ProtocolExperimentalTCP)
		}
		if got := PublicProtocol(alias); got != ProtocolTIXTCP {
			t.Fatalf("PublicProtocol(%q) = %q, want %q", alias, got, ProtocolTIXTCP)
		}
	}
}

func TestRegistryAcceptsTIXTCPPublicAlias(t *testing.T) {
	registry := NewRegistry()
	implementation := protocolOnlyTransport{name: ProtocolExperimentalTCP}
	if err := registry.Register(implementation); err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.Get(ProtocolTIXTCP); !ok || got.Name() != ProtocolExperimentalTCP {
		t.Fatalf("Get(%q) = %#v, %v", ProtocolTIXTCP, got, ok)
	}
}

type protocolOnlyTransport struct {
	name Protocol
}

func (transportImpl protocolOnlyTransport) Name() Protocol { return transportImpl.name }
func (protocolOnlyTransport) Probe(context.Context, Peer) ProbeResult {
	return ProbeResult{}
}
func (protocolOnlyTransport) Dial(context.Context, Peer, *tls.Config) (Session, error) {
	return nil, errors.New("not implemented")
}
func (protocolOnlyTransport) Listen(context.Context, Endpoint, *tls.Config) (Listener, error) {
	return nil, errors.New("not implemented")
}
