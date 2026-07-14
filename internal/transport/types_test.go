package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
)

func TestNormalizeProtocolCanonicalizesTIXTCP(t *testing.T) {
	for _, value := range []Protocol{ProtocolTIXTCP, "tix-tcp", " TIX_TCP "} {
		if got := NormalizeProtocol(value); got != ProtocolTIXTCP {
			t.Fatalf("NormalizeProtocol(%q) = %q, want %q", value, got, ProtocolTIXTCP)
		}
	}
}

func TestRegistryUsesOnlyTIXTCPIdentity(t *testing.T) {
	registry := NewRegistry()
	implementation := protocolOnlyTransport{name: ProtocolTIXTCP}
	if err := registry.Register(implementation); err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.Get(ProtocolTIXTCP); !ok || got.Name() != ProtocolTIXTCP {
		t.Fatalf("Get(%q) = %#v, %v", ProtocolTIXTCP, got, ok)
	}
	legacy := []Protocol{
		Protocol("experimental" + "_tcp"),
		Protocol("experimental" + "-tcp"),
		Protocol("ackless" + "_tcp"),
	}
	for _, value := range legacy {
		if _, ok := registry.Get(value); ok {
			t.Fatalf("legacy transport %q unexpectedly resolved", value)
		}
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
