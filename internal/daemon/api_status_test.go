package daemon

import (
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
)

func TestPublicDataPathStatusUsesTIXTCPNameAndKeepsLegacyStatusKey(t *testing.T) {
	experimental := &dataplane.ExperimentalTCPStatus{Available: true}
	status := dataPathStatus{
		Listeners:       []dataPathListenerStatus{{Endpoint: "local", Transport: "experimental_tcp"}},
		Sessions:        []dataPathSessionStatus{{Peer: "ix-b", Transport: "experimental-tcp"}},
		EndpointStats:   []dataPathEndpointStats{{Peer: "ix-b", Transport: "ackless_tcp"}},
		KernelTransport: &dataplane.KernelTransportStatus{Protocols: []dataplane.KernelTransportProtocol{{Protocol: "experimental_tcp"}}},
		ExperimentalTCP: experimental,
	}

	public := publicDataPathStatus(status)
	if public.Listeners[0].Transport != "tix_tcp" ||
		public.Sessions[0].Transport != "tix_tcp" ||
		public.EndpointStats[0].Transport != "tix_tcp" ||
		public.KernelTransport.Protocols[0].Protocol != "tix_tcp" {
		t.Fatalf("public data path = %#v", public)
	}
	if public.TIXTCP != experimental || public.ExperimentalTCP != experimental {
		t.Fatalf("TIX-TCP status aliases = %#v/%#v", public.TIXTCP, public.ExperimentalTCP)
	}
	if status.Listeners[0].Transport != "experimental_tcp" || status.KernelTransport.Protocols[0].Protocol != "experimental_tcp" {
		t.Fatalf("public conversion mutated runtime status = %#v", status)
	}
}

func TestTransportNamesPublishesAndDeduplicatesTIXTCP(t *testing.T) {
	got := transportNames([]transport.Protocol{transport.ProtocolUDP, transport.ProtocolExperimentalTCP, transport.ProtocolTIXTCP})
	if len(got) != 2 || got[0] != "tix_tcp" || got[1] != "udp" {
		t.Fatalf("transport names = %#v", got)
	}
}

func TestDomainIXStatusCountsT1WithoutDownstream(t *testing.T) {
	now := time.Now().UTC()
	daemon := &Daemon{
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
		},
		members: map[core.IXID]memberRecord{
			"ix-a": {LastSeen: now, Direct: true},
			"ix-b": {LastSeen: now, Direct: true},
			"ix-c": {LastSeen: now, Direct: false, Via: "ix-b"},
			"ix-d": {LastSeen: now.Add(-memberRecordTTL - time.Second), Direct: true},
		},
	}

	status := daemon.domainIXStatus(now, dataPathStatus{})
	if status.T1 != 2 || status.Local != 1 || status.Direct != 1 {
		t.Fatalf("T1 status = %#v, want local ix-a plus direct ix-b only", status)
	}
	if status.Active != 3 || status.Downstream != 1 || status.Stale != 1 {
		t.Fatalf("domain IX status = %#v, want active=3 downstream=1 stale=1", status)
	}
}

func TestDomainIXStatusCountsActiveStaticPeersAsT1(t *testing.T) {
	now := time.Now().UTC()
	daemon := &Daemon{
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Peers: []config.PeerConfig{
				{ID: "ix-b"},
				{ID: "ix-c"},
			},
		},
		members: map[core.IXID]memberRecord{},
	}

	status := daemon.domainIXStatus(now, dataPathStatus{
		Sessions: []dataPathSessionStatus{
			{Peer: "ix-b"},
		},
	})
	if status.T1 != 3 || status.Local != 1 || status.Direct != 2 {
		t.Fatalf("T1 status = %#v, want local plus two static direct peers", status)
	}
	if status.Active != 2 || status.Downstream != 0 || status.Stale != 0 {
		t.Fatalf("domain IX status = %#v, want local plus active ix-b only", status)
	}
}
