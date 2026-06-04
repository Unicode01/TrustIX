package daemon

import (
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
)

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
