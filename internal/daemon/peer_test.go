package daemon

import (
	"testing"
	"time"
)

func TestPeerPollIntervalDefaultAndEnv(t *testing.T) {
	t.Setenv("TRUSTIX_PEER_POLL_INTERVAL", "")
	if got := peerPollInterval(); got != defaultPeerPollInterval {
		t.Fatalf("default peer poll interval = %s, want %s", got, defaultPeerPollInterval)
	}
	t.Setenv("TRUSTIX_PEER_POLL_INTERVAL", "250ms")
	if got := peerPollInterval(); got != 250*time.Millisecond {
		t.Fatalf("env peer poll interval = %s, want 250ms", got)
	}
	t.Setenv("TRUSTIX_PEER_POLL_INTERVAL", "2.5")
	if got := peerPollInterval(); got != 2500*time.Millisecond {
		t.Fatalf("numeric peer poll interval = %s, want 2.5s", got)
	}
}
