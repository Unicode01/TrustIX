package daemon

import (
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
)

func TestTransportCryptoPlacementDoesNotTakeConfigLock(t *testing.T) {
	daemon := &Daemon{}
	daemon.setTransportCryptoPlacement(config.TransportPolicyConfig{CryptoPlacement: "kernel"})
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()

	done := make(chan dataplane.CryptoPlacement, 1)
	go func() {
		done <- daemon.transportCryptoPlacement()
	}()

	select {
	case placement := <-done:
		if placement != dataplane.CryptoPlacementKernel {
			t.Fatalf("placement = %q, want kernel", placement)
		}
	case <-time.After(time.Second):
		t.Fatal("transportCryptoPlacement blocked on configMu")
	}
}
