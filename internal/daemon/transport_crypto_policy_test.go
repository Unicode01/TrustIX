package daemon

import (
	"testing"

	"trustix.local/trustix/internal/dataplane"
)

func TestEffectiveCryptoPlacementAutoPrefersKernelCryptoWhenBothPlacementsAvailable(t *testing.T) {
	placement, err := effectiveCryptoPlacement("kernel_udp", dataplane.CryptoPlacementAuto, cryptoPlacementStatus{
		UserspaceCrypto: true,
		KernelCrypto:    true,
		PreferredCrypto: dataplane.CryptoPlacementUserspace,
	})
	if err != nil {
		t.Fatalf("effective crypto placement: %v", err)
	}
	if placement != dataplane.CryptoPlacementKernel {
		t.Fatalf("auto crypto placement = %q, want kernel", placement)
	}
}
