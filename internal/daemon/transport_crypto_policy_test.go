package daemon

import (
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
)

func TestEffectiveTransportCryptoPlacementEmptyPolicyUsesProductionUserspaceDefault(t *testing.T) {
	if got := effectiveTransportCryptoPlacementConfig(config.TransportPolicyConfig{}); got != string(dataplane.CryptoPlacementUserspace) {
		t.Fatalf("empty policy crypto placement = %q, want userspace", got)
	}
}

func TestEffectiveTransportCryptoPlacementPreservesExplicitAuto(t *testing.T) {
	if got := effectiveTransportCryptoPlacementConfig(config.TransportPolicyConfig{CryptoPlacement: "auto"}); got != string(dataplane.CryptoPlacementAuto) {
		t.Fatalf("explicit auto crypto placement = %q, want auto", got)
	}
}

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
