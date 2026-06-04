package kernelmodule

import (
	"context"
	"testing"

	"trustix.local/trustix/internal/config"
)

func TestNormalizeMode(t *testing.T) {
	for raw, want := range map[string]string{
		"":         ModeDisabled,
		"disabled": ModeDisabled,
		" AUTO ":   ModeAuto,
		"required": ModeRequired,
		"force":    ModeDisabled,
	} {
		if got := normalizeMode(raw); got != want {
			t.Fatalf("normalizeMode(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestEnsureDisabledDoesNotRequireLinuxCapability(t *testing.T) {
	manager := NewTrustIXCryptoManager()
	status, err := manager.Ensure(context.Background(), config.KernelModuleConfig{Mode: "disabled"})
	if err != nil {
		t.Fatalf("ensure disabled: %v", err)
	}
	if status.Name != "trustix_crypto" || status.Mode != ModeDisabled || status.State != ModeDisabled {
		t.Fatalf("disabled status = %#v", status)
	}
	if status.CapabilityTier != CapabilityTierUnavailable {
		t.Fatalf("disabled capability tier = %q, want %q", status.CapabilityTier, CapabilityTierUnavailable)
	}
}

func TestEnsureUnknownModuleNameDoesNotFallBackToCrypto(t *testing.T) {
	manager := NewManager("trustix_kernel")
	status, err := manager.Ensure(context.Background(), config.KernelModuleConfig{Mode: "auto", Path: "embedded"})
	if err != nil {
		t.Fatalf("ensure unknown auto: %v", err)
	}
	if status.Name != "trustix_kernel" || status.State != "unsupported" {
		t.Fatalf("unknown module status = %#v", status)
	}
	if status.Path != "embedded" {
		t.Fatalf("unknown module path = %q, want embedded", status.Path)
	}
	if status.CapabilityTier != CapabilityTierUnavailable {
		t.Fatalf("unknown module tier = %q, want %q", status.CapabilityTier, CapabilityTierUnavailable)
	}

	_, err = manager.Ensure(context.Background(), config.KernelModuleConfig{Mode: "required", Path: "embedded"})
	if err == nil {
		t.Fatal("expected required unknown module to fail")
	}
}

func TestCompleteCapabilityStatusDerivesCryptoOnlyTier(t *testing.T) {
	status := completeCapabilityStatus(Status{
		Name:     "trustix_crypto",
		Loaded:   true,
		Features: []string{FeatureKfuncTC, FeatureCryptoAEAD, FeatureKfuncTC, FeatureDeviceAEAD},
	})
	if status.CapabilityTier != CapabilityTierCryptoOnly {
		t.Fatalf("tier = %q, want %q", status.CapabilityTier, CapabilityTierCryptoOnly)
	}
	if !status.HasFeature(FeatureCryptoAEAD) || !status.HasFeature(FeatureDeviceAEAD) || !status.HasFeature(FeatureKfuncTC) {
		t.Fatalf("features were not preserved: %#v", status.Features)
	}
	if len(status.Features) != 3 {
		t.Fatalf("features were not deduplicated: %#v", status.Features)
	}
	if len(status.MissingFeatures) != 0 {
		t.Fatalf("crypto-only status should not claim missing datapath features: %#v", status.MissingFeatures)
	}
}

func TestCompleteCapabilityStatusKeepsCryptoModuleOutOfDatapathTiers(t *testing.T) {
	status := completeCapabilityStatus(Status{
		Name:     "trustix_crypto",
		Loaded:   true,
		Features: []string{FeatureCryptoAEAD, FeatureGSOSKB, FeatureFullDatapath},
	})
	if status.CapabilityTier != CapabilityTierCryptoOnly {
		t.Fatalf("tier = %q, want %q", status.CapabilityTier, CapabilityTierCryptoOnly)
	}
}

func TestCompleteCapabilityStatusPromotesDatapathTiers(t *testing.T) {
	gso := completeCapabilityStatus(Status{Name: "trustix_datapath_helpers", Loaded: true, Features: []string{FeatureGSOSKB}})
	if gso.CapabilityTier != CapabilityTierGSOSKB {
		t.Fatalf("GSO tier = %q, want %q", gso.CapabilityTier, CapabilityTierGSOSKB)
	}
	full := completeCapabilityStatus(Status{Name: "trustix_datapath", Loaded: true, Features: []string{FeatureFullDatapath}})
	if full.CapabilityTier != CapabilityTierFullDatapath || len(full.MissingFeatures) != 0 {
		t.Fatalf("full tier status = %#v", full)
	}
	invalidHelper := completeCapabilityStatus(Status{Name: "trustix_datapath_helpers", Loaded: true, Features: []string{FeatureGSOSKB, FeatureFullDatapath}})
	if invalidHelper.CapabilityTier != CapabilityTierUnavailable {
		t.Fatalf("helper full datapath status = %#v, want unavailable", invalidHelper)
	}
}

func TestCompleteCapabilityStatusRejectsUnknownModuleCapabilities(t *testing.T) {
	status := completeCapabilityStatus(Status{
		Name:     "trustix_other",
		Loaded:   true,
		Features: []string{FeatureCryptoAEAD, FeatureGSOSKB, FeatureFullDatapath},
	})
	if status.CapabilityTier != CapabilityTierUnavailable {
		t.Fatalf("unknown module tier = %q, want %q", status.CapabilityTier, CapabilityTierUnavailable)
	}
	if status.CapabilityReason != "unknown TrustIX kernel module; no first-release capability contract applies" {
		t.Fatalf("unknown module reason = %q", status.CapabilityReason)
	}
}
