//go:build linux

package kernelmodule

import "testing"

func TestModuleFeatureMaskIncludesRouteTCPKfunc(t *testing.T) {
	features := moduleFeatureMaskToNames(trustIXKernelFeatureCryptoAEADBit | trustIXKernelFeatureGSOSKBBit | trustIXKernelFeatureRouteTCPKfuncBit | trustIXKernelFeatureRouteTCPXmitBit)
	status := completeCapabilityStatus(Status{Name: "trustix_datapath_helpers", Loaded: true, Features: features})
	if !status.HasFeature(FeatureRouteTCPKfunc) {
		t.Fatalf("features = %#v, missing %q", status.Features, FeatureRouteTCPKfunc)
	}
	if !status.HasFeature(FeatureRouteTCPXmit) {
		t.Fatalf("features = %#v, missing %q", status.Features, FeatureRouteTCPXmit)
	}
	if status.CapabilityTier != CapabilityTierGSOSKB {
		t.Fatalf("tier = %q, want %q", status.CapabilityTier, CapabilityTierGSOSKB)
	}
}

func TestModuleFeatureMaskCannotPromoteCryptoModuleToDatapathTier(t *testing.T) {
	features := moduleFeatureMaskToNames(trustIXKernelFeatureCryptoAEADBit | trustIXKernelFeatureGSOSKBBit | trustIXKernelFeatureFullDatapathBit)
	status := completeCapabilityStatus(Status{Name: "trustix_crypto", Loaded: true, Features: features})
	if status.CapabilityTier != CapabilityTierCryptoOnly {
		t.Fatalf("tier = %q, want %q", status.CapabilityTier, CapabilityTierCryptoOnly)
	}
}

func TestDatapathHelpersFeaturesRequireModuleBTF(t *testing.T) {
	old := moduleBTFAvailable
	moduleBTFAvailable = func(string) bool { return false }
	defer func() { moduleBTFAvailable = old }()

	features, missing := filterModuleFeaturesByRuntimeBTF("trustix_datapath_helpers", []string{FeatureGSOSKB, FeatureRouteTCPKfunc})
	if !missing {
		t.Fatal("expected missing module BTF to be reported")
	}
	if len(features) != 0 {
		t.Fatalf("features = %#v, want none without module BTF", features)
	}
}

func TestCryptoModuleBTFFilterKeepsDeviceFeatures(t *testing.T) {
	old := moduleBTFAvailable
	moduleBTFAvailable = func(string) bool { return false }
	defer func() { moduleBTFAvailable = old }()

	features, missing := filterModuleFeaturesByRuntimeBTF("trustix_crypto", []string{FeatureDeviceAEAD, FeatureDirectAESNI, FeatureKfuncTC})
	if !missing {
		t.Fatal("expected missing module BTF to be reported")
	}
	if len(features) != 2 || !featureListHasAny(features, FeatureDeviceAEAD) || !featureListHasAny(features, FeatureDirectAESNI) {
		t.Fatalf("features = %#v, want device features retained", features)
	}
	if featureListHasAny(features, FeatureKfuncTC) {
		t.Fatalf("features = %#v, kfunc feature should be filtered without module BTF", features)
	}
}
