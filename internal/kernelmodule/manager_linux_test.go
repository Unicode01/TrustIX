//go:build linux

package kernelmodule

import (
	"errors"
	"testing"

	"trustix.local/trustix/internal/config"
)

func TestLoadParametersWithBuildSHAOverridesUserValue(t *testing.T) {
	source := moduleSource{label: "test.ko", payload: []byte("\x7fELF...parm=build_sha256:TrustIX build fingerprint")}
	parameters := loadParametersWithBuildSHA(source, "prefer_software=1 build_sha256=bad")
	want := "prefer_software=1 build_sha256=" + moduleSourceSHA256(source)
	if parameters != want {
		t.Fatalf("parameters = %q", parameters)
	}
}

func TestLoadParametersWithBuildSHAAcceptsOpenWrtParmTypeMetadata(t *testing.T) {
	source := moduleSource{label: "openwrt.ko", payload: []byte("\x7fELF...parmtype=build_sha256:charp")}
	parameters := loadParametersWithBuildSHA(source, "prefer_software=1")
	want := "prefer_software=1 build_sha256=" + moduleSourceSHA256(source)
	if parameters != want {
		t.Fatalf("parameters = %q, want %q", parameters, want)
	}
}

func TestModulePayloadSupportsParameterMetadataForms(t *testing.T) {
	for name, tc := range map[string]struct {
		payload []byte
		key     string
		want    bool
	}{
		"description": {payload: []byte("parm=build_sha256:fingerprint"), key: "build_sha256", want: true},
		"type only":   {payload: []byte("parmtype=build_sha256:charp"), key: "build_sha256", want: true},
		"other key":   {payload: []byte("parmtype=features:ullong"), key: "build_sha256"},
		"empty key":   {payload: []byte("parmtype=build_sha256:charp")},
	} {
		t.Run(name, func(t *testing.T) {
			if got := modulePayloadSupportsParameter(tc.payload, tc.key); got != tc.want {
				t.Fatalf("modulePayloadSupportsParameter() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestLoadParametersWithBuildSHARemovesReservedValueWhenUnsupported(t *testing.T) {
	source := moduleSource{label: "test.ko", payload: []byte("\x7fELF...old module")}
	parameters := loadParametersWithBuildSHA(source, "prefer_software=1 build_sha256=bad")
	if parameters != "prefer_software=1" {
		t.Fatalf("parameters = %q", parameters)
	}
}

func TestLoadedModuleUpgradeState(t *testing.T) {
	source := moduleSource{label: "test.ko", payload: []byte("\x7fELF...parm=build_sha256:TrustIX build fingerprint")}
	sourceSHA := moduleSourceSHA256(source)
	for name, tc := range map[string]struct {
		status Status
		want   string
	}{
		"not loaded": {status: Status{}, want: "not_loaded"},
		"missing":    {status: Status{Loaded: true}, want: "missing_loaded_fingerprint"},
		"mismatch":   {status: Status{Loaded: true, LoadedSHA256: "other"}, want: "mismatch"},
		"current":    {status: Status{Loaded: true, LoadedSHA256: sourceSHA}, want: "current"},
	} {
		if got := loadedModuleUpgradeState(source, tc.status); got != tc.want {
			t.Fatalf("%s: upgrade state = %q, want %q", name, got, tc.want)
		}
	}
}

func TestLoadedModuleUpgradeReloadRequiredHonorsPolicyAndFingerprint(t *testing.T) {
	supported := moduleSource{label: "test.ko", payload: []byte("\x7fELF...parm=build_sha256:TrustIX build fingerprint")}
	unsupported := moduleSource{label: "legacy.ko", payload: []byte("\x7fELF...legacy module")}
	currentSHA := moduleSourceSHA256(supported)
	for name, tc := range map[string]struct {
		module config.KernelModuleConfig
		source moduleSource
		status Status
		want   bool
	}{
		"auto mismatch": {
			module: config.KernelModuleConfig{ReloadOnUpgrade: "auto"},
			source: supported,
			status: Status{Loaded: true, LoadedSHA256: "old"},
			want:   true,
		},
		"auto current": {
			module: config.KernelModuleConfig{ReloadOnUpgrade: "auto"},
			source: supported,
			status: Status{Loaded: true, LoadedSHA256: currentSHA},
		},
		"never mismatch": {
			module: config.KernelModuleConfig{ReloadOnUpgrade: "never"},
			source: supported,
			status: Status{Loaded: true, LoadedSHA256: "old"},
		},
		"always current": {
			module: config.KernelModuleConfig{ReloadOnUpgrade: "always"},
			source: supported,
			status: Status{Loaded: true, LoadedSHA256: currentSHA},
			want:   true,
		},
		"auto legacy target": {
			module: config.KernelModuleConfig{ReloadOnUpgrade: "auto"},
			source: unsupported,
			status: Status{Loaded: true},
		},
		"always not loaded": {
			module: config.KernelModuleConfig{ReloadOnUpgrade: "always"},
			source: supported,
			status: Status{},
		},
	} {
		if got := loadedModuleUpgradeReloadRequired(tc.module, tc.source, tc.status); got != tc.want {
			t.Fatalf("%s: reload required = %t, want %t", name, got, tc.want)
		}
	}
}

func TestModuleSourceReloadAvailableRequiresUsablePayload(t *testing.T) {
	for name, tc := range map[string]struct {
		source moduleSource
		want   bool
	}{
		"embedded payload": {source: moduleSource{payload: []byte("module")}, want: true},
		"resolved path":    {source: moduleSource{path: "module.ko", sha256: "known"}, want: true},
		"empty source":     {source: moduleSource{}},
		"source error":     {source: moduleSource{err: errors.New("missing module")}},
	} {
		if got := moduleSourceReloadAvailable(tc.source); got != tc.want {
			t.Fatalf("%s: reload available = %t, want %t", name, got, tc.want)
		}
	}
}

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

func TestModuleFeatureMaskIncludesInnerTCPOptimizations(t *testing.T) {
	features := moduleFeatureMaskToNames(trustIXKernelFeatureFullDatapathBit | trustIXKernelFeatureInnerTCPChecksumPartialBit | trustIXKernelFeatureInnerGSOBit | trustIXKernelFeatureTIXTCPPortShardingBit | trustIXKernelFeatureSecureTIXTCPFullDatapathBit | trustIXKernelFeatureSecureInnerTCPChecksumPartialBit)
	status := completeCapabilityStatus(Status{Name: "trustix_datapath", Loaded: true, Features: features})
	if !status.HasFeature(FeatureInnerTCPChecksumPartial) {
		t.Fatalf("features = %#v, missing %q", status.Features, FeatureInnerTCPChecksumPartial)
	}
	if !status.HasFeature(FeatureInnerGSO) {
		t.Fatalf("features = %#v, missing %q", status.Features, FeatureInnerGSO)
	}
	if !status.HasFeature(FeatureTIXTCPPortSharding) {
		t.Fatalf("features = %#v, missing %q", status.Features, FeatureTIXTCPPortSharding)
	}
	if !status.HasFeature(FeatureSecureTIXTCPFullDatapath) {
		t.Fatalf("features = %#v, missing %q", status.Features, FeatureSecureTIXTCPFullDatapath)
	}
	if !status.HasFeature(FeatureSecureInnerTCPChecksumPartial) {
		t.Fatalf("features = %#v, missing %q", status.Features, FeatureSecureInnerTCPChecksumPartial)
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
