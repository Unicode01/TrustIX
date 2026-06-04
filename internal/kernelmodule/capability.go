package kernelmodule

import "sort"

const (
	FeatureCryptoAEAD    = "crypto_aead"
	FeatureDeviceAEAD    = "device_aead"
	FeatureKfuncTC       = "kfunc_tc"
	FeatureKfuncXDP      = "kfunc_xdp"
	FeatureDirectAESNI   = "direct_aesni"
	FeatureDirectVAES    = "direct_vaes"
	FeatureGSOSKB        = "gso_skb"
	FeatureFullDatapath  = "full_datapath"
	FeatureRouteTCPKfunc = "route_tcp_kfunc"
	FeatureRouteTCPXmit  = "route_tcp_xmit_kfunc"

	CapabilityTierUnavailable  = "unavailable"
	CapabilityTierCryptoOnly   = "crypto_only"
	CapabilityTierGSOSKB       = "gso_skb"
	CapabilityTierFullDatapath = "full_datapath"
)

func (status Status) HasFeature(feature string) bool {
	for _, candidate := range status.Features {
		if candidate == feature {
			return true
		}
	}
	return false
}

func (status Status) FullDatapathReady() bool {
	return status.Loaded && status.HasFeature(FeatureFullDatapath)
}

func (status Status) GSOSKBReady() bool {
	return status.Loaded && status.HasFeature(FeatureGSOSKB)
}

func completeCapabilityStatus(status Status) Status {
	status.Features = normalizeCapabilityFeatures(status.Features)
	status.CapabilityTier, status.CapabilityReason, status.MissingFeatures = deriveCapabilityTier(status.Name, status.Loaded, status.Features)
	return status
}

func normalizeCapabilityFeatures(features []string) []string {
	if len(features) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(features))
	out := make([]string, 0, len(features))
	for _, feature := range features {
		if feature == "" {
			continue
		}
		if _, ok := seen[feature]; ok {
			continue
		}
		seen[feature] = struct{}{}
		out = append(out, feature)
	}
	sort.Strings(out)
	return out
}

func deriveCapabilityTier(name string, loaded bool, features []string) (string, string, []string) {
	if !loaded {
		return CapabilityTierUnavailable, "module is not loaded; crypto and datapath stay in userspace or the dataplane's built-in fallback", nil
	}
	featureSet := make(map[string]struct{}, len(features))
	for _, feature := range features {
		featureSet[feature] = struct{}{}
	}
	has := func(feature string) bool {
		_, ok := featureSet[feature]
		return ok
	}
	switch name {
	case "trustix_datapath":
		switch {
		case has(FeatureFullDatapath):
			return CapabilityTierFullDatapath, "trustix_datapath reports full TrustIX datapath capability", nil
		default:
			return CapabilityTierUnavailable, "trustix_datapath is loaded but full datapath capability is not active", []string{FeatureFullDatapath}
		}
	case "trustix_datapath_helpers":
		switch {
		case has(FeatureFullDatapath):
			return CapabilityTierUnavailable, "trustix_datapath_helpers must not report full TrustIX datapath capability", []string{FeatureGSOSKB}
		case has(FeatureGSOSKB):
			return CapabilityTierGSOSKB, "trustix_datapath_helpers reports skb/GSO datapath helpers; complete route/session datapath belongs to trustix_datapath", nil
		default:
			return CapabilityTierUnavailable, "trustix_datapath_helpers is loaded but no safe datapath helper capability was detected", []string{FeatureGSOSKB}
		}
	case "trustix_crypto":
		if has(FeatureCryptoAEAD) || has(FeatureDeviceAEAD) || has(FeatureKfuncTC) || has(FeatureKfuncXDP) {
			return CapabilityTierCryptoOnly, "trustix_crypto supports TrustIX AEAD crypto only; datapath helpers belong to trustix_datapath_helpers", nil
		}
		return CapabilityTierUnavailable, "trustix_crypto is loaded but no TrustIX AEAD capability was detected", []string{FeatureCryptoAEAD, FeatureDeviceAEAD}
	default:
		return CapabilityTierUnavailable, "unknown TrustIX kernel module; no first-release capability contract applies", nil
	}
}
