//go:build linux

package kernelmodule

func EmbeddedTrustIXCryptoAsset() EmbeddedAsset {
	payload := embeddedTrustIXCrypto()
	asset := EmbeddedAsset{Name: "trustix_crypto.ko"}
	if len(payload) == 0 {
		return asset
	}
	asset.Present = true
	asset.SHA256 = bytesSHA256(payload)
	asset.Size = int64(len(payload))
	asset.ELF = looksLikeELF(payload)
	return asset
}

func EmbeddedTrustIXDatapathHelpersAsset() EmbeddedAsset {
	payload := embeddedTrustIXDatapathHelpers()
	asset := EmbeddedAsset{Name: "trustix_datapath_helpers.ko"}
	if len(payload) == 0 {
		return asset
	}
	asset.Present = true
	asset.SHA256 = bytesSHA256(payload)
	asset.Size = int64(len(payload))
	asset.ELF = looksLikeELF(payload)
	return asset
}

func EmbeddedTrustIXDatapathAsset() EmbeddedAsset {
	payload := embeddedTrustIXDatapath()
	asset := EmbeddedAsset{Name: "trustix_datapath.ko"}
	if len(payload) == 0 {
		return asset
	}
	asset.Present = true
	asset.SHA256 = bytesSHA256(payload)
	asset.Size = int64(len(payload))
	asset.ELF = looksLikeELF(payload)
	return asset
}
