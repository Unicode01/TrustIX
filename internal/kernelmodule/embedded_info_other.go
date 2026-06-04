//go:build !linux

package kernelmodule

func EmbeddedTrustIXCryptoAsset() EmbeddedAsset {
	return EmbeddedAsset{Name: "trustix_crypto.ko"}
}

func EmbeddedTrustIXDatapathHelpersAsset() EmbeddedAsset {
	return EmbeddedAsset{Name: "trustix_datapath_helpers.ko"}
}

func EmbeddedTrustIXDatapathAsset() EmbeddedAsset {
	return EmbeddedAsset{Name: "trustix_datapath.ko"}
}

func embeddedModuleForName(name string) embeddedModuleAsset {
	switch name {
	case "trustix_crypto":
		return embeddedModuleAsset{name: "trustix_crypto.ko", label: "embedded://trustix_crypto.ko"}
	case "trustix_datapath":
		return embeddedModuleAsset{name: "trustix_datapath.ko", label: "embedded://trustix_datapath.ko"}
	case "trustix_datapath_helpers":
		return embeddedModuleAsset{name: "trustix_datapath_helpers.ko", label: "embedded://trustix_datapath_helpers.ko"}
	default:
		return embeddedModuleAsset{}
	}
}
