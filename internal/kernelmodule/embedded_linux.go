//go:build linux

package kernelmodule

import "embed"

//go:embed assets/trustix_crypto.ko assets/trustix_datapath.ko assets/trustix_datapath_helpers.ko
var embeddedModuleFS embed.FS

const embeddedTrustIXCryptoPath = "embedded://trustix_crypto.ko"
const embeddedTrustIXDatapathPath = "embedded://trustix_datapath.ko"
const embeddedTrustIXDatapathHelpersPath = "embedded://trustix_datapath_helpers.ko"

func embeddedTrustIXCrypto() []byte {
	payload, err := embeddedModuleFS.ReadFile("assets/trustix_crypto.ko")
	if err != nil {
		return nil
	}
	return payload
}

func embeddedTrustIXDatapathHelpers() []byte {
	payload, err := embeddedModuleFS.ReadFile("assets/trustix_datapath_helpers.ko")
	if err != nil {
		return nil
	}
	return payload
}

func embeddedTrustIXDatapath() []byte {
	payload, err := embeddedModuleFS.ReadFile("assets/trustix_datapath.ko")
	if err != nil {
		return nil
	}
	return payload
}

func embeddedModuleForName(name string) embeddedModuleAsset {
	switch name {
	case "trustix_crypto":
		return embeddedModuleAsset{name: "trustix_crypto.ko", label: embeddedTrustIXCryptoPath, read: embeddedTrustIXCrypto}
	case "trustix_datapath":
		return embeddedModuleAsset{name: "trustix_datapath.ko", label: embeddedTrustIXDatapathPath, read: embeddedTrustIXDatapath}
	case "trustix_datapath_helpers":
		return embeddedModuleAsset{name: "trustix_datapath_helpers.ko", label: embeddedTrustIXDatapathHelpersPath, read: embeddedTrustIXDatapathHelpers}
	default:
		return embeddedModuleAsset{}
	}
}
