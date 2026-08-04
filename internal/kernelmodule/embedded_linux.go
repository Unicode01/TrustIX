//go:build linux

package kernelmodule

import (
	"embed"
	"sync"
)

//go:embed assets/trustix_crypto.ko assets/trustix_datapath.ko assets/trustix_datapath_helpers.ko
var embeddedModuleFS embed.FS

const embeddedTrustIXCryptoPath = "embedded://trustix_crypto.ko"
const embeddedTrustIXDatapathPath = "embedded://trustix_datapath.ko"
const embeddedTrustIXDatapathHelpersPath = "embedded://trustix_datapath_helpers.ko"

type embeddedModulePayload struct {
	once    sync.Once
	path    string
	payload []byte
}

var (
	embeddedTrustIXCryptoPayload = embeddedModulePayload{
		path: "assets/trustix_crypto.ko",
	}
	embeddedTrustIXDatapathPayload = embeddedModulePayload{
		path: "assets/trustix_datapath.ko",
	}
	embeddedTrustIXDatapathHelpersPayload = embeddedModulePayload{
		path: "assets/trustix_datapath_helpers.ko",
	}
)

func (asset *embeddedModulePayload) read() []byte {
	asset.once.Do(func() {
		asset.payload, _ = embeddedModuleFS.ReadFile(asset.path)
	})
	return asset.payload
}

func embeddedTrustIXCrypto() []byte {
	return embeddedTrustIXCryptoPayload.read()
}

func embeddedTrustIXDatapathHelpers() []byte {
	return embeddedTrustIXDatapathHelpersPayload.read()
}

func embeddedTrustIXDatapath() []byte {
	return embeddedTrustIXDatapathPayload.read()
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
