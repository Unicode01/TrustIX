package buildassets

import (
	"sync"

	"trustix.local/trustix/internal/buildinfo"
	"trustix.local/trustix/internal/dataplane/ebpf"
	"trustix.local/trustix/internal/kernelmodule"
)

var (
	assetsOnce sync.Once
	assets     buildinfo.Assets
)

func Snapshot() buildinfo.Assets {
	assetsOnce.Do(func() {
		assets = collect()
	})
	return assets
}

func collect() buildinfo.Assets {
	ebpfAssets := make(map[string]buildinfo.AssetInfo)
	for _, asset := range ebpf.EmbeddedAssets() {
		ebpfAssets[asset.Name] = buildinfo.AssetInfo{
			Name:     asset.Name,
			Embedded: true,
			Present:  asset.Present,
			SHA256:   asset.SHA256,
			Size:     asset.Size,
			ELF:      asset.ELF,
		}
	}
	cryptoAsset := kernelmodule.EmbeddedTrustIXCryptoAsset()
	fullDatapathAsset := kernelmodule.EmbeddedTrustIXDatapathAsset()
	datapathAsset := kernelmodule.EmbeddedTrustIXDatapathHelpersAsset()
	moduleAssets := map[string]buildinfo.AssetInfo{
		cryptoAsset.Name: {
			Name:     cryptoAsset.Name,
			Embedded: true,
			Present:  cryptoAsset.Present,
			SHA256:   cryptoAsset.SHA256,
			Size:     cryptoAsset.Size,
			ELF:      cryptoAsset.ELF,
		},
		fullDatapathAsset.Name: {
			Name:     fullDatapathAsset.Name,
			Embedded: true,
			Present:  fullDatapathAsset.Present,
			SHA256:   fullDatapathAsset.SHA256,
			Size:     fullDatapathAsset.Size,
			ELF:      fullDatapathAsset.ELF,
		},
		datapathAsset.Name: {
			Name:     datapathAsset.Name,
			Embedded: true,
			Present:  datapathAsset.Present,
			SHA256:   datapathAsset.SHA256,
			Size:     datapathAsset.Size,
			ELF:      datapathAsset.ELF,
		},
	}
	return buildinfo.Assets{
		EmbeddedKOs: moduleAssets,
		EBPF:        ebpfAssets,
	}
}

func BuildInfo() buildinfo.Info {
	return buildinfo.SnapshotWithAssets(Snapshot())
}
