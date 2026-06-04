//go:build !linux

package ebpf

func EmbeddedAssets() []EmbeddedAsset {
	return nil
}
