//go:build linux

package ebpf

import (
	"crypto/sha256"
	"encoding/hex"
)

func EmbeddedAssets() []EmbeddedAsset {
	specs := []struct {
		name string
		read func() ([]byte, error)
	}{
		{
			name: "experimental_tcp_xdp_bpfel.o",
			read: func() ([]byte, error) {
				return experimentalTCPXDPFS.ReadFile("bpf/experimental_tcp_xdp_bpfel.o")
			},
		},
		{
			name: "experimental_tcp_kernel_crypto_xdp_bpfel.o",
			read: func() ([]byte, error) {
				return experimentalTCPXDPFS.ReadFile("bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o")
			},
		},
		{
			name: "experimental_tcp_kernel_crypto_xdp_direct_bpfel.o",
			read: func() ([]byte, error) {
				return experimentalTCPXDPFS.ReadFile("bpf/experimental_tcp_kernel_crypto_xdp_direct_bpfel.o")
			},
		},
		{
			name: "kernel_udp_xdp_bpfel.o",
			read: func() ([]byte, error) {
				return experimentalTCPXDPFS.ReadFile("bpf/kernel_udp_xdp_bpfel.o")
			},
		},
		{
			name: "experimental_tcp_kernel_crypto_tx_xdp_bpfel.o",
			read: func() ([]byte, error) {
				return experimentalTCPTXSealFS.ReadFile("bpf/experimental_tcp_kernel_crypto_tx_xdp_bpfel.o")
			},
		},
		{
			name: "kernel_udp_tx_kernel_crypto_tc_bpfel.o",
			read: func() ([]byte, error) {
				return kernelUDPTXSecureDirectFS.ReadFile("bpf/kernel_udp_tx_kernel_crypto_tc_bpfel.o")
			},
		},
		{
			name: "kernel_udp_rx_kernel_crypto_tc_bpfel.o",
			read: func() ([]byte, error) {
				return kernelUDPRXSecureDirectFS.ReadFile("bpf/kernel_udp_rx_kernel_crypto_tc_bpfel.o")
			},
		},
		{
			name: "skb_kfunc_tc_bpfel.o",
			read: func() ([]byte, error) {
				return skbKfuncTCFS.ReadFile("bpf/skb_kfunc_tc_bpfel.o")
			},
		},
		{
			name: "kernel_crypto_provider_bpfel.o",
			read: func() ([]byte, error) {
				return kernelCryptoProviderFS.ReadFile("bpf/kernel_crypto_provider_bpfel.o")
			},
		},
		{
			name: "kernel_crypto_selftest_bpfel.o",
			read: func() ([]byte, error) {
				return kernelCryptoSelfTestFS.ReadFile("bpf/kernel_crypto_selftest_bpfel.o")
			},
		},
	}

	assets := make([]EmbeddedAsset, 0, len(specs))
	for _, spec := range specs {
		payload, err := spec.read()
		assets = append(assets, embeddedAssetFromPayload(spec.name, payload, err))
	}
	return assets
}

func embeddedAssetFromPayload(name string, payload []byte, err error) EmbeddedAsset {
	asset := EmbeddedAsset{Name: name}
	if err != nil || len(payload) == 0 {
		return asset
	}
	sum := sha256.Sum256(payload)
	asset.Present = true
	asset.SHA256 = hex.EncodeToString(sum[:])
	asset.Size = int64(len(payload))
	asset.ELF = embeddedAssetLooksLikeELF(payload)
	return asset
}

func embeddedAssetLooksLikeELF(payload []byte) bool {
	return len(payload) >= 4 && payload[0] == 0x7f && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'F'
}
