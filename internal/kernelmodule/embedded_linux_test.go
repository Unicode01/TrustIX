//go:build linux

package kernelmodule

import "testing"

func TestEmbeddedModulePayloadsAreCached(t *testing.T) {
	tests := map[string]func() []byte{
		"trustix_crypto":           embeddedTrustIXCrypto,
		"trustix_datapath":         embeddedTrustIXDatapath,
		"trustix_datapath_helpers": embeddedTrustIXDatapathHelpers,
	}
	for name, read := range tests {
		t.Run(name, func(t *testing.T) {
			first := read()
			second := read()
			if len(first) == 0 || len(second) == 0 {
				t.Fatal("embedded payload is empty")
			}
			if &first[0] != &second[0] {
				t.Fatal("embedded payload was copied on repeated read")
			}
		})
	}
}

func TestEmbeddedModulePayloadMissingAssetReturnsNil(t *testing.T) {
	asset := embeddedModulePayload{path: "assets/missing.ko"}
	if payload := asset.read(); payload != nil {
		t.Fatalf("missing embedded payload length = %d, want nil", len(payload))
	}
	if payload := asset.read(); payload != nil {
		t.Fatalf("cached missing embedded payload length = %d, want nil", len(payload))
	}
}
