//go:build linux

package ebpf

import (
	"os"
	"strings"
	"testing"
)

func TestReadKernelCryptoProbeBTFUsesConfiguredPath(t *testing.T) {
	path := tempBTFPayload(t, testBTFWithFunctions("bpf_crypto_ctx_create"))
	t.Setenv(bpfKernelBTFEnv, path)
	t.Setenv(bpfBTFStrictEnv, "")

	payload, source, err := readKernelCryptoProbeBTF()
	if err != nil {
		t.Fatalf("readKernelCryptoProbeBTF error = %v", err)
	}
	if source != path {
		t.Fatalf("source = %q, want %q", source, path)
	}
	if len(payload) == 0 {
		t.Fatal("payload is empty")
	}
}

func TestReadKernelCryptoProbeBTFMissingConfiguredPathFallsBack(t *testing.T) {
	t.Setenv(bpfKernelBTFEnv, "/definitely/not/a/trustix/btf")
	t.Setenv(bpfBTFStrictEnv, "")

	_, _, err := readKernelCryptoProbeBTF()
	if err == nil {
		t.Skip("system kernel BTF is available")
	}
	if got := err.Error(); strings.Contains(got, "/definitely/not/a/trustix/btf") {
		t.Fatalf("error = %q, missing optional configured path should not be fatal", got)
	}
}

func TestReadKernelCryptoProbeBTFStrictMissingConfiguredPath(t *testing.T) {
	t.Setenv(bpfKernelBTFEnv, "/definitely/not/a/trustix/btf")
	t.Setenv(bpfBTFStrictEnv, "1")

	_, _, err := readKernelCryptoProbeBTF()
	if err == nil {
		t.Fatal("readKernelCryptoProbeBTF error = nil, want error")
	}
	if got := err.Error(); !strings.Contains(got, bpfKernelBTFEnv) || !strings.Contains(got, "/definitely/not/a/trustix/btf") {
		t.Fatalf("error = %q, want env name and path", got)
	}
}

func tempBTFPayload(t *testing.T, payload []byte) string {
	t.Helper()
	path := t.TempDir() + "/vmlinux.btf"
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write temp BTF: %v", err)
	}
	return path
}
