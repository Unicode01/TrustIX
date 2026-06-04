//go:build linux

package ebpf

import (
	"strings"
	"sync"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

func TestProgramOptionsWithConfiguredBTFEmpty(t *testing.T) {
	t.Setenv(bpfKernelBTFEnv, "")
	t.Setenv(bpfExtraBTFEnv, "")

	got, err := programOptionsWithConfiguredBTF(cebpf.ProgramOptions{LogSizeStart: 4096})
	if err != nil {
		t.Fatalf("programOptionsWithConfiguredBTF error = %v", err)
	}
	if got.KernelTypes != nil {
		t.Fatalf("KernelTypes = %v, want nil", got.KernelTypes)
	}
	if len(got.ExtraRelocationTargets) != 0 {
		t.Fatalf("ExtraRelocationTargets len = %d, want 0", len(got.ExtraRelocationTargets))
	}
	if got.LogSizeStart != 4096 {
		t.Fatalf("LogSizeStart = %d, want 4096", got.LogSizeStart)
	}
}

func TestProgramOptionsWithConfiguredBTFMissingKernelPathIsOptional(t *testing.T) {
	resetConfiguredBTFForTest()
	t.Cleanup(resetConfiguredBTFForTest)
	t.Setenv(bpfKernelBTFEnv, "/definitely/not/a/trustix/btf")
	t.Setenv(bpfExtraBTFEnv, "")
	t.Setenv(bpfBTFStrictEnv, "")

	got, err := programOptionsWithConfiguredBTF(cebpf.ProgramOptions{})
	if err != nil {
		t.Fatalf("programOptionsWithConfiguredBTF error = %v", err)
	}
	if got.KernelTypes != nil {
		t.Fatalf("KernelTypes = %v, want nil", got.KernelTypes)
	}
}

func TestProgramOptionsWithConfiguredBTFStrictMissingKernelPath(t *testing.T) {
	resetConfiguredBTFForTest()
	t.Cleanup(resetConfiguredBTFForTest)
	t.Setenv(bpfKernelBTFEnv, "/definitely/not/a/trustix/btf")
	t.Setenv(bpfExtraBTFEnv, "")
	t.Setenv(bpfBTFStrictEnv, "1")

	_, err := programOptionsWithConfiguredBTF(cebpf.ProgramOptions{})
	if err == nil {
		t.Fatal("programOptionsWithConfiguredBTF error = nil, want error")
	}
	if got := err.Error(); !strings.Contains(got, bpfKernelBTFEnv) || !strings.Contains(got, "/definitely/not/a/trustix/btf") {
		t.Fatalf("error = %q, want env name and path", got)
	}
}

func resetConfiguredBTFForTest() {
	configuredKernelBTFOnce = sync.Once{}
	configuredKernelBTFSpec = nil
	configuredKernelBTFErr = nil
	configuredExtraBTFOnce = sync.Once{}
	configuredExtraBTFSpecs = nil
	configuredExtraBTFErr = nil
}
