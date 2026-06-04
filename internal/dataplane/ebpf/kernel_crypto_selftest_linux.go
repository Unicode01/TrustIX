//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	cebpf "github.com/cilium/ebpf"

	"trustix.local/trustix/internal/dataplane"
)

const kernelCryptoSelfTestPassedReason = "embedded ELF/CO-RE verifier selftest loaded syscall init plus XDP/TC crypto kfunc programs"
const kernelCryptoSelfTestMaxReason = 768

//go:embed bpf/kernel_crypto_selftest_bpfel.o
var kernelCryptoSelfTestFS embed.FS

func probeKernelCryptoVerifierSelfTest(probe dataplane.KernelCryptoProbe) *dataplane.KernelCryptoSelfTest {
	selfTest := kernelCryptoSelfTest(probe)
	if !probe.CapabilityReady {
		return selfTest
	}
	selfTest.Attempted = true
	if runtime.GOOS != "linux" {
		selfTest.Reason = "unsupported OS for BPF verifier selftest"
		return selfTest
	}
	if err := loadKernelCryptoSelfTestObject(); err != nil {
		selfTest.Reason = summarizeKernelCryptoSelfTestError(err)
		return selfTest
	}
	selfTest.Passed = true
	selfTest.Reason = kernelCryptoSelfTestPassedReason
	return selfTest
}

func loadKernelCryptoSelfTestObject() (err error) {
	object, err := kernelCryptoSelfTestFS.ReadFile("bpf/kernel_crypto_selftest_bpfel.o")
	if err != nil {
		return fmt.Errorf("read embedded selftest object: %w", err)
	}
	if len(object) == 0 {
		return fmt.Errorf("embedded selftest object is empty")
	}
	defer debug.FreeOSMemory()

	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return fmt.Errorf("parse embedded selftest ELF: %w", err)
	}
	for _, program := range []string{"trustix_kernel_crypto_init", "trustix_kernel_crypto_xdp", "trustix_kernel_crypto_tc"} {
		if spec.Programs[program] == nil {
			return fmt.Errorf("embedded selftest ELF is missing program %q", program)
		}
	}
	coll, err := newBPFCollectionWithOptions(spec, cebpf.CollectionOptions{})
	if err != nil {
		return fmt.Errorf("load embedded selftest programs: %w", err)
	}
	coll.Close()
	return nil
}

func summarizeKernelCryptoSelfTestError(err error) string {
	if err == nil {
		return ""
	}
	var verifier *cebpf.VerifierError
	var reason string
	if errors.As(err, &verifier) {
		reason = fmt.Sprintf("%+v", verifier)
	} else {
		reason = err.Error()
	}
	reason = strings.Join(strings.Fields(reason), " ")
	if len(reason) > kernelCryptoSelfTestMaxReason {
		reason = reason[:kernelCryptoSelfTestMaxReason] + "..."
	}
	return reason
}
