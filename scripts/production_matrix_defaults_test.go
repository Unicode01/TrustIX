package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionMatrixDefaultsAvoidUnsafeExperimentalTCPSecureFastPath(t *testing.T) {
	for _, name := range []string{"linux-production-transport-matrix.sh"} {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join(".", name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			text := string(payload)
			if strings.Contains(text, "experimental_tcp:secure:stable:kernel_module:userspace") {
				t.Fatalf("%s production defaults still select unsafe secure userspace-crypto experimental_tcp kernel fast path", name)
			}
			for _, want := range []string{
				"udp:plaintext:performance:kernel_module:userspace",
				"experimental_tcp:plaintext:performance:kernel_module:userspace",
				"experimental_tcp:secure:stable:userspace:userspace",
			} {
				if !strings.Contains(text, want) {
					t.Fatalf("%s production defaults missing %q", name, want)
				}
			}
		})
	}
}

func TestProductionSoakWrapsProductionMatrix(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-production-soak.sh"))
	if err != nil {
		t.Fatalf("read linux-production-soak.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_PRODUCTION_SOAK_DURATION_SECONDS:-3600",
		"TRUSTIX_PRODUCTION_SOAK_IPERF3_SECONDS:-120",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASES",
		"linux-production-transport-matrix.sh",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-production-soak.sh missing %q", want)
		}
	}
}
