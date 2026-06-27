package scripts

import (
	"os"
	"strings"
	"testing"
)

func TestSampleConfigsPinCompatibilityTransportPolicy(t *testing.T) {
	for _, name := range []string{"lab-a.yaml", "lab-b.yaml"} {
		name := name
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile("../configs/" + name)
			if err != nil {
				t.Fatalf("read sample config: %v", err)
			}
			source := string(payload)
			for _, want := range []string{
				"transport_policy:\n",
				"  profile: stable\n",
				"  datapath: userspace\n",
				"  encryption: secure\n",
				"  crypto_key_source: auto\n",
				"  crypto_placement: userspace\n",
			} {
				if !strings.Contains(source, want) {
					t.Fatalf("%s missing pinned compatibility fragment %q", name, want)
				}
			}
			if strings.Contains(source, "load_balance: least_conn") {
				t.Fatalf("%s still carries legacy least_conn default", name)
			}
		})
	}
}
