package scripts

import (
	"os"
	"strings"
	"testing"
)

func TestDefaultSmokeScriptsPinCompatibilityTransportPolicy(t *testing.T) {
	cases := []struct {
		name string
		want []string
	}{
		{
			name: "linux-membership-smoke.sh",
			want: []string{
				"  profile: stable\n",
				"  datapath: userspace\n",
				"  encryption: secure\n",
				"  crypto_key_source: auto\n",
				"  crypto_placement: userspace\n",
				"  kernel_transport:\n    mode: disabled\n",
			},
		},
		{
			name: "linux-trust-policy-smoke.sh",
			want: []string{
				"  profile: stable\n",
				"  datapath: userspace\n",
				"  encryption: secure\n",
				"  crypto_key_source: auto\n",
				"  crypto_placement: userspace\n",
				"  kernel_transport:\n    mode: disabled\n",
			},
		},
		{
			name: "linux-device-access-smoke.sh",
			want: []string{
				"  profile: stable\n",
				"  datapath: userspace\n",
				"  encryption: secure\n",
				"  crypto_key_source: trustix_x25519\n",
				"  crypto_placement: userspace\n",
				"  kernel_transport:\n    mode: disabled\n",
			},
		},
		{
			name: "release-smoke-linux.sh",
			want: []string{
				"  profile: stable\n",
				"  datapath: userspace\n",
				"  encryption: secure\n",
				"  crypto_key_source: auto\n",
				"  crypto_placement: userspace\n",
				"  kernel_transport:\n    mode: disabled\n",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			payload, err := os.ReadFile(tc.name)
			if err != nil {
				t.Fatalf("read %s: %v", tc.name, err)
			}
			source := string(payload)
			for _, want := range tc.want {
				if !strings.Contains(source, want) {
					t.Fatalf("%s missing pinned compatibility fragment %q", tc.name, want)
				}
			}
			if strings.Contains(source, "load_balance: least_conn") {
				t.Fatalf("%s still carries legacy least_conn in default smoke config", tc.name)
			}
		})
	}
}
