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

func TestThreeIXMatrixSmokePinsFastPathTransportPolicy(t *testing.T) {
	payload, err := os.ReadFile("linux-three-ix-e2e-smoke.sh")
	if err != nil {
		t.Fatalf("read linux-three-ix-e2e-smoke.sh: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		`transport_profile="${TRUSTIX_3IX_E2E_TRANSPORT_PROFILE:-}"`,
		`transport_datapath="${TRUSTIX_3IX_E2E_TRANSPORT_DATAPATH:-}"`,
		`transport_encryption="${TRUSTIX_3IX_E2E_TRANSPORT_ENCRYPTION:-${TRUSTIX_3IX_E2E_ENCRYPTION:-secure}}"`,
		"transport_policy_profile()",
		"tix_tcp|kernel_udp|gre|ipip|vxlan) printf 'performance\\n'",
		"tix_tcp|kernel_udp|gre|ipip|vxlan) printf 'tc_xdp\\n'",
		"profile: $(transport_policy_profile)",
		"datapath: $(transport_policy_datapath)",
		"encryption: $(transport_policy_encryption)",
		"crypto_key_source: auto",
		"TRUSTIX_3IX_E2E_TRANSPORT_PROFILE must be stable, performance, or latency when set",
		"TRUSTIX_3IX_E2E_TRANSPORT_DATAPATH must be auto, userspace, tc_xdp, or kernel_module when set",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("linux-three-ix-e2e-smoke.sh missing explicit fast-path policy fragment %q", want)
		}
	}
}

func TestModuleSmokesDiscoverPackagedTestsAndDisableStatefulGoTestCache(t *testing.T) {
	cases := []struct {
		name string
		want []string
	}{
		{
			name: "linux-kernel-module-smoke.sh",
			want: []string{
				`test_bin="${repo_root}/bin/ebpf.test"`,
				`kernelmodule_test_bin="${repo_root}/bin/kernelmodule.test"`,
				`go test -count=1 ./internal/dataplane/ebpf -run "$roundtrip_tests" -v`,
			},
		},
		{
			name: "linux-datapath-module-smoke.sh",
			want: []string{
				`kernelmodule_test_bin="${repo_root}/bin/kernelmodule.test"`,
				`go test -count=1 ./internal/kernelmodule -run '^TestTrustIXDatapathHelpersDeviceQueryAndSelftest$' -v`,
			},
		},
		{
			name: "linux-full-datapath-module-smoke.sh",
			want: []string{
				`kernelmodule_test_bin="${repo_root}/bin/kernelmodule.test"`,
				`go test -count=1 ./internal/kernelmodule -run '^TestTrustIXFullDatapathDeviceQueryAndSelftest$' -v`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := os.ReadFile(tc.name)
			if err != nil {
				t.Fatalf("read %s: %v", tc.name, err)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(payload), want) {
					t.Fatalf("%s missing stateful smoke guard %q", tc.name, want)
				}
			}
		})
	}
}

func TestReleaseSmokeUnloadsOnlyModulesItIntroduced(t *testing.T) {
	payload, err := os.ReadFile("release-smoke-linux.sh")
	if err != nil {
		t.Fatalf("read release-smoke-linux.sh: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		`preexisting_crypto=0`,
		`preexisting_datapath=0`,
		`preexisting_helpers=0`,
		`unload_new_module trustix_datapath "$preexisting_datapath"`,
		`unload_new_module trustix_datapath_helpers "$preexisting_helpers"`,
		`unload_new_module trustix_crypto "$preexisting_crypto"`,
		`cleanup_leaked_release_processes()`,
		`case "$exe" in`,
		`"$workdir"/extract/bin/*)`,
		`if ! cleanup_leaked_release_processes && [[ "$exit_code" == "0" ]]`,
		`trap - EXIT`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("release-smoke-linux.sh missing module cleanup guard %q", want)
		}
	}
}

func TestDeviceAccessSmokeTracksDirectNetnsProcessPIDs(t *testing.T) {
	payload, err := os.ReadFile("linux-device-access-smoke.sh")
	if err != nil {
		t.Fatalf("read linux-device-access-smoke.sh: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		`ip netns exec "$ns_ix" "$trustixd"`,
		`ip netns exec "$ns_dev" "$trustixdevice"`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("linux-device-access-smoke.sh must launch the tracked process directly with %q", want)
		}
	}
	for _, bad := range []string{
		`run_ns "$ns_ix" "$trustixd"`,
		`run_ns "$ns_dev" "$trustixdevice"`,
	} {
		if strings.Contains(source, bad) {
			t.Fatalf("linux-device-access-smoke.sh must not background a shell function with %q", bad)
		}
	}
}

func TestLinuxE2ESkipsUnavailableKernelCryptoProbeForEmbeddedModule(t *testing.T) {
	payload, err := os.ReadFile("linux-e2e-smoke.sh")
	if err != nil {
		t.Fatalf("read linux-e2e-smoke.sh: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		`kernel_provider_loadable()`,
		`"${bin_dir}/trustixd" -version`,
		`^asset.embedded_kos.trustix_crypto.ko.embedded=true$`,
		`if kernel_provider_loadable; then`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("linux-e2e-smoke.sh missing embedded kernel provider detection %q", want)
		}
	}
}

func TestLinuxE2ERequiresKernelTransportForAFXDPTransports(t *testing.T) {
	payload, err := os.ReadFile("linux-e2e-smoke.sh")
	if err != nil {
		t.Fatalf("read linux-e2e-smoke.sh: %v", err)
	}
	want := "if is_af_xdp_transport || is_iptunnel_transport || tix_tcp_direct_enabled || kernel_plaintext_direct_fastpath_enabled; then"
	if !strings.Contains(string(payload), want) {
		t.Fatalf("linux-e2e-smoke.sh must require kernel transport for AF_XDP transports with %q", want)
	}
}
