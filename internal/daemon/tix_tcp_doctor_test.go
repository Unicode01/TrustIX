package daemon

import (
	"strings"
	"testing"

	"trustix.local/trustix/internal/dataplane"
)

func TestTIXTCPDoctorReportsKernelCryptoRequestAsDegraded(t *testing.T) {
	status := dataPathStatus{
		TIXTCP: &dataplane.TIXTCPStatus{
			Available:          true,
			Provider:           "af_xdp",
			FastPath:           true,
			Reinject:           true,
			UserspaceCrypto:    true,
			KernelCrypto:       false,
			KernelCryptoReason: "kernel BTF is missing BPF crypto kfuncs: bpf_crypto_encrypt",
			RequestedCrypto:    dataplane.CryptoPlacementKernel,
			PreferredCrypto:    dataplane.CryptoPlacementUserspace,
			EffectiveCrypto:    "",
			KernelCryptoProbe: &dataplane.KernelCryptoProbe{
				KernelBTF:     true,
				CryptoKfuncs:  false,
				AESGCM:        true,
				AESNI:         true,
				ProviderReady: false,
			},
		},
	}

	if got := tixTCPDoctorStatus(status); got != "degraded" {
		t.Fatalf("doctor status = %q, want degraded", got)
	}
	detail := tixTCPDoctorDetail(status)
	for _, want := range []string{"provider=af_xdp", "requested_crypto=kernel", "kernel_btf=true", "crypto_kfuncs=false", "bpf_crypto_encrypt"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("doctor detail %q does not contain %q", detail, want)
		}
	}
}

func TestTIXTCPDoctorReportsAFXDPSUserspaceAsOK(t *testing.T) {
	status := dataPathStatus{
		TIXTCP: &dataplane.TIXTCPStatus{
			Available:       true,
			Provider:        "af_xdp",
			FastPath:        true,
			Reinject:        true,
			UserspaceCrypto: true,
			KernelCrypto:    false,
			RequestedCrypto: dataplane.CryptoPlacementUserspace,
			EffectiveCrypto: dataplane.CryptoPlacementUserspace,
			KernelCryptoProbe: &dataplane.KernelCryptoProbe{
				KernelBTF:     true,
				CryptoKfuncs:  false,
				AESGCM:        true,
				AESNI:         true,
				ProviderReady: false,
			},
		},
	}

	if got := tixTCPDoctorStatus(status); got != "ok" {
		t.Fatalf("doctor status = %q, want ok", got)
	}
}

func TestKernelTransportDoctorReportsRequiredUnavailableAsDegraded(t *testing.T) {
	status := dataPathStatus{
		KernelTransport: &dataplane.KernelTransportStatus{
			Mode:      dataplane.KernelTransportModeRequireKernel,
			Available: false,
			Provider:  "none",
		},
	}
	if got := kernelTransportDoctorStatus(status); got != "degraded" {
		t.Fatalf("kernel transport doctor status = %q, want degraded", got)
	}
}

func TestKernelTransportDoctorReportsAvailableAsOK(t *testing.T) {
	status := dataPathStatus{
		KernelTransport: &dataplane.KernelTransportStatus{
			Mode:      dataplane.KernelTransportModePreferKernel,
			Available: true,
			Provider:  "af_xdp",
			Protocols: []dataplane.KernelTransportProtocol{{
				Protocol:  "tix_tcp",
				Available: true,
				Placement: "hybrid",
			}},
		},
	}
	if got := kernelTransportDoctorStatus(status); got != "ok" {
		t.Fatalf("kernel transport doctor status = %q, want ok", got)
	}
	detail := kernelTransportDoctorDetail(status)
	for _, want := range []string{"mode=prefer_kernel", "provider=af_xdp", "tix_tcp=hybrid/true"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("doctor detail %q does not contain %q", detail, want)
		}
	}
}

func TestKernelUDPDoctorReportsAvailableAsOK(t *testing.T) {
	status := dataPathStatus{
		KernelUDP: &dataplane.KernelUDPStatus{
			Available:       true,
			Provider:        "af_xdp",
			FastPath:        true,
			UserspaceCrypto: true,
			Reinject:        true,
			XDPAttachMode:   "native",
			AFXDPBindMode:   "zerocopy",
			ZeroCopyEnabled: true,
			ActiveFlows:     3,
			SubmittedFrames: 12,
			ReceivedFrames:  11,
			ProviderStats: map[string]uint64{
				"xdp_redirect": 11,
			},
		},
	}

	if got := kernelUDPDoctorStatus(status); got != "ok" {
		t.Fatalf("kernel UDP doctor status = %q, want ok", got)
	}
	detail := kernelUDPDoctorDetail(status)
	for _, want := range []string{"provider=af_xdp", "fast_path=true", "reinject=true", "xdp_attach_mode=native", "af_xdp_bind_mode=zerocopy", "xdp_redirect"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("doctor detail %q does not contain %q", detail, want)
		}
	}
}

func TestKernelUDPDoctorReportsRequiredUnavailableAsDegraded(t *testing.T) {
	status := dataPathStatus{
		KernelTransport: &dataplane.KernelTransportStatus{
			Mode:      dataplane.KernelTransportModeRequireKernel,
			Available: false,
			Provider:  "none",
		},
		KernelUDP: &dataplane.KernelUDPStatus{
			Available: false,
			Provider:  "none",
			FastPath:  false,
			Reinject:  false,
		},
	}

	if got := kernelUDPDoctorStatus(status); got != "degraded" {
		t.Fatalf("kernel UDP doctor status = %q, want degraded", got)
	}
	if detail := kernelUDPDoctorDetail(status); !strings.Contains(detail, "available=false") {
		t.Fatalf("doctor detail %q does not contain unavailable state", detail)
	}
}
