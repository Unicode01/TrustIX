package dataplane

const (
	CryptoFallbackLayerKernelModule = "kernel_module"
	CryptoFallbackLayerTC           = "tc"
	CryptoFallbackLayerXDP          = "xdp"
	CryptoFallbackLayerBPFProgRun   = "bpf_prog_run"
	CryptoFallbackLayerDevice       = "kernel_module_device"
	CryptoFallbackLayerUserspace    = "userspace"

	CryptoFallbackFullKernelModuleDatapath = "ko_full_datapath"
	CryptoFallbackGSOSKBModuleHelpers      = "ko_gso_skb"
	CryptoFallbackTCBPFDirect              = "tc_bpf_direct"
	CryptoFallbackBPFProgRunFrame          = "bpf_prog_run_frame"
	CryptoFallbackKOAEADDevice             = "ko_aead_device"
	CryptoFallbackUserspaceAEAD            = "userspace_aead"
)

func FirstReadyCryptoFallbackStep(steps []CryptoFallbackStep) string {
	for _, step := range steps {
		if step.Ready {
			return step.Name
		}
	}
	return ""
}
