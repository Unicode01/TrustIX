package scripts

import (
	"os"
	"strings"
	"testing"
)

func TestWebUIIXProvisionDefaultsMatchBackendProductionProfiles(t *testing.T) {
	payload, err := os.ReadFile("../webui/src/components.tsx")
	if err != nil {
		t.Fatalf("read webui components: %v", err)
	}
	source := string(payload)
	mustContain := []string{
		`return { transportProfile: "performance", datapath: "tc_xdp", encryption: "secure", cryptoPlacement: "kernel", kernelTransport: "require_kernel" };`,
		`return { transportProfile: "performance", datapath: "kernel_module", encryption: "plaintext", cryptoPlacement: "userspace", kernelTransport: "require_kernel" };`,
		`crypto_placement: "userspace",`,
		`function ixProvisionDefaultEndpointTransport(profile: string, endpointMode = "passive", endpointAddress = "", serviceManager = "auto"): string`,
		`String(serviceManager || "").trim().toLowerCase().replaceAll("-", "_") === "openwrt"`,
		`ixProvisionDefaultEndpointTransport(input.profile, endpointMode, endpointAddress, input.serviceManager)`,
		`ixProvisionDefaultEndpointTransport(newIXProfile, newIXEndpointMode, newIXEndpointAddress, newIXServiceManager)`,
		`ixProvisionDefaultEndpointTransport(nextProfile, newIXEndpointMode, newIXEndpointAddress, nextServiceManager)`,
	}
	for _, want := range mustContain {
		if !strings.Contains(source, want) {
			t.Fatalf("webui IX provision defaults missing fragment %q", want)
		}
	}
	forbidden := []string{
		`return { transportProfile: "performance", datapath: "auto", encryption: "secure", cryptoPlacement: "auto", kernelTransport: "auto" };`,
		`return { transportProfile: "performance", datapath: "kernel_module", encryption: "plaintext", cryptoPlacement: "auto", kernelTransport: "auto" };`,
		`crypto_placement: "auto",`,
	}
	for _, bad := range forbidden {
		if strings.Contains(source, bad) {
			t.Fatalf("webui IX provision defaults still contain old fragment %q", bad)
		}
	}
}
