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

func TestWebUITitleIncludesCurrentIXID(t *testing.T) {
	payload, err := os.ReadFile("../webui/src/main.tsx")
	if err != nil {
		t.Fatalf("read webui main: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		`const documentTitleIX = status?.ix_id || desired?.ix?.id || "";`,
		`document.title = documentTitleIX ? ` + "`TrustIX - ${documentTitleIX}`" + ` : "TrustIX";`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("webui dynamic title missing fragment %q", want)
		}
	}
}

func TestWebUIEndpointEditorUsesStableKeys(t *testing.T) {
	payload, err := os.ReadFile("../webui/src/components.tsx")
	if err != nil {
		t.Fatalf("read webui components: %v", err)
	}
	source := string(payload)
	mustContain := []string{
		`{props.endpoints.map((endpoint, index) => (`,
		`<button key={index} type="button" className={` + "`config-list-row ${index === selectedIndex ? \"is-selected\" : \"\"}`" + `} onClick={() => setSelectedIndex(index)}>`,
		`<EndpointConfigFields t={props.t} scope="peer" endpoint={selectedEndpoint} onUpdate={(endpoint) => props.onUpdate(selectedIndex, endpoint)} />`,
	}
	for _, want := range mustContain {
		if !strings.Contains(source, want) {
			t.Fatalf("webui endpoint editor stable-key guard missing fragment %q", want)
		}
	}
	forbidden := []string{
		"<button key={`${endpoint.name}-${index}`} type=\"button\" className={`config-list-row ${index === selectedIndex ? \"is-selected\" : \"\"}`",
		"<ConfigEndpointCard\n              key={`${endpoint.name}-${index}`}",
	}
	for _, bad := range forbidden {
		if strings.Contains(source, bad) {
			t.Fatalf("webui endpoint editor still uses mutable endpoint name as React key: %q", bad)
		}
	}
}
