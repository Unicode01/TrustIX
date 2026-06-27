package scripts

import (
	"os"
	"regexp"
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
		`case "stable":
      return { transportProfile: "stable", datapath: "userspace", encryption: "secure", cryptoPlacement: "userspace", kernelTransport: "disabled" };`,
		`case "latency":
      return { transportProfile: "stable", datapath: "userspace", encryption: "secure", cryptoPlacement: "userspace", kernelTransport: "disabled" };`,
		`return { transportProfile: "performance", datapath: "tc_xdp", encryption: "secure", cryptoPlacement: "kernel", kernelTransport: "require_kernel" };`,
		`return { transportProfile: "performance", datapath: "kernel_module", encryption: "plaintext", cryptoPlacement: "userspace", kernelTransport: "require_kernel" };`,
		`crypto_placement: "userspace",`,
		`function ixProvisionDefaultEndpointTransport(profile: string, endpointMode = "passive", endpointAddress = "", serviceManager = "auto"): string`,
		`String(serviceManager || "").trim().toLowerCase().replaceAll("-", "_") === "openwrt"`,
		`ixProvisionDefaultEndpointTransport(input.profile, endpointMode, endpointAddress, input.serviceManager)`,
		`ixProvisionDefaultEndpointTransport(newIXProfile, newIXEndpointMode, newIXEndpointAddress, newIXServiceManager)`,
		`ixProvisionDefaultEndpointTransport(nextProfile, newIXEndpointMode, newIXEndpointAddress, nextServiceManager)`,
		`const { security, transport_profile: transportProfile, transport = "udp", ...rest } = options;`,
		`plaintextPerformanceEndpoint("local-udp",`,
		`plaintextPerformanceEndpoint(` + "`${id}-udp`" + `, { mode: "active", address: "" })`,
		`{ transport: "udp", profile: "performance", datapath: "kernel_module", encryption: "plaintext", crypto_placement: "userspace", advanced: {} }`,
		`plaintextPerformanceEndpoint(` + "`${selectedPeer.id || \"peer\"}-udp-${endpoints.length + 1}`" + `, { mode: "active", address: "" })`,
	}
	for _, want := range mustContain {
		if !strings.Contains(source, want) {
			t.Fatalf("webui IX provision defaults missing fragment %q", want)
		}
	}
	forbidden := []string{
		`case "stable":
      return { transportProfile: "stable", datapath: "auto", encryption: "secure", cryptoPlacement: "auto", kernelTransport: "auto" };`,
		`default:
      return { transportProfile: "stable", datapath: "auto", encryption: "secure", cryptoPlacement: "auto", kernelTransport: "auto" };`,
		`case "latency":
      return { transportProfile: "latency", datapath: "auto", encryption: "secure", cryptoPlacement: "auto", kernelTransport: "auto" };`,
		`return { transportProfile: "performance", datapath: "auto", encryption: "secure", cryptoPlacement: "auto", kernelTransport: "auto" };`,
		`return { transportProfile: "performance", datapath: "kernel_module", encryption: "plaintext", cryptoPlacement: "auto", kernelTransport: "auto" };`,
		`crypto_placement: "auto",`,
		`plaintextPerformanceEndpoint("local-experimental_tcp",`,
		`plaintextPerformanceEndpoint(` + "`${id}-experimental_tcp`" + `, { mode: "active", address: "" })`,
		`{ transport: "experimental_tcp", profile: "performance", datapath: "auto", advanced: {} }`,
		`plaintextPerformanceEndpoint(` + "`${selectedPeer.id || \"peer\"}-experimental_tcp-${endpoints.length + 1}`" + `, { mode: "active", address: "" })`,
	}
	for _, bad := range forbidden {
		if strings.Contains(source, bad) {
			t.Fatalf("webui IX provision defaults still contain old fragment %q", bad)
		}
	}
}

func TestWebUIIXProvisionProfileDefaultsArePinnedByProfile(t *testing.T) {
	payload, err := os.ReadFile("../webui/src/components.tsx")
	if err != nil {
		t.Fatalf("read webui components: %v", err)
	}
	source := string(payload)
	if got := parseWebUIStringArray(t, source, "newIXProfileOptions"); strings.Join(got, ",") != "stable,performance,latency,compatibility,plaintext_performance" {
		t.Fatalf("newIXProfileOptions = %#v", got)
	}

	defaults := parseWebUIIXProvisionProfileDefaults(t, source)
	expected := map[string]map[string]string{
		"stable": {
			"transportProfile": "stable",
			"datapath":         "userspace",
			"encryption":       "secure",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "disabled",
		},
		"latency": {
			"transportProfile": "stable",
			"datapath":         "userspace",
			"encryption":       "secure",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "disabled",
		},
		"compatibility": {
			"transportProfile": "stable",
			"datapath":         "userspace",
			"encryption":       "secure",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "disabled",
		},
		"compat": {
			"transportProfile": "stable",
			"datapath":         "userspace",
			"encryption":       "secure",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "disabled",
		},
		"compatible": {
			"transportProfile": "stable",
			"datapath":         "userspace",
			"encryption":       "secure",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "disabled",
		},
		"performance": {
			"transportProfile": "performance",
			"datapath":         "tc_xdp",
			"encryption":       "secure",
			"cryptoPlacement":  "kernel",
			"kernelTransport":  "require_kernel",
		},
		"plaintext_performance": {
			"transportProfile": "performance",
			"datapath":         "kernel_module",
			"encryption":       "plaintext",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "require_kernel",
		},
		"plaintext-performance": {
			"transportProfile": "performance",
			"datapath":         "kernel_module",
			"encryption":       "plaintext",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "require_kernel",
		},
		"plaintext": {
			"transportProfile": "performance",
			"datapath":         "kernel_module",
			"encryption":       "plaintext",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "require_kernel",
		},
		"plain": {
			"transportProfile": "performance",
			"datapath":         "kernel_module",
			"encryption":       "plaintext",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "require_kernel",
		},
		"default": {
			"transportProfile": "stable",
			"datapath":         "userspace",
			"encryption":       "secure",
			"cryptoPlacement":  "userspace",
			"kernelTransport":  "disabled",
		},
	}
	for name, want := range expected {
		got, ok := defaults[name]
		if !ok {
			t.Fatalf("webui profile %q missing from ixProvisionProfileDefaults; parsed=%#v", name, defaults)
		}
		assertWebUIStringMap(t, "profile "+name, got, want)
	}
	for name, got := range defaults {
		if _, ok := expected[name]; !ok {
			t.Fatalf("webui profile %q is not covered by pinned-default expectations: %#v", name, got)
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

func parseWebUIStringArray(t *testing.T, source, name string) []string {
	t.Helper()
	re := regexp.MustCompile(`const\s+` + regexp.QuoteMeta(name) + `\s*=\s*\[([^\]]*)\];`)
	matches := re.FindStringSubmatch(source)
	if len(matches) != 2 {
		t.Fatalf("webui string array %s not found", name)
	}
	itemRE := regexp.MustCompile(`"([^"]+)"`)
	var out []string
	for _, item := range itemRE.FindAllStringSubmatch(matches[1], -1) {
		out = append(out, item[1])
	}
	return out
}

func parseWebUIIXProvisionProfileDefaults(t *testing.T, source string) map[string]map[string]string {
	t.Helper()
	start := strings.Index(source, "function ixProvisionProfileDefaults")
	end := strings.Index(source, "\nfunction normalizeIXProvisionProfileName")
	if start < 0 || end <= start {
		t.Fatalf("ixProvisionProfileDefaults function body not found")
	}
	body := source[start:end]
	caseRE := regexp.MustCompile(`^case\s+"([^"]+)":$`)
	returnRE := regexp.MustCompile(`return\s+\{([^}]*)\};`)
	defaults := map[string]map[string]string{}
	var pending []string
	for _, rawLine := range strings.Split(body, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "default:" {
			pending = append(pending, "default")
			continue
		}
		if matches := caseRE.FindStringSubmatch(line); len(matches) == 2 {
			pending = append(pending, matches[1])
			continue
		}
		matches := returnRE.FindStringSubmatch(line)
		if len(matches) != 2 {
			continue
		}
		if len(pending) == 0 {
			t.Fatalf("return object in ixProvisionProfileDefaults has no pending cases: %s", line)
		}
		object := parseWebUIStringObject(matches[1])
		for _, name := range pending {
			defaults[name] = object
		}
		pending = nil
	}
	if len(pending) != 0 {
		t.Fatalf("ixProvisionProfileDefaults cases without return: %#v", pending)
	}
	return defaults
}

func parseWebUIStringObject(raw string) map[string]string {
	fieldRE := regexp.MustCompile(`([A-Za-z0-9_]+)\s*:\s*"([^"]*)"`)
	out := map[string]string{}
	for _, match := range fieldRE.FindAllStringSubmatch(raw, -1) {
		out[match[1]] = match[2]
	}
	return out
}

func assertWebUIStringMap(t *testing.T, label string, got, want map[string]string) {
	t.Helper()
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Fatalf("%s field %s = %q, want %q; object=%#v", label, key, got[key], wantValue, got)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Fatalf("%s has unexpected field %s in object %#v", label, key, got)
		}
	}
}

func TestWebUITopologyQuickPeerUsesPinnedPlaintextFullKmodDefault(t *testing.T) {
	payload, err := os.ReadFile("../webui/src/main.tsx")
	if err != nil {
		t.Fatalf("read webui main: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		`name: ` + "`${nextID}-udp`" + `,`,
		`transport: "udp",`,
		`encryption: "plaintext",`,
		`transport_profile: {`,
		`profile: "performance",`,
		`datapath: "kernel_module",`,
		`crypto_placement: "userspace",`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("webui topology quick peer default missing fragment %q", want)
		}
	}
	if strings.Contains(source, `security: {},`) {
		t.Fatal("webui topology quick peer still creates an endpoint without explicit plaintext security/profile defaults")
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
