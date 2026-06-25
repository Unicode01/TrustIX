package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func readProductionTransportDefaults(t *testing.T) string {
	t.Helper()
	rows := loadProductionTransportDefaults(t)
	var packed []string
	for _, row := range rows {
		packed = append(packed, strings.Join([]string{
			row.Transport,
			row.Encryption,
			row.Profile,
			row.Datapath,
			row.CryptoPlacement,
			row.ValidationScope,
			row.GateFamily,
			row.MinGbps,
			row.MinSeconds,
		}, ":"))
	}
	return strings.Join(packed, "\n")
}

type productionTransportDefault struct {
	Transport       string
	Encryption      string
	Profile         string
	Datapath        string
	CryptoPlacement string
	ValidationScope string
	GateFamily      string
	MinGbps         string
	MinSeconds      string
}

type productionTransportEvidence struct {
	GateFamily           string
	Transport            string
	Encryption           string
	Profile              string
	Datapath             string
	CryptoPlacement      string
	ValidationScope      string
	OSMatrix             string
	KernelMatrix         string
	Result               string
	MinGbps              string
	MinSeconds           string
	GateManifestSchema   string
	ProductionGateSHA256 string
	VerifierSHA256       string
	Artifact             string
	Note                 string
}

const (
	productionGateManifestSchema      = "trustix-cross-host-production-gate-manifest-v1"
	legacyProductionGateManifestValue = "legacy-pre-manifest"
)

func loadProductionTransportDefaults(t *testing.T) []productionTransportDefault {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(".", "production-transport-defaults.tsv"))
	if err != nil {
		t.Fatalf("read production-transport-defaults.tsv: %v", err)
	}
	var rows []productionTransportDefault
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 9 {
			t.Fatalf("invalid production default row %q", line)
		}
		rows = append(rows, productionTransportDefault{
			Transport:       fields[0],
			Encryption:      fields[1],
			Profile:         fields[2],
			Datapath:        fields[3],
			CryptoPlacement: fields[4],
			ValidationScope: fields[5],
			GateFamily:      fields[6],
			MinGbps:         fields[7],
			MinSeconds:      fields[8],
		})
	}
	return rows
}

func loadProductionTransportEvidence(t *testing.T) []productionTransportEvidence {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(".", "production-transport-evidence.tsv"))
	if err != nil {
		t.Fatalf("read production-transport-evidence.tsv: %v", err)
	}
	var rows []productionTransportEvidence
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 17 {
			t.Fatalf("invalid production evidence row %q", line)
		}
		rows = append(rows, productionTransportEvidence{
			GateFamily:           fields[0],
			Transport:            fields[1],
			Encryption:           fields[2],
			Profile:              fields[3],
			Datapath:             fields[4],
			CryptoPlacement:      fields[5],
			ValidationScope:      fields[6],
			OSMatrix:             fields[7],
			KernelMatrix:         fields[8],
			Result:               fields[9],
			MinGbps:              fields[10],
			MinSeconds:           fields[11],
			GateManifestSchema:   fields[12],
			ProductionGateSHA256: fields[13],
			VerifierSHA256:       fields[14],
			Artifact:             fields[15],
			Note:                 strings.Join(fields[16:], "\t"),
		})
	}
	return rows
}

func productionDefaultEvidenceKey(row productionTransportDefault) string {
	return strings.Join([]string{
		row.Transport,
		row.Encryption,
		row.Profile,
		row.Datapath,
		row.CryptoPlacement,
		row.ValidationScope,
		row.GateFamily,
	}, ":")
}

func productionEvidenceKey(row productionTransportEvidence) string {
	return strings.Join([]string{
		row.Transport,
		row.Encryption,
		row.Profile,
		row.Datapath,
		row.CryptoPlacement,
		row.ValidationScope,
		row.GateFamily,
	}, ":")
}

func productionGateFamilyClass(gateFamily string) string {
	switch gateFamily {
	case "full_kmod", "dd_full_kmod", "owdeb_full_kmod":
		return "full_kmod"
	case "secure_kudp", "dd_secure_kudp", "owdeb_secure_kudp":
		return "secure_kudp"
	case "secure_exp_tcp_kernel", "dd_secure_exp_tcp_kernel", "owdeb_secure_exp_tcp_kernel":
		return "secure_exp_tcp_kernel"
	case "route_gso", "dd_route_gso", "owdeb_route_gso":
		return "route_gso"
	default:
		return gateFamily
	}
}

func assertProductionGateFamilySemantics(t *testing.T, label, transport, encryption, datapath, placement, gateFamily string) {
	t.Helper()
	require := func(field, got, want string) {
		t.Helper()
		if got != want {
			t.Fatalf("%s gate_family=%s requires %s=%s, got %s=%s", label, gateFamily, field, want, field, got)
		}
	}
	requireTransport := func(allowed ...string) {
		t.Helper()
		for _, value := range allowed {
			if transport == value {
				return
			}
		}
		t.Fatalf("%s gate_family=%s does not allow transport=%s", label, gateFamily, transport)
	}

	switch productionGateFamilyClass(gateFamily) {
	case "userspace":
		requireTransport("udp", "tcp", "quic", "websocket", "http_connect", "experimental_tcp")
		require("datapath", datapath, "userspace")
		require("crypto_placement", placement, "userspace")
	case "userspace_tc":
		requireTransport("gre", "ipip", "vxlan")
		require("datapath", datapath, "tc_xdp")
		require("crypto_placement", placement, "userspace")
	case "tc_direct":
		require("transport", transport, "kernel_udp")
		require("encryption", encryption, "plaintext")
		require("datapath", datapath, "tc_xdp")
		require("crypto_placement", placement, "userspace")
	case "full_kmod":
		require("transport", transport, "udp")
		require("encryption", encryption, "plaintext")
		require("datapath", datapath, "kernel_module")
		require("crypto_placement", placement, "userspace")
	case "secure_kudp":
		require("transport", transport, "kernel_udp")
		require("encryption", encryption, "secure")
		require("datapath", datapath, "tc_xdp")
		require("crypto_placement", placement, "kernel")
	case "secure_exp_tcp_kernel":
		require("transport", transport, "experimental_tcp")
		require("encryption", encryption, "secure")
		require("datapath", datapath, "kernel_module")
		require("crypto_placement", placement, "kernel")
	case "route_gso":
		require("transport", transport, "experimental_tcp")
		require("encryption", encryption, "plaintext")
		require("datapath", datapath, "kernel_module")
		require("crypto_placement", placement, "userspace")
	default:
		t.Fatalf("%s has unknown production gate family %q", label, gateFamily)
	}
}

func knownLegacyProductionEvidenceArtifacts() map[string]bool {
	return map[string]bool{
		"docs/trustix-performance-log.md#2026-06-19-zaozhuang-pve-selected-transport-matrix-gate":               true,
		"docs/trustix-performance-log.md#2026-06-20-zaozhuang-pve-compatibility-900s-strict-gate":               true,
		"docs/trustix-performance-log.md#2026-06-20-zaozhuang-pve-gre-p4-900s-strict-gate":                      true,
		"docs/trustix-performance-log.md#2026-06-20-zaozhuang-pve-ipip-vxlan-p4-900s-strict-gates":              true,
		"docs/trustix-performance-log.md#2026-06-20-zaozhuang-pve-secure-tunnel-userspace-tc-900s-strict-gates": true,
		"docs/trustix-performance-log.md#2026-06-21-zaozhuang-pve-userspace-gap-900s-strict-gates":              true,
		"docs/trustix-performance-log.md#debian-full-kmod-current-head-production-recheck":                      true,
		"docs/trustix-performance-log.md#debian-route-gso-current-head-production-recheck":                      true,
		"docs/trustix-performance-log.md#debian-secure-kudp-current-head-production-recheck":                    true,
		"docs/trustix-performance-log.md#debian-tc-direct-current-head-production-recheck":                      true,
		"docs/trustix-performance-log.md#debian-userspace-current-head-production-gates":                        true,
		"docs/trustix-performance-log.md#debian-userspace-tc-current-head-production-gates":                     true,
		"docs/trustix-performance-log.md#openwrt-24102-full-kmod-production-gate":                               true,
		"docs/trustix-performance-log.md#openwrt-24107-runtime-capability-check":                                true,
		"docs/trustix-performance-log.md#2026-06-24-zaozhuang-pve-openwrt-25124-route-gso-runtime-check":        true,
	}
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func validateProductionEvidenceManifestIdentity(t *testing.T, evidence productionTransportEvidence) {
	t.Helper()
	if evidence.GateManifestSchema == "" ||
		evidence.ProductionGateSHA256 == "" ||
		evidence.VerifierSHA256 == "" {
		t.Fatalf("production evidence row lacks manifest identity: %+v", evidence)
	}
	if evidence.GateManifestSchema == legacyProductionGateManifestValue {
		if evidence.ProductionGateSHA256 != legacyProductionGateManifestValue ||
			evidence.VerifierSHA256 != legacyProductionGateManifestValue {
			t.Fatalf("legacy production evidence must mark all manifest identity fields as %q: %+v", legacyProductionGateManifestValue, evidence)
		}
		if !knownLegacyProductionEvidenceArtifacts()[evidence.Artifact] {
			t.Fatalf("legacy production evidence artifact is not allowlisted; rerun with production-gate-manifest.json instead: %+v", evidence)
		}
		return
	}
	if evidence.GateManifestSchema != productionGateManifestSchema {
		t.Fatalf("production evidence has unknown gate manifest schema %q in %+v", evidence.GateManifestSchema, evidence)
	}
	if !isSHA256Hex(evidence.ProductionGateSHA256) {
		t.Fatalf("production evidence has invalid production gate SHA256 %q in %+v", evidence.ProductionGateSHA256, evidence)
	}
	if !isSHA256Hex(evidence.VerifierSHA256) {
		t.Fatalf("production evidence has invalid verifier SHA256 %q in %+v", evidence.VerifierSHA256, evidence)
	}
}

type currentProductionEvidenceRequirement struct {
	OSMatrix           string
	KernelMatrix       string
	Artifact           string
	GateManifestSchema string
}

func currentProductionEvidenceRequirementForDefault(row productionTransportDefault) (currentProductionEvidenceRequirement, bool) {
	if row.ValidationScope != "cross_host" {
		return currentProductionEvidenceRequirement{}, false
	}
	switch row.GateFamily {
	case "userspace":
		if row.Datapath != "userspace" || row.CryptoPlacement != "userspace" {
			return currentProductionEvidenceRequirement{}, false
		}
		return currentProductionEvidenceRequirement{
			OSMatrix:           "debian13-debian13",
			KernelMatrix:       "6.12.69+deb13-amd64_to_6.12.69+deb13-amd64",
			Artifact:           "docs/trustix-performance-log.md#2026-06-23-zaozhuang-pve-userspace-userspace-tc-3600s-production-gates",
			GateManifestSchema: productionGateManifestSchema,
		}, true
	case "userspace_tc":
		if row.Datapath != "tc_xdp" || row.CryptoPlacement != "userspace" {
			return currentProductionEvidenceRequirement{}, false
		}
		return currentProductionEvidenceRequirement{
			OSMatrix:           "debian13-debian13",
			KernelMatrix:       "6.12.69+deb13-amd64_to_6.12.69+deb13-amd64",
			Artifact:           "docs/trustix-performance-log.md#2026-06-23-zaozhuang-pve-userspace-userspace-tc-3600s-production-gates",
			GateManifestSchema: productionGateManifestSchema,
		}, true
	case "tc_direct":
		return currentProductionEvidenceRequirement{
			OSMatrix:           "debian13-debian13",
			KernelMatrix:       "6.12.94+deb13-cloud-amd64_to_6.12.94+deb13-cloud-amd64",
			Artifact:           "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-tc-direct-secure-kudp-3600s-ratio-gates",
			GateManifestSchema: productionGateManifestSchema,
		}, true
	case "full_kmod":
		return currentProductionEvidenceRequirement{
			OSMatrix:           "debian13-debian13",
			KernelMatrix:       "6.12.94+deb13-amd64_to_6.12.94+deb13-amd64",
			Artifact:           "docs/trustix-performance-log.md#2026-06-23-zaozhuang-pve-current-head-full-kmod-3600s-production-gates",
			GateManifestSchema: productionGateManifestSchema,
		}, true
	case "owdeb_full_kmod":
		return currentProductionEvidenceRequirement{
			OSMatrix:           "openwrt24.10.7-debian13",
			KernelMatrix:       "6.6.141_to_6.12.94+deb13-cloud-amd64",
			Artifact:           "docs/trustix-performance-log.md#2026-06-25-zaozhuang-pve-openwrt-24107-current-head-full-kmod-3600s-production-gate",
			GateManifestSchema: productionGateManifestSchema,
		}, true
	case "secure_kudp":
		return currentProductionEvidenceRequirement{
			OSMatrix:           "debian13-debian13",
			KernelMatrix:       "6.12.94+deb13-cloud-amd64_to_6.12.94+deb13-cloud-amd64",
			Artifact:           "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-tc-direct-secure-kudp-3600s-ratio-gates",
			GateManifestSchema: productionGateManifestSchema,
		}, true
	case "route_gso":
		return currentProductionEvidenceRequirement{
			OSMatrix:           "debian13-debian13",
			KernelMatrix:       "6.12.94+deb13-cloud-amd64_to_6.12.94+deb13-cloud-amd64",
			Artifact:           "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-route-gso-3600s-production-gate",
			GateManifestSchema: productionGateManifestSchema,
		}, true
	case "secure_exp_tcp_kernel":
		return currentProductionEvidenceRequirement{
			OSMatrix:           "debian13-debian13",
			KernelMatrix:       "6.12.90+deb13.1-cloud-amd64_to_6.12.90+deb13.1-cloud-amd64",
			Artifact:           "docs/trustix-performance-log.md#2026-06-25-zaozhuang-pve-secure-exp-tcp-kernel-fpu-fallback-3600s-production-gate",
			GateManifestSchema: productionGateManifestSchema,
		}, true
	default:
		return currentProductionEvidenceRequirement{}, false
	}
}

func markdownHeadingAnchor(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#") {
		return "", false
	}
	hashes := 0
	for hashes < len(line) && line[hashes] == '#' {
		hashes++
	}
	if hashes == 0 || hashes >= len(line) || line[hashes] != ' ' {
		return "", false
	}
	title := strings.TrimSpace(line[hashes:])
	title = strings.TrimSpace(strings.TrimRight(title, "#"))
	title = strings.ToLower(title)
	var slug strings.Builder
	for _, r := range title {
		switch {
		case r >= 'a' && r <= 'z':
			slug.WriteRune(r)
		case r >= '0' && r <= '9':
			slug.WriteRune(r)
		case r == ' ' || r == '\t':
			slug.WriteByte('-')
		case r == '-' || r == '_':
			slug.WriteRune(r)
		}
	}
	anchor := slug.String()
	return anchor, anchor != ""
}

func htmlAnchorIDs(line string) []string {
	var anchors []string
	for _, marker := range []string{`id="`, `name="`, `id='`, `name='`} {
		quote := marker[len(marker)-1]
		offset := 0
		for {
			idx := strings.Index(line[offset:], marker)
			if idx < 0 {
				break
			}
			start := offset + idx + len(marker)
			end := strings.IndexByte(line[start:], quote)
			if end < 0 {
				break
			}
			if anchor := line[start : start+end]; anchor != "" {
				anchors = append(anchors, anchor)
			}
			offset = start + end + 1
		}
	}
	return anchors
}

func loadDocumentAnchors(t *testing.T, path string) map[string]bool {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read document %s: %v", path, err)
	}
	anchors := map[string]bool{}
	headingCounts := map[string]int{}
	for _, line := range strings.Split(string(payload), "\n") {
		if base, ok := markdownHeadingAnchor(line); ok {
			count := headingCounts[base]
			anchor := base
			if count > 0 {
				anchor = base + "-" + strconv.Itoa(count)
			}
			headingCounts[base] = count + 1
			anchors[anchor] = true
		}
		for _, anchor := range htmlAnchorIDs(line) {
			anchors[anchor] = true
		}
	}
	return anchors
}

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
			defaults := readProductionTransportDefaults(t)
			for _, wantCase := range []string{
				"udp:secure:stable:userspace:userspace:cross_host:userspace:1.5:3600",
				"udp:plaintext:stable:userspace:userspace:cross_host:userspace:1.5:3600",
				"udp:plaintext:performance:kernel_module:userspace:cross_host:full_kmod:3:3600",
				"udp:plaintext:performance:kernel_module:userspace:cross_host:owdeb_full_kmod:3:3600",
				"tcp:secure:stable:userspace:userspace:cross_host:userspace:0.75:3600",
				"tcp:plaintext:stable:userspace:userspace:cross_host:userspace:1:3600",
				"quic:secure:stable:userspace:userspace:cross_host:userspace:0.75:3600",
				"quic:plaintext:stable:userspace:userspace:cross_host:userspace:1:3600",
				"websocket:secure:stable:userspace:userspace:cross_host:userspace:0.5:3600",
				"websocket:plaintext:stable:userspace:userspace:cross_host:userspace:1:3600",
				"http_connect:secure:stable:userspace:userspace:cross_host:userspace:0.75:3600",
				"http_connect:plaintext:stable:userspace:userspace:cross_host:userspace:1:3600",
				"gre:secure:stable:tc_xdp:userspace:cross_host:userspace_tc:1:3600",
				"gre:plaintext:performance:tc_xdp:userspace:cross_host:userspace_tc:4:3600",
				"ipip:secure:stable:tc_xdp:userspace:cross_host:userspace_tc:1:3600",
				"ipip:plaintext:performance:tc_xdp:userspace:cross_host:userspace_tc:4:3600",
				"vxlan:secure:stable:tc_xdp:userspace:cross_host:userspace_tc:1:3600",
				"vxlan:plaintext:performance:tc_xdp:userspace:cross_host:userspace_tc:4:3600",
				"kernel_udp:plaintext:performance:tc_xdp:userspace:cross_host:tc_direct:3:3600",
				"kernel_udp:secure:performance:tc_xdp:kernel:cross_host:secure_kudp:1.5:3600",
				"experimental_tcp:plaintext:performance:kernel_module:userspace:cross_host:route_gso:2.5:3600",
				"experimental_tcp:secure:stable:userspace:userspace:single_host:userspace:0:30",
				"experimental_tcp:secure:stable:userspace:userspace:cross_host:userspace:1:3600",
				"experimental_tcp:secure:performance:kernel_module:kernel:cross_host:secure_exp_tcp_kernel:1.5:3600",
				"experimental_tcp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
			} {
				if !strings.Contains(defaults, wantCase) {
					t.Fatalf("production defaults missing %q", wantCase)
				}
			}
			for _, unwanted := range []string{
				"kernel_udp:secure:stable:tc_xdp:userspace",
			} {
				if strings.Contains(defaults, unwanted) {
					t.Fatalf("production defaults still include slow/unselected combo %q", unwanted)
				}
			}
		})
	}
}

func TestProductionTransportMatrixDefaults(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-production-transport-matrix.sh"))
	if err != nil {
		t.Fatalf("read linux-production-transport-matrix.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_PERF_FAST:-1",
		"defaults_file=\"${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_DEFAULTS:-${repo_root}/scripts/production-transport-defaults.tsv}\"",
		"matrix_scope=\"${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SCOPE:-single_host}\"",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASE_TIMEOUT",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_IOCTL_SELFTEST:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_VERIFY_SAFE_DEFAULTS:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_FULL_DATAPATH:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_ROUTE_GSO:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_MIN_GBPS:-3",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_ROUTE_GSO_MIN_GBPS:-2.5",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_AF_XDP_TX_BACKPRESSURE_WAIT:-50ms",
		"TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT",
		"awk -v scope=\"$matrix_scope\" -F '\\t'",
		"scope != \"all\" && $6 != scope { next }",
		"key = $1 SUBSEP $2 SUBSEP $3 SUBSEP $4 SUBSEP $5",
		"if (seen[key]++) next",
		"print $1, $2, $3, $4, $5, $8, $9",
		"single_host|cross_host|all)",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SCOPE must be single_host, cross_host, or all",
		"case_iperf3_seconds=\"${default_seconds:-$iperf3_seconds}\"",
		"export TRUSTIX_E2E_IPERF3_SECONDS=\"$case_iperf3_seconds\"",
		"rx_worker_xmit=1",
		"rx_worker_single_coalesce=1",
		"rx_worker_single_coalesce_max_frames=32",
		"tx_plaintext_skip_inner_tcp_checksum=0",
		"production defaults file not found",
		"invalid production defaults row",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-production-transport-matrix.sh production defaults missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"rx_worker_single_coalesce=0",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-production-transport-matrix.sh production defaults still include %q", unwanted)
		}
	}
}

func TestProductionTransportMatrixSingleHostScopeCannotSelectCrossHostOnlyGates(t *testing.T) {
	rows := loadProductionTransportDefaults(t)
	crossHostOnlyGate := map[string]bool{
		"full_kmod":       true,
		"owdeb_full_kmod": true,
		"secure_kudp":     true,
		"route_gso":       true,
	}
	forbiddenFastPathKey := map[string]bool{
		"udp:plaintext:performance:kernel_module:userspace":              true,
		"kernel_udp:secure:performance:tc_xdp:kernel":                    true,
		"experimental_tcp:plaintext:performance:kernel_module:userspace": true,
		"experimental_tcp:secure:performance:kernel_module:kernel":       true,
		"experimental_tcp:secure:performance:kernel_module:userspace":    true,
		"experimental_tcp:plaintext:performance:tc_xdp:userspace":        true,
		"experimental_tcp:secure:performance:tc_xdp:kernel":              true,
		"experimental_tcp:secure:performance:tc_xdp:userspace":           true,
		"kernel_udp:plaintext:performance:kernel_module:userspace":       true,
		"kernel_udp:plaintext:performance:kernel_module:kernel":          true,
		"kernel_udp:secure:performance:kernel_module:kernel":             true,
		"kernel_udp:secure:performance:kernel_module:userspace":          true,
	}
	selected := map[string]productionTransportDefault{}
	for _, row := range rows {
		if row.ValidationScope != "single_host" {
			continue
		}
		key := strings.Join([]string{
			row.Transport,
			row.Encryption,
			row.Profile,
			row.Datapath,
			row.CryptoPlacement,
		}, ":")
		if _, seen := selected[key]; seen {
			continue
		}
		selected[key] = row
	}
	if len(selected) == 0 {
		t.Fatalf("single-host production matrix scope selected no defaults")
	}
	for key, row := range selected {
		if crossHostOnlyGate[row.GateFamily] {
			t.Fatalf("single-host production matrix default selected cross-host-only gate %s: %+v", key, row)
		}
		if forbiddenFastPathKey[key] {
			t.Fatalf("single-host production matrix default selected cross-host fast path %s: %+v", key, row)
		}
		if row.MinGbps != "0" || row.MinSeconds != "30" {
			t.Fatalf("single-host production matrix default should remain a smoke gate, got %+v", row)
		}
	}
	for key := range forbiddenFastPathKey {
		if _, exists := selected[key]; exists {
			t.Fatalf("single-host production matrix default unexpectedly selected %s", key)
		}
	}
}

func TestCrossHostProductionDefaultsHavePassingEvidence(t *testing.T) {
	defaults := loadProductionTransportDefaults(t)
	evidenceRows := loadProductionTransportEvidence(t)
	evidenceByKey := map[string][]productionTransportEvidence{}
	seenEvidence := map[string]bool{}
	for _, evidence := range evidenceRows {
		key := productionEvidenceKey(evidence)
		identity := strings.Join([]string{
			key,
			evidence.OSMatrix,
			evidence.KernelMatrix,
			evidence.Result,
			evidence.GateManifestSchema,
			evidence.ProductionGateSHA256,
			evidence.VerifierSHA256,
			evidence.Artifact,
		}, ":")
		if seenEvidence[identity] {
			t.Fatalf("duplicate production evidence row %q", identity)
		}
		seenEvidence[identity] = true
		validateProductionEvidenceManifestIdentity(t, evidence)
		assertProductionGateFamilySemantics(
			t,
			"production evidence "+key,
			evidence.Transport,
			evidence.Encryption,
			evidence.Datapath,
			evidence.CryptoPlacement,
			evidence.GateFamily,
		)
		if evidence.Artifact == "" {
			t.Fatalf("production evidence row lacks artifact: %+v", evidence)
		}
		switch evidence.Result {
		case "pass", "fail", "fail_closed":
		default:
			t.Fatalf("unknown production evidence result %q in %+v", evidence.Result, evidence)
		}
		evidenceMinGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil || evidenceMinGbps < 0 {
			t.Fatalf("invalid production evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceMinSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil || evidenceMinSeconds <= 0 {
			t.Fatalf("invalid production evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		evidenceByKey[key] = append(evidenceByKey[key], evidence)
	}
	for _, row := range defaults {
		if row.ValidationScope != "cross_host" {
			continue
		}
		minGbps, err := strconv.ParseFloat(row.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid production default min_gbps %q in %+v", row.MinGbps, row)
		}
		minSeconds, err := strconv.Atoi(row.MinSeconds)
		if err != nil {
			t.Fatalf("invalid production default min_seconds %q in %+v", row.MinSeconds, row)
		}
		key := productionDefaultEvidenceKey(row)
		var candidates []string
		found := false
		for _, evidence := range evidenceByKey[key] {
			evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
			if err != nil {
				t.Fatalf("invalid production evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
			}
			evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
			if err != nil {
				t.Fatalf("invalid production evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
			}
			candidates = append(candidates, strings.Join([]string{
				evidence.Result,
				evidence.MinGbps,
				evidence.MinSeconds,
				evidence.Artifact,
			}, " "))
			if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
				found = true
				break
			}
		}
		if found {
			continue
		}
		t.Fatalf("cross-host production default lacks passing evidence at or above gate %s: %+v; candidates=%v", key, row, candidates)
	}
}

func TestProductionEvidenceRequiresGateManifestIdentity(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "production-transport-evidence.tsv"))
	if err != nil {
		t.Fatalf("read production-transport-evidence.tsv: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"gate_manifest_schema",
		"production_gate_sha256",
		"verifier_sha256",
		productionGateManifestSchema,
		legacyProductionGateManifestValue,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("production evidence schema missing %q", want)
		}
	}
	for _, evidence := range loadProductionTransportEvidence(t) {
		validateProductionEvidenceManifestIdentity(t, evidence)
	}
}

func TestProductionEvidenceFromGateSummary(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	matrixSummary := filepath.Join(workdir, "summary.jsonl")
	gateSummaryDir := filepath.Join(workdir, "selected-production-gate")
	if err := os.MkdirAll(gateSummaryDir, 0o755); err != nil {
		t.Fatalf("create gate summary dir: %v", err)
	}
	matrixRow := map[string]any{
		"status":           "pass",
		"case":             "udp-secure-stable-userspace-userspace",
		"runner_case":      "userspace-udp-secure",
		"transport":        "udp",
		"encryption":       "secure",
		"profile":          "stable",
		"datapath":         "userspace",
		"crypto_placement": "userspace",
		"validation_scope": "cross_host",
		"gate_family":      "userspace",
		"min_gbps":         1.5,
		"min_seconds":      3600,
		"exit_code":        0,
		"workdir":          filepath.Join(workdir, "udp-secure-stable-userspace-userspace"),
	}
	matrixPayload, err := json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace",
		"path":                       filepath.Join(workdir, "udp-secure-stable-userspace-userspace"),
		"status":                     "pass",
		"min_gbps_required":          1.5,
		"min_seconds_required":       3600,
		"min_sent_gbps":              1.876543,
		"min_received_gbps":          1.765432,
		"min_required_received_gbps": 1.654321,
		"min_seconds":                3600.05,
		"seconds_slop":               0,
		"run_timing": []map[string]any{
			{
				"source":                  "run-timing.json",
				"iperf_mode":              "forward",
				"iperf_directions":        "both",
				"iperf_seconds_requested": 3600,
				"start_epoch":             1000,
				"end_epoch":               4600.05,
				"elapsed_seconds":         3600.05,
			},
		},
		"uname_artifacts": []map[string]any{
			{"node": "a", "phase": "before", "kernel_release": "6.12.90+deb13.1-amd64"},
			{"node": "a", "phase": "after", "kernel_release": "6.12.90+deb13.1-amd64"},
			{"node": "b", "phase": "before", "kernel_release": "6.12.90+deb13.1-amd64"},
			{"node": "b", "phase": "after", "kernel_release": "6.12.90+deb13.1-amd64"},
		},
		"os_release_artifacts": []map[string]any{
			{"node": "a", "phase": "before", "identity": "debian:13"},
			{"node": "a", "phase": "after", "identity": "debian:13"},
			{"node": "b", "phase": "before", "identity": "debian:13"},
			{"node": "b", "phase": "after", "identity": "debian:13"},
		},
		"boot_ids": []map[string]any{
			{"node": "a", "phase": "before", "boot_id": "boot-a"},
			{"node": "a", "phase": "after", "boot_id": "boot-a"},
			{"node": "b", "phase": "before", "boot_id": "boot-b"},
			{"node": "b", "phase": "after", "boot_id": "boot-b"},
		},
		"errors":                        []string{},
		"log_findings":                  []string{},
		"kernel_log_artifacts":          []string{"collect/a/kernel.log", "collect/b/kernel.log"},
		"kernel_log_nodes":              []string{"a", "b"},
		"kernel_log_rejected_artifacts": []string{},
		"pstore_artifacts":              []string{"collect/a/pstore.txt", "collect/b/pstore.txt"},
		"pstore_nodes":                  []string{"a", "b"},
		"pstore_rejected_artifacts":     []string{},
	}
	addProductionGatePassIperfCoverage(gateRow)
	gatePayload, err := json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write gate summary: %v", err)
	}
	manifest := map[string]any{
		"schema": productionGateManifestSchema,
		"production_gate": map[string]any{
			"path":   "scripts/linux-cross-host-production-gate.sh",
			"sha256": strings.Repeat("a", 64),
			"size":   123,
		},
		"verifier": map[string]any{
			"path":   "scripts/linux-cross-host-soak-verify.py",
			"sha256": strings.Repeat("b", 64),
			"size":   456,
		},
		"cases": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace")),
		},
		"case_min_gbps": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace=1.5",
		},
		"case_min_seconds": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace=3600",
		},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#example-production-gate",
		"--note-template", "{transport} {encryption} {gate_family} evidence",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production evidence generator failed: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one evidence row, got %d:\n%s", len(lines), output)
	}
	fields := strings.Split(lines[0], "\t")
	if len(fields) != 17 {
		t.Fatalf("expected 17 evidence fields, got %d:\n%s", len(fields), output)
	}
	wantFields := map[int]string{
		0:  "userspace",
		1:  "udp",
		2:  "secure",
		3:  "stable",
		4:  "userspace",
		5:  "userspace",
		6:  "cross_host",
		7:  "debian13-debian13",
		8:  "6.12.90+deb13.1-amd64_to_6.12.90+deb13.1-amd64",
		9:  "pass",
		10: "1.654321",
		11: "3600",
		12: productionGateManifestSchema,
		13: strings.Repeat("a", 64),
		14: strings.Repeat("b", 64),
		15: "docs/trustix-performance-log.md#example-production-gate",
		16: "udp secure userspace evidence",
	}
	for idx, want := range wantFields {
		if fields[idx] != want {
			t.Fatalf("field %d = %q, want %q\n%s", idx, fields[idx], want, output)
		}
	}

	strongBuildIdentities := gateRow["build_identities"]
	gateRow["build_identities"] = []map[string]any{
		{
			"source":     "collect/a/status.json",
			"version":    "trustix-test",
			"commit":     "unknown",
			"built_at":   "2026-06-25T00:00:00Z",
			"go_version": "go1.25.0",
			"goos":       "linux",
			"goarch":     "amd64",
			"strong":     false,
		},
		{
			"source":     "collect/b/status.json",
			"version":    "trustix-test",
			"commit":     "unknown",
			"built_at":   "2026-06-25T00:00:00Z",
			"go_version": "go1.25.0",
			"goos":       "linux",
			"goarch":     "amd64",
			"strong":     false,
		},
	}
	gatePayload, err = json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal weak-build gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write weak-build gate summary: %v", err)
	}
	weakBuildCmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#example-production-gate",
	)
	weakBuildCmd.Dir = "."
	weakBuildOutput, err := weakBuildCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted weak build identity:\n%s", weakBuildOutput)
	}
	if !strings.Contains(string(weakBuildOutput), "weak build identity") ||
		!strings.Contains(string(weakBuildOutput), "commit") {
		t.Fatalf("generator did not explain weak build identity:\n%s", weakBuildOutput)
	}
	gateRow["build_identities"] = strongBuildIdentities
	gatePayload, err = json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal strong-build gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("restore strong-build gate summary: %v", err)
	}

	runnerCase := "userspace-udp-secure"
	gateRow["case"] = runnerCase
	gatePayload, err = json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal runner-case gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write runner-case gate summary: %v", err)
	}
	manifest["cases"] = map[string]any{
		"userspace": runnerCase + "=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace")),
	}
	manifest["case_min_gbps"] = map[string]any{
		"userspace": runnerCase + "=1.5",
	}
	manifest["case_min_seconds"] = map[string]any{
		"userspace": runnerCase + "=3600",
	}
	manifestPayload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal runner-case manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write runner-case manifest: %v", err)
	}
	runnerCaseCmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#example-production-gate",
		"--note-template", "{transport} {encryption} {gate_family} evidence",
	)
	runnerCaseCmd.Dir = "."
	runnerCaseOutput, err := runnerCaseCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production evidence generator rejected runner-case gate summary: %v\n%s", err, runnerCaseOutput)
	}
	runnerCaseLines := strings.Split(strings.TrimSpace(string(runnerCaseOutput)), "\n")
	if len(runnerCaseLines) != 1 {
		t.Fatalf("expected one runner-case evidence row, got %d:\n%s", len(runnerCaseLines), runnerCaseOutput)
	}
	runnerCaseFields := strings.Split(runnerCaseLines[0], "\t")
	for idx, want := range wantFields {
		if runnerCaseFields[idx] != want {
			t.Fatalf("runner-case field %d = %q, want %q\n%s", idx, runnerCaseFields[idx], want, runnerCaseOutput)
		}
	}

	gateRow["case"] = "udp-secure-stable-userspace-userspace"
	gatePayload, err = json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal restored gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write restored gate summary: %v", err)
	}
	manifest["cases"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace")),
	}
	manifest["case_min_gbps"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace=1.5",
	}
	manifest["case_min_seconds"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace=3600",
	}
	manifestPayload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal restored manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write restored manifest: %v", err)
	}

	mismatchCmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--kernel-matrix", "6.6.141_to_6.12.90+deb13.1-amd64",
		"--artifact", "docs/trustix-performance-log.md#example-production-gate",
	)
	mismatchCmd.Dir = "."
	mismatchOutput, err := mismatchCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted mismatched kernel matrix override:\n%s", mismatchOutput)
	}
	if !strings.Contains(string(mismatchOutput), "kernel matrix override") ||
		!strings.Contains(string(mismatchOutput), "does not match inferred value") {
		t.Fatalf("generator did not explain kernel matrix mismatch:\n%s", mismatchOutput)
	}

	manifest["cases"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace=" + slashPath(filepath.Join(workdir, "wrong-evidence-dir")),
	}
	manifestPayload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest with mismatched path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest with mismatched path: %v", err)
	}
	pathMismatchCmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#example-production-gate",
	)
	pathMismatchCmd.Dir = "."
	pathMismatchOutput, err := pathMismatchCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted manifest path mismatch:\n%s", pathMismatchOutput)
	}
	if !strings.Contains(string(pathMismatchOutput), "cases.userspace") ||
		!strings.Contains(string(pathMismatchOutput), "does not match gate summary path") {
		t.Fatalf("generator did not explain manifest path mismatch:\n%s", pathMismatchOutput)
	}

	manifest["cases"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace")),
	}
	manifestPayload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal restored manifest path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write restored manifest path: %v", err)
	}
	matrixRow["workdir"] = filepath.Join(workdir, "wrong-matrix-dir")
	matrixPayload, err = json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal matrix row with mismatched workdir: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary with mismatched workdir: %v", err)
	}
	matrixPathMismatchCmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#example-production-gate",
	)
	matrixPathMismatchCmd.Dir = "."
	matrixPathMismatchOutput, err := matrixPathMismatchCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted matrix workdir mismatch:\n%s", matrixPathMismatchOutput)
	}
	if !strings.Contains(string(matrixPathMismatchOutput), "cases.userspace") ||
		!strings.Contains(string(matrixPathMismatchOutput), "does not match matrix summary workdir path") {
		t.Fatalf("generator did not explain matrix workdir mismatch:\n%s", matrixPathMismatchOutput)
	}
	matrixRow["workdir"] = filepath.Join(workdir, "udp-secure-stable-userspace-userspace")
	matrixPayload, err = json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal restored matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write restored matrix summary: %v", err)
	}

	manifest["case_min_gbps"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace=1.0",
	}
	manifestPayload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal mismatched manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write mismatched manifest: %v", err)
	}
	manifestMismatchCmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#example-production-gate",
	)
	manifestMismatchCmd.Dir = "."
	manifestMismatchOutput, err := manifestMismatchCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted manifest case_min_gbps below gate:\n%s", manifestMismatchOutput)
	}
	if !strings.Contains(string(manifestMismatchOutput), "case_min_gbps.userspace") ||
		!strings.Contains(string(manifestMismatchOutput), "below matrix requirement 1.500000") {
		t.Fatalf("generator did not explain manifest case_min_gbps mismatch:\n%s", manifestMismatchOutput)
	}
}

func TestProductionEvidenceFromGateSummaryRejectsMatrixGateMismatch(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	matrixSummary := filepath.Join(workdir, "summary.jsonl")
	gateSummaryDir := filepath.Join(workdir, "selected-production-gate")
	if err := os.MkdirAll(gateSummaryDir, 0o755); err != nil {
		t.Fatalf("create gate summary dir: %v", err)
	}
	matrixRow := map[string]any{
		"status":           "pass",
		"case":             "udp-secure-stable-userspace-userspace",
		"runner_case":      "userspace-udp-secure",
		"transport":        "udp",
		"encryption":       "secure",
		"profile":          "stable",
		"datapath":         "userspace",
		"crypto_placement": "userspace",
		"validation_scope": "cross_host",
		"gate_family":      "userspace",
		"min_gbps":         2.0,
		"min_seconds":      3600,
		"exit_code":        0,
		"workdir":          filepath.Join(workdir, "udp-secure-stable-userspace-userspace"),
	}
	matrixPayload, err := json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace",
		"path":                       filepath.Join(workdir, "udp-secure-stable-userspace-userspace"),
		"status":                     "pass",
		"min_gbps_required":          1.5,
		"min_seconds_required":       3600,
		"min_sent_gbps":              1.9,
		"min_received_gbps":          1.8,
		"min_required_received_gbps": 1.7,
		"min_seconds":                3600.1,
		"seconds_slop":               0,
		"run_timing": []map[string]any{
			{
				"source":                  "run-timing.json",
				"iperf_mode":              "forward",
				"iperf_directions":        "both",
				"iperf_seconds_requested": 3600,
				"start_epoch":             1000,
				"end_epoch":               4600.1,
				"elapsed_seconds":         3600.1,
			},
		},
		"uname_artifacts": []map[string]any{
			{"node": "a", "phase": "before", "kernel_release": "6.12.90+deb13.1-amd64"},
			{"node": "a", "phase": "after", "kernel_release": "6.12.90+deb13.1-amd64"},
			{"node": "b", "phase": "before", "kernel_release": "6.12.90+deb13.1-amd64"},
			{"node": "b", "phase": "after", "kernel_release": "6.12.90+deb13.1-amd64"},
		},
		"os_release_artifacts": []map[string]any{
			{"node": "a", "phase": "before", "identity": "debian:13"},
			{"node": "a", "phase": "after", "identity": "debian:13"},
			{"node": "b", "phase": "before", "identity": "debian:13"},
			{"node": "b", "phase": "after", "identity": "debian:13"},
		},
		"boot_ids": []map[string]any{
			{"node": "a", "phase": "before", "boot_id": "boot-a"},
			{"node": "a", "phase": "after", "boot_id": "boot-a"},
			{"node": "b", "phase": "before", "boot_id": "boot-b"},
			{"node": "b", "phase": "after", "boot_id": "boot-b"},
		},
		"errors":                        []string{},
		"log_findings":                  []string{},
		"kernel_log_artifacts":          []string{"collect/a/kernel.log", "collect/b/kernel.log"},
		"kernel_log_nodes":              []string{"a", "b"},
		"kernel_log_rejected_artifacts": []string{},
		"pstore_artifacts":              []string{"collect/a/pstore.txt", "collect/b/pstore.txt"},
		"pstore_nodes":                  []string{"a", "b"},
		"pstore_rejected_artifacts":     []string{},
	}
	addProductionGatePassIperfCoverage(gateRow)
	gatePayload, err := json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write gate summary: %v", err)
	}
	manifest := map[string]any{
		"schema": productionGateManifestSchema,
		"production_gate": map[string]any{
			"path":   "scripts/linux-cross-host-production-gate.sh",
			"sha256": strings.Repeat("a", 64),
			"size":   123,
		},
		"verifier": map[string]any{
			"path":   "scripts/linux-cross-host-soak-verify.py",
			"sha256": strings.Repeat("b", 64),
			"size":   456,
		},
		"cases": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace")),
		},
		"case_min_gbps": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace=1.5",
		},
		"case_min_seconds": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace=3600",
		},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#matrix-gate-mismatch",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted gate below matrix threshold:\n%s", output)
	}
	text := string(output)
	for _, want := range []string{
		"case_min_gbps.userspace",
		"below matrix requirement 2.000000",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("generator did not explain matrix/gate mismatch, missing %q:\n%s", want, output)
		}
	}
}

func TestProductionEvidenceFromGateSummaryRejectsMatrixSemanticMismatch(t *testing.T) {
	python := requirePython3(t)
	tests := []struct {
		name      string
		matrixRow map[string]any
		want      []string
	}{
		{
			name: "secure_kudp_wrong_transport",
			matrixRow: map[string]any{
				"status":           "pass",
				"case":             "tcp-secure-performance-tc_xdp-kernel",
				"runner_case":      "secure-kudp",
				"transport":        "tcp",
				"encryption":       "secure",
				"profile":          "performance",
				"datapath":         "tc_xdp",
				"crypto_placement": "kernel",
				"validation_scope": "cross_host",
				"gate_family":      "secure_kudp",
				"min_gbps":         1.5,
				"min_seconds":      3600,
			},
			want: []string{
				"gate_family=secure_kudp",
				"requires transport='kernel_udp'",
				"got 'tcp'",
			},
		},
		{
			name: "route_gso_wrong_runner",
			matrixRow: map[string]any{
				"status":           "pass",
				"case":             "experimental_tcp-plaintext-performance-kernel_module-userspace",
				"runner_case":      "userspace-tcp-plaintext",
				"transport":        "experimental_tcp",
				"encryption":       "plaintext",
				"profile":          "performance",
				"datapath":         "kernel_module",
				"crypto_placement": "userspace",
				"validation_scope": "cross_host",
				"gate_family":      "route_gso",
				"min_gbps":         2.5,
				"min_seconds":      3600,
			},
			want: []string{
				"gate_family=route_gso",
				"requires runner_case='dd-routegso'",
				"got 'userspace-tcp-plaintext'",
			},
		},
		{
			name: "secure_exp_tcp_kernel_wrong_datapath",
			matrixRow: map[string]any{
				"status":           "pass",
				"case":             "experimental_tcp-secure-performance-tc_xdp-kernel",
				"runner_case":      "secure-exp-tcp-kernel",
				"transport":        "experimental_tcp",
				"encryption":       "secure",
				"profile":          "performance",
				"datapath":         "tc_xdp",
				"crypto_placement": "kernel",
				"validation_scope": "cross_host",
				"gate_family":      "secure_exp_tcp_kernel",
				"min_gbps":         1.5,
				"min_seconds":      3600,
			},
			want: []string{
				"gate_family=secure_exp_tcp_kernel",
				"requires datapath='kernel_module'",
				"got 'tc_xdp'",
			},
		},
		{
			name: "owdeb_route_gso_missing_case_suffix",
			matrixRow: map[string]any{
				"status":           "pass",
				"case":             "experimental_tcp-plaintext-performance-kernel_module-userspace",
				"runner_case":      "owdeb-routegso",
				"transport":        "experimental_tcp",
				"encryption":       "plaintext",
				"profile":          "performance",
				"datapath":         "kernel_module",
				"crypto_placement": "userspace",
				"validation_scope": "cross_host",
				"gate_family":      "owdeb_route_gso",
				"min_gbps":         2.5,
				"min_seconds":      3600,
			},
			want: []string{
				"gate_family=owdeb_route_gso",
				"requires case='experimental_tcp-plaintext-performance-kernel_module-userspace-owdeb'",
				"got 'experimental_tcp-plaintext-performance-kernel_module-userspace'",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workdir := t.TempDir()
			matrixSummary := filepath.Join(workdir, "summary.jsonl")
			gateSummaryDir := filepath.Join(workdir, "selected-production-gate")
			if err := os.MkdirAll(gateSummaryDir, 0o755); err != nil {
				t.Fatalf("create gate summary dir: %v", err)
			}
			matrixPayload, err := json.Marshal(tt.matrixRow)
			if err != nil {
				t.Fatalf("marshal matrix row: %v", err)
			}
			if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
				t.Fatalf("write matrix summary: %v", err)
			}
			caseName, _ := tt.matrixRow["case"].(string)
			gateRow := map[string]any{
				"case":                       caseName,
				"status":                     "pass",
				"min_gbps_required":          1.5,
				"min_seconds_required":       3600,
				"min_sent_gbps":              1.9,
				"min_received_gbps":          1.8,
				"min_required_received_gbps": 1.7,
				"min_seconds":                3600.1,
				"seconds_slop":               0,
				"run_timing": []map[string]any{
					{
						"source":                  "run-timing.json",
						"iperf_mode":              "forward",
						"iperf_directions":        "both",
						"iperf_seconds_requested": 3600,
						"start_epoch":             1000,
						"end_epoch":               4600.1,
						"elapsed_seconds":         3600.1,
					},
				},
				"uname_artifacts": []map[string]any{
					{"node": "a", "phase": "before", "kernel_release": "6.12.90+deb13.1-amd64"},
					{"node": "a", "phase": "after", "kernel_release": "6.12.90+deb13.1-amd64"},
					{"node": "b", "phase": "before", "kernel_release": "6.12.90+deb13.1-amd64"},
					{"node": "b", "phase": "after", "kernel_release": "6.12.90+deb13.1-amd64"},
				},
				"os_release_artifacts": []map[string]any{
					{"node": "a", "phase": "before", "identity": "debian:13"},
					{"node": "a", "phase": "after", "identity": "debian:13"},
					{"node": "b", "phase": "before", "identity": "debian:13"},
					{"node": "b", "phase": "after", "identity": "debian:13"},
				},
				"boot_ids": []map[string]any{
					{"node": "a", "phase": "before", "boot_id": "boot-a"},
					{"node": "a", "phase": "after", "boot_id": "boot-a"},
					{"node": "b", "phase": "before", "boot_id": "boot-b"},
					{"node": "b", "phase": "after", "boot_id": "boot-b"},
				},
				"errors":                        []string{},
				"log_findings":                  []string{},
				"kernel_log_artifacts":          []string{"collect/a/kernel.log", "collect/b/kernel.log"},
				"kernel_log_nodes":              []string{"a", "b"},
				"kernel_log_rejected_artifacts": []string{},
				"pstore_artifacts":              []string{"collect/a/pstore.txt", "collect/b/pstore.txt"},
				"pstore_nodes":                  []string{"a", "b"},
				"pstore_rejected_artifacts":     []string{},
			}
			addProductionGatePassIperfCoverage(gateRow)
			gatePayload, err := json.Marshal(gateRow)
			if err != nil {
				t.Fatalf("marshal gate row: %v", err)
			}
			if err := os.WriteFile(filepath.Join(gateSummaryDir, "gate.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
				t.Fatalf("write gate summary: %v", err)
			}
			manifestPayload, err := json.Marshal(map[string]any{
				"schema": productionGateManifestSchema,
				"production_gate": map[string]any{
					"path":   "scripts/linux-cross-host-production-gate.sh",
					"sha256": strings.Repeat("a", 64),
					"size":   123,
				},
				"verifier": map[string]any{
					"path":   "scripts/linux-cross-host-soak-verify.py",
					"sha256": strings.Repeat("b", 64),
					"size":   456,
				},
			})
			if err != nil {
				t.Fatalf("marshal manifest: %v", err)
			}
			if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
				t.Fatalf("write manifest: %v", err)
			}

			cmd := exec.Command(python, "production-evidence-from-gate-summary.py",
				"--matrix-summary", slashPath(matrixSummary),
				"--gate-summary-dir", slashPath(gateSummaryDir),
				"--artifact", "docs/trustix-performance-log.md#semantic-mismatch",
			)
			cmd.Dir = "."
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("generator accepted semantically mismatched matrix row:\n%s", output)
			}
			text := string(output)
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Fatalf("generator output missing %q:\n%s", want, output)
				}
			}
		})
	}
}

func addProductionGatePassIperfCoverage(row map[string]any) {
	row["min_iperf_intervals_required"] = 600
	row["min_iperf_interval_gbps_ratio_required"] = 0.25
	row["iperf_json_count"] = 2
	row["iperf_direction_count"] = 2
	row["iperf_pair_directions"] = []string{"a-to-b", "b-to-a"}
	row["iperf"] = []map[string]any{
		{
			"direction":         "forward",
			"sent_gbps":         1.9,
			"received_gbps":     1.8,
			"seconds":           3600.1,
			"intervals":         600,
			"interval_min_gbps": 1.0,
			"sent_required":     true,
			"received_required": true,
		},
		{
			"direction":         "forward",
			"sent_gbps":         1.8,
			"received_gbps":     1.7,
			"seconds":           3600.1,
			"intervals":         600,
			"interval_min_gbps": 1.0,
			"sent_required":     true,
			"received_required": true,
		},
	}
	row["result_markers"] = []string{"pass"}
	row["binary_identities"] = []map[string]any{
		{"source": "collect/a/binary-identity.json", "sha256": strings.Repeat("c", 64)},
		{"source": "collect/b/binary-identity.json", "sha256": strings.Repeat("c", 64)},
	}
	row["build_identities"] = []map[string]any{
		{
			"source":     "collect/a/status.json",
			"version":    "trustix-test",
			"commit":     "0123456789ab",
			"built_at":   "2026-06-25T00:00:00Z",
			"go_version": "go1.25.0",
			"goos":       "linux",
			"goarch":     "amd64",
			"strong":     true,
		},
		{
			"source":     "collect/b/status.json",
			"version":    "trustix-test",
			"commit":     "0123456789ab",
			"built_at":   "2026-06-25T00:00:00Z",
			"go_version": "go1.25.0",
			"goos":       "linux",
			"goarch":     "amd64",
			"strong":     true,
		},
	}
	row["lsmod_artifacts"] = []map[string]any{
		{"source": "collect/a/lsmod.txt", "node": "a", "modules": []string{}},
		{"source": "collect/b/lsmod.txt", "node": "b", "modules": []string{}},
	}
	row["lsmod_nodes"] = []string{"a", "b"}
	row["lan_state_artifacts"] = []map[string]any{
		{"source": "collect/a/lan-state.txt", "node": "a", "interface": "tix-lan-a", "tx_queue_len": 1000},
		{"source": "collect/b/lan-state.txt", "node": "b", "interface": "tix-lan-b", "tx_queue_len": 1000},
	}
	row["lan_state_nodes"] = []string{"a", "b"}
}

func TestProductionEvidenceFromGateSummaryRejectsShortPassSoak(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	matrixSummary := filepath.Join(workdir, "summary.jsonl")
	gateSummaryDir := filepath.Join(workdir, "selected-production-gate")
	if err := os.MkdirAll(gateSummaryDir, 0o755); err != nil {
		t.Fatalf("create gate summary dir: %v", err)
	}
	matrixRow := map[string]any{
		"status":           "pass",
		"case":             "udp-secure-stable-userspace-userspace",
		"runner_case":      "userspace-udp-secure",
		"transport":        "udp",
		"encryption":       "secure",
		"profile":          "stable",
		"datapath":         "userspace",
		"crypto_placement": "userspace",
		"validation_scope": "cross_host",
		"gate_family":      "userspace",
		"min_gbps":         1.5,
		"min_seconds":      900,
		"exit_code":        0,
	}
	matrixPayload, err := json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace",
		"status":                     "pass",
		"min_gbps_required":          1.5,
		"min_seconds_required":       900,
		"min_sent_gbps":              1.9,
		"min_received_gbps":          1.8,
		"min_required_received_gbps": 1.7,
		"min_seconds":                900,
		"seconds_slop":               0,
	}
	gatePayload, err := json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write gate summary: %v", err)
	}
	manifest := map[string]any{
		"schema": productionGateManifestSchema,
		"production_gate": map[string]any{
			"path":   "scripts/linux-cross-host-production-gate.sh",
			"sha256": strings.Repeat("a", 64),
			"size":   123,
		},
		"verifier": map[string]any{
			"path":   "scripts/linux-cross-host-soak-verify.py",
			"sha256": strings.Repeat("b", 64),
			"size":   456,
		},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#short-production-gate",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted short pass soak:\n%s", output)
	}
	text := string(output)
	if !strings.Contains(text, "3600s production soak") || !strings.Contains(text, "900s") {
		t.Fatalf("generator did not explain short pass soak rejection:\n%s", output)
	}
}

func TestProductionEvidenceFromGateSummaryRejectsUnderMeasuredPassSoak(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	matrixSummary := filepath.Join(workdir, "summary.jsonl")
	gateSummaryDir := filepath.Join(workdir, "selected-production-gate")
	if err := os.MkdirAll(gateSummaryDir, 0o755); err != nil {
		t.Fatalf("create gate summary dir: %v", err)
	}
	matrixRow := map[string]any{
		"status": "pass",
		"case":   "udp-secure-stable-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace",
		"status":                     "pass",
		"min_gbps_required":          1.5,
		"min_seconds_required":       3600,
		"min_sent_gbps":              1.9,
		"min_received_gbps":          1.8,
		"min_required_received_gbps": 1.7,
		"min_seconds":                3598.5,
		"seconds_slop":               1,
	}
	gatePayload, err := json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write gate summary: %v", err)
	}
	manifest := map[string]any{
		"schema": productionGateManifestSchema,
		"production_gate": map[string]any{
			"path":   "scripts/linux-cross-host-production-gate.sh",
			"sha256": strings.Repeat("a", 64),
			"size":   123,
		},
		"verifier": map[string]any{
			"path":   "scripts/linux-cross-host-soak-verify.py",
			"sha256": strings.Repeat("b", 64),
			"size":   456,
		},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#under-measured-production-gate",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted under-measured pass soak:\n%s", output)
	}
	text := string(output)
	for _, want := range []string{
		"measured soak is shorter than required",
		"min_seconds=3598.5s",
		"seconds_slop=1s",
		"required=3600s",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("generator did not explain under-measured soak rejection, missing %q:\n%s", want, output)
		}
	}
}

func TestProductionEvidenceFromGateSummaryRequiresRunTimingArtifacts(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	matrixSummary := filepath.Join(workdir, "summary.jsonl")
	gateSummaryDir := filepath.Join(workdir, "selected-production-gate")
	if err := os.MkdirAll(gateSummaryDir, 0o755); err != nil {
		t.Fatalf("create gate summary dir: %v", err)
	}
	matrixRow := map[string]any{
		"status": "pass",
		"case":   "udp-secure-stable-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace",
		"status":                     "pass",
		"min_gbps_required":          1.5,
		"min_seconds_required":       3600,
		"min_sent_gbps":              1.9,
		"min_received_gbps":          1.8,
		"min_required_received_gbps": 1.7,
		"min_seconds":                3600.1,
		"seconds_slop":               0,
	}
	gatePayload, err := json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write gate summary: %v", err)
	}
	manifest := map[string]any{
		"schema": productionGateManifestSchema,
		"production_gate": map[string]any{
			"path":   "scripts/linux-cross-host-production-gate.sh",
			"sha256": strings.Repeat("a", 64),
			"size":   123,
		},
		"verifier": map[string]any{
			"path":   "scripts/linux-cross-host-soak-verify.py",
			"sha256": strings.Repeat("b", 64),
			"size":   456,
		},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#missing-run-timing",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted pass evidence without run timing:\n%s", output)
	}
	if !strings.Contains(string(output), "run_timing") {
		t.Fatalf("generator did not explain missing run timing:\n%s", output)
	}
}

func TestProductionEvidenceFromGateSummaryRequiresIperfCoverageArtifacts(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	matrixSummary := filepath.Join(workdir, "summary.jsonl")
	gateSummaryDir := filepath.Join(workdir, "selected-production-gate")
	if err := os.MkdirAll(gateSummaryDir, 0o755); err != nil {
		t.Fatalf("create gate summary dir: %v", err)
	}
	matrixRow := map[string]any{
		"status": "pass",
		"case":   "udp-secure-stable-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace",
		"status":                     "pass",
		"min_gbps_required":          1.5,
		"min_seconds_required":       3600,
		"min_sent_gbps":              1.9,
		"min_received_gbps":          1.8,
		"min_required_received_gbps": 1.7,
		"min_seconds":                3600.1,
		"seconds_slop":               0,
		"run_timing": []map[string]any{
			{
				"source":                  "run-timing.json",
				"iperf_mode":              "forward",
				"iperf_directions":        "both",
				"iperf_seconds_requested": 3600,
				"start_epoch":             1000,
				"end_epoch":               4600.1,
				"elapsed_seconds":         3600.1,
			},
		},
	}
	gatePayload, err := json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write gate summary: %v", err)
	}
	manifest := map[string]any{
		"schema": productionGateManifestSchema,
		"production_gate": map[string]any{
			"path":   "scripts/linux-cross-host-production-gate.sh",
			"sha256": strings.Repeat("a", 64),
			"size":   123,
		},
		"verifier": map[string]any{
			"path":   "scripts/linux-cross-host-soak-verify.py",
			"sha256": strings.Repeat("b", 64),
			"size":   456,
		},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#missing-iperf-coverage",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted pass evidence without iperf coverage:\n%s", output)
	}
	if !strings.Contains(string(output), "min_iperf_intervals_required") {
		t.Fatalf("generator did not explain missing iperf coverage:\n%s", output)
	}
}

func TestProductionEvidenceFromGateSummaryRequiresRuntimeIdentityArtifacts(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	matrixSummary := filepath.Join(workdir, "summary.jsonl")
	gateSummaryDir := filepath.Join(workdir, "selected-production-gate")
	if err := os.MkdirAll(gateSummaryDir, 0o755); err != nil {
		t.Fatalf("create gate summary dir: %v", err)
	}
	matrixRow := map[string]any{
		"status": "pass",
		"case":   "udp-secure-stable-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace",
		"status":                     "pass",
		"min_gbps_required":          1.5,
		"min_seconds_required":       3600,
		"min_sent_gbps":              1.9,
		"min_received_gbps":          1.8,
		"min_required_received_gbps": 1.7,
		"min_seconds":                3600.1,
		"seconds_slop":               0,
		"run_timing": []map[string]any{
			{
				"source":                  "run-timing.json",
				"iperf_mode":              "forward",
				"iperf_directions":        "both",
				"iperf_seconds_requested": 3600,
				"start_epoch":             1000,
				"end_epoch":               4600.1,
				"elapsed_seconds":         3600.1,
			},
		},
	}
	addProductionGatePassIperfCoverage(gateRow)
	delete(gateRow, "result_markers")
	gatePayload, err := json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write gate summary: %v", err)
	}
	manifest := map[string]any{
		"schema": productionGateManifestSchema,
		"production_gate": map[string]any{
			"path":   "scripts/linux-cross-host-production-gate.sh",
			"sha256": strings.Repeat("a", 64),
			"size":   123,
		},
		"verifier": map[string]any{
			"path":   "scripts/linux-cross-host-soak-verify.py",
			"sha256": strings.Repeat("b", 64),
			"size":   456,
		},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#missing-runtime-identity",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted pass evidence without result markers:\n%s", output)
	}
	if !strings.Contains(string(output), "result_markers") {
		t.Fatalf("generator did not explain missing runtime identity:\n%s", output)
	}
}

func TestProductionEvidenceFromGateSummaryRequiresCrashStabilityArtifacts(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	matrixSummary := filepath.Join(workdir, "summary.jsonl")
	gateSummaryDir := filepath.Join(workdir, "selected-production-gate")
	if err := os.MkdirAll(gateSummaryDir, 0o755); err != nil {
		t.Fatalf("create gate summary dir: %v", err)
	}
	matrixRow := map[string]any{
		"status": "pass",
		"case":   "udp-secure-stable-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(matrixRow)
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace",
		"status":                     "pass",
		"min_gbps_required":          1.5,
		"min_seconds_required":       3600,
		"min_sent_gbps":              1.9,
		"min_received_gbps":          1.8,
		"min_required_received_gbps": 1.7,
		"min_seconds":                3600.1,
		"seconds_slop":               0,
		"run_timing": []map[string]any{
			{
				"source":                  "run-timing.json",
				"iperf_mode":              "forward",
				"iperf_directions":        "both",
				"iperf_seconds_requested": 3600,
				"start_epoch":             1000,
				"end_epoch":               4600.1,
				"elapsed_seconds":         3600.1,
			},
		},
		"errors":                        []string{},
		"log_findings":                  []string{},
		"kernel_log_artifacts":          []string{"collect/a/kernel.log", "collect/b/kernel.log"},
		"kernel_log_nodes":              []string{"a", "b"},
		"kernel_log_rejected_artifacts": []string{},
		"pstore_artifacts":              []string{"collect/a/pstore.txt", "collect/b/pstore.txt"},
		"pstore_nodes":                  []string{"a", "b"},
		"pstore_rejected_artifacts":     []string{},
	}
	addProductionGatePassIperfCoverage(gateRow)
	gatePayload, err := json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write gate summary: %v", err)
	}
	manifest := map[string]any{
		"schema": productionGateManifestSchema,
		"production_gate": map[string]any{
			"path":   "scripts/linux-cross-host-production-gate.sh",
			"sha256": strings.Repeat("a", 64),
			"size":   123,
		},
		"verifier": map[string]any{
			"path":   "scripts/linux-cross-host-soak-verify.py",
			"sha256": strings.Repeat("b", 64),
			"size":   456,
		},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#missing-crash-stability",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted pass evidence without boot-id coverage:\n%s", output)
	}
	if !strings.Contains(string(output), "boot_ids") {
		t.Fatalf("generator did not explain missing boot-id coverage:\n%s", output)
	}
}

func TestSelectedCrossHostProductionDefaultsHaveCurrentEvidence(t *testing.T) {
	defaults := loadProductionTransportDefaults(t)
	evidenceByKey := map[string][]productionTransportEvidence{}
	for _, evidence := range loadProductionTransportEvidence(t) {
		evidenceByKey[productionEvidenceKey(evidence)] = append(evidenceByKey[productionEvidenceKey(evidence)], evidence)
	}

	checkedByFamily := map[string]int{}
	for _, row := range defaults {
		if row.ValidationScope != "cross_host" {
			continue
		}
		requirement, ok := currentProductionEvidenceRequirementForDefault(row)
		if !ok {
			t.Fatalf("cross-host production default lacks current evidence requirement: %+v", row)
		}
		minGbps, err := strconv.ParseFloat(row.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid production default min_gbps %q in %+v", row.MinGbps, row)
		}
		minSeconds, err := strconv.Atoi(row.MinSeconds)
		if err != nil {
			t.Fatalf("invalid production default min_seconds %q in %+v", row.MinSeconds, row)
		}
		key := productionDefaultEvidenceKey(row)
		var candidates []string
		found := false
		for _, evidence := range evidenceByKey[key] {
			candidates = append(candidates, strings.Join([]string{
				evidence.OSMatrix,
				evidence.KernelMatrix,
				evidence.Result,
				evidence.MinGbps,
				evidence.MinSeconds,
				evidence.GateManifestSchema,
				evidence.Artifact,
			}, " "))
			if evidence.OSMatrix != requirement.OSMatrix ||
				evidence.KernelMatrix != requirement.KernelMatrix ||
				evidence.GateManifestSchema != requirement.GateManifestSchema ||
				evidence.Artifact != requirement.Artifact ||
				evidence.Result != "pass" {
				continue
			}
			evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
			if err != nil {
				t.Fatalf("invalid production evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
			}
			evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
			if err != nil {
				t.Fatalf("invalid production evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
			}
			if evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("cross-host production default lacks current passing evidence at or above gate %s: %+v; requirement=%+v; candidates=%v", key, row, requirement, candidates)
		}
		checkedByFamily[row.GateFamily]++
	}
	for _, family := range []string{
		"userspace",
		"userspace_tc",
		"tc_direct",
		"full_kmod",
		"owdeb_full_kmod",
		"secure_kudp",
		"secure_exp_tcp_kernel",
		"route_gso",
	} {
		if checkedByFamily[family] == 0 {
			t.Fatalf("no current cross-host production defaults checked for gate family %s", family)
		}
	}
}

func TestProductionTransportAuditScriptCoversCrossHostDefaults(t *testing.T) {
	python := requirePython3(t)
	cmd := exec.Command(python, "production-transport-audit.py",
		"--scope", "cross_host",
		"--require-manifest",
		"--fail-on-missing",
		"--json",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production transport audit failed: %v\n%s", err, output)
	}
	var rows []struct {
		Status  string `json:"status"`
		Key     string `json:"key"`
		Default struct {
			MinGbps    string `json:"min_gbps"`
			MinSeconds string `json:"min_seconds"`
		} `json:"default"`
		Evidence struct {
			MinGbps            string `json:"min_gbps"`
			MinSeconds         string `json:"min_seconds"`
			GateManifestSchema string `json:"gate_manifest_schema"`
			Artifact           string `json:"artifact"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		t.Fatalf("decode audit JSON: %v\n%s", err, output)
	}
	wantRows := 0
	defaultByKey := map[string]productionTransportDefault{}
	for _, row := range loadProductionTransportDefaults(t) {
		if row.ValidationScope != "cross_host" {
			continue
		}
		wantRows++
		defaultByKey[productionDefaultEvidenceKey(row)] = row
	}
	if len(rows) != wantRows {
		t.Fatalf("audit rows = %d, want %d\n%s", len(rows), wantRows, output)
	}
	for _, row := range rows {
		if row.Status != "pass" {
			t.Fatalf("audit row did not pass: %+v\n%s", row, output)
		}
		defaultRow, ok := defaultByKey[row.Key]
		if !ok {
			t.Fatalf("audit emitted non-default key %q\n%s", row.Key, output)
		}
		defaultGbps, err := strconv.ParseFloat(defaultRow.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid default min_gbps %q in %+v", defaultRow.MinGbps, defaultRow)
		}
		defaultSeconds, err := strconv.ParseFloat(defaultRow.MinSeconds, 64)
		if err != nil {
			t.Fatalf("invalid default min_seconds %q in %+v", defaultRow.MinSeconds, defaultRow)
		}
		evidenceGbps, err := strconv.ParseFloat(row.Evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid audit evidence min_gbps %q in %+v", row.Evidence.MinGbps, row)
		}
		evidenceSeconds, err := strconv.ParseFloat(row.Evidence.MinSeconds, 64)
		if err != nil {
			t.Fatalf("invalid audit evidence min_seconds %q in %+v", row.Evidence.MinSeconds, row)
		}
		if evidenceGbps < defaultGbps || evidenceSeconds < defaultSeconds {
			t.Fatalf("audit accepted below-threshold evidence for %s: %+v default=%+v", row.Key, row.Evidence, defaultRow)
		}
		if row.Evidence.GateManifestSchema != productionGateManifestSchema {
			t.Fatalf("audit accepted non-manifest evidence for %s: %+v", row.Key, row.Evidence)
		}
		if !strings.HasPrefix(row.Evidence.Artifact, "docs/") || !strings.Contains(row.Evidence.Artifact, "#") {
			t.Fatalf("audit evidence artifact should be a docs anchor for %s: %+v", row.Key, row.Evidence)
		}
	}
}

func TestProductionTransportAuditScriptFailsOnMissingEvidence(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	payload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t100\t3600\timpossible threshold for audit failure",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(payload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", "production-transport-evidence.tsv",
		"--scope", "cross_host",
		"--require-manifest",
		"--fail-on-missing",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted missing evidence:\n%s", output)
	}
	if !strings.Contains(string(output), "lack matching evidence") {
		t.Fatalf("audit failure did not explain missing evidence:\n%s", output)
	}
}

func TestCurrentProductionEvidenceManifestPromotionBoundaries(t *testing.T) {
	manifestRequiredArtifacts := map[string]string{
		"tc_direct":             "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-tc-direct-secure-kudp-3600s-ratio-gates",
		"full_kmod":             "docs/trustix-performance-log.md#2026-06-23-zaozhuang-pve-current-head-full-kmod-3600s-production-gates",
		"secure_kudp":           "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-tc-direct-secure-kudp-3600s-ratio-gates",
		"secure_exp_tcp_kernel": "docs/trustix-performance-log.md#2026-06-25-zaozhuang-pve-secure-exp-tcp-kernel-fpu-fallback-3600s-production-gate",
		"route_gso":             "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-route-gso-3600s-production-gate",
		"owdeb_full_kmod":       "docs/trustix-performance-log.md#2026-06-25-zaozhuang-pve-openwrt-24107-current-head-full-kmod-3600s-production-gate",
		"userspace":             "docs/trustix-performance-log.md#2026-06-23-zaozhuang-pve-userspace-userspace-tc-3600s-production-gates",
		"userspace_tc":          "docs/trustix-performance-log.md#2026-06-23-zaozhuang-pve-userspace-userspace-tc-3600s-production-gates",
	}
	legacyPendingFamilies := map[string]bool{}
	seen := map[string]bool{}
	for _, row := range loadProductionTransportDefaults(t) {
		if row.ValidationScope != "cross_host" {
			continue
		}
		requirement, ok := currentProductionEvidenceRequirementForDefault(row)
		if !ok {
			t.Fatalf("cross-host production default lacks current evidence requirement: %+v", row)
		}
		seen[row.GateFamily] = true
		switch {
		case manifestRequiredArtifacts[row.GateFamily] != "":
			if requirement.GateManifestSchema != productionGateManifestSchema {
				t.Fatalf("production default must require manifest-backed evidence: row=%+v requirement=%+v", row, requirement)
			}
			if requirement.Artifact != manifestRequiredArtifacts[row.GateFamily] {
				t.Fatalf("production default points at stale evidence: row=%+v requirement=%+v", row, requirement)
			}
		case legacyPendingFamilies[row.GateFamily]:
			if requirement.GateManifestSchema != legacyProductionGateManifestValue {
				t.Fatalf("legacy-pending default should remain explicit until rerun with a gate manifest: row=%+v requirement=%+v", row, requirement)
			}
		default:
			t.Fatalf("cross-host production default has unclassified manifest policy: row=%+v requirement=%+v", row, requirement)
		}
	}
	for family := range manifestRequiredArtifacts {
		if !seen[family] {
			t.Fatalf("manifest-required production family was not exercised: %s", family)
		}
	}
	for family := range legacyPendingFamilies {
		if !seen[family] {
			t.Fatalf("legacy-pending production family was not exercised: %s", family)
		}
	}
}

func TestProductionEvidenceArtifactsResolveToDocsAnchors(t *testing.T) {
	anchorsByPath := map[string]map[string]bool{}
	for _, evidence := range loadProductionTransportEvidence(t) {
		parts := strings.SplitN(evidence.Artifact, "#", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			t.Fatalf("production evidence artifact must be a local markdown anchor: %+v", evidence)
		}
		docPath := filepath.Clean(filepath.FromSlash(parts[0]))
		anchor := parts[1]
		if !strings.HasPrefix(docPath, filepath.Clean("docs")+string(os.PathSeparator)) {
			t.Fatalf("production evidence artifact must point under docs/: %+v", evidence)
		}
		repoDocPath := filepath.Join("..", docPath)
		if _, ok := anchorsByPath[repoDocPath]; !ok {
			anchorsByPath[repoDocPath] = loadDocumentAnchors(t, repoDocPath)
		}
		if !anchorsByPath[repoDocPath][anchor] {
			t.Fatalf("production evidence artifact anchor does not exist: %s in %+v", evidence.Artifact, evidence)
		}
	}
}

func TestCurrentOpenWrtFullKmodEvidenceCoversProductionGate(t *testing.T) {
	const (
		wantOSMatrix     = "openwrt24.10.7-debian13"
		wantKernelMatrix = "6.6.141_to_6.12.94+deb13-cloud-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-06-25-zaozhuang-pve-openwrt-24107-current-head-full-kmod-3600s-production-gate"
		minGbps          = 3.0
		minSeconds       = 3600
	)
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.GateFamily != "owdeb_full_kmod" ||
			evidence.OSMatrix != wantOSMatrix ||
			evidence.KernelMatrix != wantKernelMatrix ||
			evidence.Artifact != wantArtifact {
			continue
		}
		evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid OpenWrt full-kmod evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid OpenWrt full-kmod evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		if evidence.GateManifestSchema != productionGateManifestSchema {
			t.Fatalf("current OpenWrt full-kmod evidence must be manifest-backed: %+v", evidence)
		}
		if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
			return
		}
		t.Fatalf("current OpenWrt full-kmod evidence is below production gate: %+v", evidence)
	}
	t.Fatalf("missing current OpenWrt full-kmod production evidence for %s / %s", wantOSMatrix, wantKernelMatrix)
}

func TestOpenWrtRouteGSOFamiliesHaveFailClosedRuntimeEvidence(t *testing.T) {
	want := map[string]bool{
		"owdeb_secure_kudp:openwrt24.10.2-debian13:6.6.93_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24102-full-kmod-production-gate":                           false,
		"owdeb_route_gso:openwrt24.10.2-debian13:6.6.93_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24102-full-kmod-production-gate":                             false,
		"owdeb_secure_exp_tcp_kernel:openwrt24.10.2-debian13:6.6.93_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24102-full-kmod-production-gate":                 false,
		"owdeb_secure_kudp:openwrt24.10.7-debian13:6.6.141_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24107-runtime-capability-check":                           false,
		"owdeb_route_gso:openwrt24.10.7-debian13:6.6.141_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24107-runtime-capability-check":                             false,
		"owdeb_secure_exp_tcp_kernel:openwrt24.10.7-debian13:6.6.141_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24107-runtime-capability-check":                 false,
		"owdeb_secure_kudp:openwrt25.12.4-debian13:6.12.87_to_6.12.94+deb13-amd64:docs/trustix-performance-log.md#2026-06-24-zaozhuang-pve-openwrt-25124-route-gso-runtime-check":           false,
		"owdeb_route_gso:openwrt25.12.4-debian13:6.12.87_to_6.12.94+deb13-amd64:docs/trustix-performance-log.md#2026-06-24-zaozhuang-pve-openwrt-25124-route-gso-runtime-check":             false,
		"owdeb_secure_exp_tcp_kernel:openwrt25.12.4-debian13:6.12.87_to_6.12.94+deb13-amd64:docs/trustix-performance-log.md#2026-06-24-zaozhuang-pve-openwrt-25124-route-gso-runtime-check": false,
	}
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.Result != "fail_closed" || evidence.MinGbps != "0" || evidence.MinSeconds != "30" {
			continue
		}
		key := strings.Join([]string{
			evidence.GateFamily,
			evidence.OSMatrix,
			evidence.KernelMatrix,
			evidence.Artifact,
		}, ":")
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	var missing []string
	for key, found := range want {
		if !found {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("missing OpenWrt route-GSO fail-closed runtime evidence: %v", missing)
	}
}

func TestOpenWrtSecureExperimentalTCPKernelFailClosedRowsInheritRouteTCPGate(t *testing.T) {
	rows := loadProductionTransportEvidence(t)
	routeTCPFailures := map[string]bool{}
	keyFor := func(evidence productionTransportEvidence) string {
		return strings.Join([]string{
			evidence.OSMatrix,
			evidence.KernelMatrix,
			evidence.Artifact,
		}, ":")
	}
	for _, evidence := range rows {
		if evidence.GateFamily == "owdeb_route_gso" &&
			evidence.Result == "fail_closed" &&
			evidence.MinGbps == "0" &&
			evidence.MinSeconds == "30" &&
			strings.Contains(evidence.Note, "route-TCP kfunc") {
			routeTCPFailures[keyFor(evidence)] = true
		}
	}
	var seen int
	for _, evidence := range rows {
		if evidence.GateFamily != "owdeb_secure_exp_tcp_kernel" {
			continue
		}
		seen++
		if evidence.Result != "fail_closed" || evidence.MinGbps != "0" || evidence.MinSeconds != "30" {
			t.Fatalf("OpenWrt secure experimental TCP kernel evidence must be fail-closed prerequisite evidence, got %+v", evidence)
		}
		if !strings.Contains(evidence.Note, "route-TCP kfunc") {
			t.Fatalf("OpenWrt secure experimental TCP kernel evidence must name the missing route-TCP prerequisite: %+v", evidence)
		}
		if !routeTCPFailures[keyFor(evidence)] {
			t.Fatalf("OpenWrt secure experimental TCP kernel fail-closed row is not tied to route-GSO route-TCP capability evidence: %+v", evidence)
		}
	}
	if seen == 0 {
		t.Fatal("missing OpenWrt secure experimental TCP kernel fail-closed boundary rows")
	}
}

func TestCurrentDebianFullKmodEvidenceCoversProductionGate(t *testing.T) {
	const (
		wantOSMatrix     = "debian13-debian13"
		wantKernelMatrix = "6.12.94+deb13-cloud-amd64_to_6.12.94+deb13-cloud-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-dd-full-kmod-3600s-production-gate"
		minGbps          = 3.0
		minSeconds       = 3600
	)
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.GateFamily != "full_kmod" ||
			evidence.OSMatrix != wantOSMatrix ||
			evidence.KernelMatrix != wantKernelMatrix ||
			evidence.Artifact != wantArtifact {
			continue
		}
		evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid Debian full-kmod evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid Debian full-kmod evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		if evidence.GateManifestSchema != productionGateManifestSchema {
			t.Fatalf("current Debian full-kmod evidence must be manifest-backed: %+v", evidence)
		}
		if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
			return
		}
		t.Fatalf("current Debian full-kmod evidence is below production gate: %+v", evidence)
	}
	t.Fatalf("missing current Debian full-kmod production evidence for %s / %s", wantOSMatrix, wantKernelMatrix)
}

func TestCurrentDebianTCDirectEvidenceCoversProductionGate(t *testing.T) {
	const (
		wantOSMatrix     = "debian13-debian13"
		wantKernelMatrix = "6.12.94+deb13-cloud-amd64_to_6.12.94+deb13-cloud-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-tc-direct-secure-kudp-3600s-ratio-gates"
		minGbps          = 3.0
		minSeconds       = 3600
	)
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.GateFamily != "tc_direct" ||
			evidence.OSMatrix != wantOSMatrix ||
			evidence.KernelMatrix != wantKernelMatrix ||
			evidence.Artifact != wantArtifact {
			continue
		}
		evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid Debian TC-direct evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid Debian TC-direct evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
			return
		}
		t.Fatalf("current Debian TC-direct evidence is below production gate: %+v", evidence)
	}
	t.Fatalf("missing current Debian TC-direct production evidence for %s / %s", wantOSMatrix, wantKernelMatrix)
}

func TestCurrentDebianSecureKUDPEvidenceCoversProductionGate(t *testing.T) {
	const (
		wantOSMatrix     = "debian13-debian13"
		wantKernelMatrix = "6.12.94+deb13-cloud-amd64_to_6.12.94+deb13-cloud-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-tc-direct-secure-kudp-3600s-ratio-gates"
		minGbps          = 1.5
		minSeconds       = 3600
	)
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.GateFamily != "secure_kudp" ||
			evidence.OSMatrix != wantOSMatrix ||
			evidence.KernelMatrix != wantKernelMatrix ||
			evidence.Artifact != wantArtifact {
			continue
		}
		evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid Debian secure-kUDP evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid Debian secure-kUDP evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
			return
		}
		t.Fatalf("current Debian secure-kUDP evidence is below production gate: %+v", evidence)
	}
	t.Fatalf("missing current Debian secure-kUDP production evidence for %s / %s", wantOSMatrix, wantKernelMatrix)
}

func TestCurrentDebianRouteGSOEvidenceCoversProductionGate(t *testing.T) {
	const (
		wantOSMatrix     = "debian13-debian13"
		wantKernelMatrix = "6.12.94+deb13-cloud-amd64_to_6.12.94+deb13-cloud-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-06-22-zaozhuang-pve-route-gso-3600s-production-gate"
		minGbps          = 2.5
		minSeconds       = 3600
	)
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.GateFamily != "route_gso" ||
			evidence.OSMatrix != wantOSMatrix ||
			evidence.KernelMatrix != wantKernelMatrix ||
			evidence.Artifact != wantArtifact {
			continue
		}
		evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid Debian route-GSO evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid Debian route-GSO evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
			return
		}
		t.Fatalf("current Debian route-GSO evidence is below production gate: %+v", evidence)
	}
	t.Fatalf("missing current Debian route-GSO production evidence for %s / %s", wantOSMatrix, wantKernelMatrix)
}

func TestCurrentDebianUserspaceEvidenceCoversProductionGates(t *testing.T) {
	const (
		wantOSMatrix     = "debian13-debian13"
		wantKernelMatrix = "6.12.69+deb13-amd64_to_6.12.69+deb13-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-06-23-zaozhuang-pve-userspace-userspace-tc-3600s-production-gates"
	)

	evidenceByKey := map[string][]productionTransportEvidence{}
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.OSMatrix != wantOSMatrix ||
			evidence.KernelMatrix != wantKernelMatrix ||
			evidence.Artifact != wantArtifact {
			continue
		}
		evidenceByKey[productionEvidenceKey(evidence)] = append(evidenceByKey[productionEvidenceKey(evidence)], evidence)
	}

	var checked int
	for _, row := range loadProductionTransportDefaults(t) {
		if row.ValidationScope != "cross_host" ||
			row.GateFamily != "userspace" ||
			row.Datapath != "userspace" ||
			row.CryptoPlacement != "userspace" {
			continue
		}
		checked++
		minGbps, err := strconv.ParseFloat(row.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid userspace default min_gbps %q in %+v", row.MinGbps, row)
		}
		minSeconds, err := strconv.Atoi(row.MinSeconds)
		if err != nil {
			t.Fatalf("invalid userspace default min_seconds %q in %+v", row.MinSeconds, row)
		}
		key := productionDefaultEvidenceKey(row)
		found := false
		for _, evidence := range evidenceByKey[key] {
			evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
			if err != nil {
				t.Fatalf("invalid userspace evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
			}
			evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
			if err != nil {
				t.Fatalf("invalid userspace evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
			}
			if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing current Debian userspace evidence for %s", key)
		}
	}
	if checked == 0 {
		t.Fatalf("no cross-host userspace production defaults checked")
	}
}

func TestCurrentDebianUserspaceTCEvidenceCoversProductionGates(t *testing.T) {
	const (
		wantOSMatrix     = "debian13-debian13"
		wantKernelMatrix = "6.12.69+deb13-amd64_to_6.12.69+deb13-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-06-23-zaozhuang-pve-userspace-userspace-tc-3600s-production-gates"
	)

	evidenceByKey := map[string][]productionTransportEvidence{}
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.OSMatrix != wantOSMatrix ||
			evidence.KernelMatrix != wantKernelMatrix ||
			evidence.Artifact != wantArtifact {
			continue
		}
		evidenceByKey[productionEvidenceKey(evidence)] = append(evidenceByKey[productionEvidenceKey(evidence)], evidence)
	}

	var checked int
	for _, row := range loadProductionTransportDefaults(t) {
		if row.ValidationScope != "cross_host" ||
			row.GateFamily != "userspace_tc" ||
			row.Datapath != "tc_xdp" ||
			row.CryptoPlacement != "userspace" {
			continue
		}
		checked++
		minGbps, err := strconv.ParseFloat(row.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid userspace-TC default min_gbps %q in %+v", row.MinGbps, row)
		}
		minSeconds, err := strconv.Atoi(row.MinSeconds)
		if err != nil {
			t.Fatalf("invalid userspace-TC default min_seconds %q in %+v", row.MinSeconds, row)
		}
		key := productionDefaultEvidenceKey(row)
		found := false
		for _, evidence := range evidenceByKey[key] {
			evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
			if err != nil {
				t.Fatalf("invalid userspace-TC evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
			}
			evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
			if err != nil {
				t.Fatalf("invalid userspace-TC evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
			}
			if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing current Debian userspace-TC evidence for %s", key)
		}
	}
	if checked == 0 {
		t.Fatalf("no cross-host userspace-TC production defaults checked")
	}
}

func TestProductionDefaultsDoNotPromotePlainExperimentalTCPUserspaceWithoutStrictEvidence(t *testing.T) {
	const (
		minGbps    = 1.0
		minSeconds = 3600
	)

	hasStrictEvidence := false
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.Transport != "experimental_tcp" ||
			evidence.Encryption != "plaintext" ||
			evidence.Profile != "stable" ||
			evidence.Datapath != "userspace" ||
			evidence.CryptoPlacement != "userspace" ||
			evidence.ValidationScope != "cross_host" ||
			evidence.GateFamily != "userspace" ||
			evidence.Result != "pass" ||
			evidence.GateManifestSchema != productionGateManifestSchema {
			continue
		}
		evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid plaintext experimental_tcp userspace evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid plaintext experimental_tcp userspace evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		if evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
			hasStrictEvidence = true
			break
		}
	}

	var sawBaseline, sawRouteGSO bool
	for _, row := range loadProductionTransportDefaults(t) {
		if row.Transport != "experimental_tcp" || row.Encryption != "plaintext" {
			continue
		}
		if row.Profile == "stable" &&
			row.Datapath == "userspace" &&
			row.CryptoPlacement == "userspace" &&
			row.ValidationScope == "single_host" &&
			row.GateFamily == "userspace" &&
			row.MinGbps == "0" &&
			row.MinSeconds == "30" {
			sawBaseline = true
		}
		if row.Profile == "performance" &&
			row.Datapath == "kernel_module" &&
			row.CryptoPlacement == "userspace" &&
			row.ValidationScope == "cross_host" &&
			row.GateFamily == "route_gso" &&
			row.MinGbps == "2.5" &&
			row.MinSeconds == "3600" {
			sawRouteGSO = true
		}
		if row.Profile == "stable" &&
			row.Datapath == "userspace" &&
			row.CryptoPlacement == "userspace" &&
			row.ValidationScope == "cross_host" &&
			row.GateFamily == "userspace" &&
			!hasStrictEvidence {
			t.Fatalf("plaintext experimental_tcp userspace cross-host default requires fresh strict 3600s manifest evidence: %+v", row)
		}
	}
	if !sawBaseline {
		t.Fatal("plaintext experimental_tcp userspace single-host baseline default disappeared")
	}
	if !sawRouteGSO {
		t.Fatal("plaintext experimental_tcp cross-host production default should stay on the selected route-GSO gate")
	}
}

func TestProductionDefaultsDoNotReuseSecureKUDPForSecureExperimentalTCPKernelCrypto(t *testing.T) {
	const (
		minGbps    = 1.5
		minSeconds = 3600
	)

	hasStrictDedicatedEvidence := false
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.GateFamily == "secure_kudp" && evidence.Transport != "kernel_udp" {
			t.Fatalf("secure_kudp evidence must describe kernel_udp, not another secure kernel crypto transport: %+v", evidence)
		}
		if evidence.Transport != "experimental_tcp" ||
			evidence.Encryption != "secure" ||
			evidence.Profile != "performance" ||
			evidence.CryptoPlacement != "kernel" ||
			evidence.ValidationScope != "cross_host" ||
			evidence.Result != "pass" ||
			evidence.GateManifestSchema != productionGateManifestSchema {
			continue
		}
		switch evidence.Datapath {
		case "tc_xdp", "kernel_module":
		default:
			continue
		}
		evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid secure experimental_tcp kernel evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid secure experimental_tcp kernel evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		if evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
			hasStrictDedicatedEvidence = true
			break
		}
	}

	var sawSecureUserspace bool
	for _, row := range loadProductionTransportDefaults(t) {
		if row.GateFamily == "secure_kudp" && row.Transport != "kernel_udp" {
			t.Fatalf("secure_kudp production default must stay scoped to kernel_udp: %+v", row)
		}
		if row.Transport != "experimental_tcp" || row.Encryption != "secure" {
			continue
		}
		if row.Profile == "stable" &&
			row.Datapath == "userspace" &&
			row.CryptoPlacement == "userspace" &&
			row.ValidationScope == "cross_host" &&
			row.GateFamily == "userspace" &&
			row.MinGbps == "1" &&
			row.MinSeconds == "3600" {
			sawSecureUserspace = true
		}
		if row.Profile == "performance" &&
			row.CryptoPlacement == "kernel" &&
			row.ValidationScope == "cross_host" &&
			!hasStrictDedicatedEvidence {
			t.Fatalf("secure experimental_tcp kernel-crypto production default requires dedicated strict 3600s manifest evidence: %+v", row)
		}
	}
	if !sawSecureUserspace {
		t.Fatal("secure experimental_tcp userspace cross-host production default disappeared")
	}
}

func TestProductionTransportDefaultsCoverProtocolsAndValidationScopes(t *testing.T) {
	defaults := readProductionTransportDefaults(t)
	for _, wantCase := range []string{
		"udp:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"udp:secure:stable:userspace:userspace:cross_host:userspace:1.5:3600",
		"udp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"udp:plaintext:stable:userspace:userspace:cross_host:userspace:1.5:3600",
		"udp:plaintext:performance:kernel_module:userspace:cross_host:owdeb_full_kmod:3:3600",
		"tcp:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"tcp:secure:stable:userspace:userspace:cross_host:userspace:0.75:3600",
		"tcp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"tcp:plaintext:stable:userspace:userspace:cross_host:userspace:1:3600",
		"quic:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"quic:secure:stable:userspace:userspace:cross_host:userspace:0.75:3600",
		"quic:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"quic:plaintext:stable:userspace:userspace:cross_host:userspace:1:3600",
		"websocket:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"websocket:secure:stable:userspace:userspace:cross_host:userspace:0.5:3600",
		"websocket:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"websocket:plaintext:stable:userspace:userspace:cross_host:userspace:1:3600",
		"http_connect:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"http_connect:secure:stable:userspace:userspace:cross_host:userspace:0.75:3600",
		"http_connect:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"http_connect:plaintext:stable:userspace:userspace:cross_host:userspace:1:3600",
		"gre:secure:stable:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"gre:secure:stable:tc_xdp:userspace:cross_host:userspace_tc:1:3600",
		"gre:plaintext:performance:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"gre:plaintext:performance:tc_xdp:userspace:cross_host:userspace_tc:4:3600",
		"ipip:secure:stable:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"ipip:secure:stable:tc_xdp:userspace:cross_host:userspace_tc:1:3600",
		"ipip:plaintext:performance:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"ipip:plaintext:performance:tc_xdp:userspace:cross_host:userspace_tc:4:3600",
		"vxlan:secure:stable:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"vxlan:secure:stable:tc_xdp:userspace:cross_host:userspace_tc:1:3600",
		"vxlan:plaintext:performance:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"vxlan:plaintext:performance:tc_xdp:userspace:cross_host:userspace_tc:4:3600",
		"kernel_udp:plaintext:performance:tc_xdp:userspace:single_host:tc_direct:0:30",
		"kernel_udp:plaintext:performance:tc_xdp:userspace:cross_host:tc_direct:3:3600",
		"kernel_udp:secure:performance:tc_xdp:kernel:cross_host:secure_kudp:1.5:3600",
		"experimental_tcp:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"experimental_tcp:secure:stable:userspace:userspace:cross_host:userspace:1:3600",
		"experimental_tcp:secure:performance:kernel_module:kernel:cross_host:secure_exp_tcp_kernel:1.5:3600",
		"experimental_tcp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"experimental_tcp:plaintext:performance:kernel_module:userspace:cross_host:route_gso:2.5:3600",
	} {
		if !strings.Contains(defaults, wantCase) {
			t.Fatalf("production defaults missing %q", wantCase)
		}
	}
}

func TestProductionTransportDefaultsAreStructuredAndGateScoped(t *testing.T) {
	rows := loadProductionTransportDefaults(t)
	knownTransport := map[string]bool{
		"udp": true, "tcp": true, "quic": true, "websocket": true,
		"http_connect": true, "gre": true, "ipip": true, "vxlan": true,
		"kernel_udp": true, "experimental_tcp": true,
	}
	knownGate := map[string]bool{
		"userspace": true, "userspace_tc": true, "tc_direct": true,
		"full_kmod": true, "owdeb_full_kmod": true,
		"secure_kudp": true, "secure_exp_tcp_kernel": true, "route_gso": true,
	}
	crossHostGate := map[string]bool{
		"userspace": true, "userspace_tc": true, "tc_direct": true,
		"full_kmod": true, "owdeb_full_kmod": true,
		"secure_kudp": true, "secure_exp_tcp_kernel": true, "route_gso": true,
	}
	crossHostOnlyGate := map[string]bool{
		"full_kmod": true, "owdeb_full_kmod": true,
		"secure_kudp": true, "secure_exp_tcp_kernel": true, "route_gso": true,
	}
	seen := map[string]bool{}
	baseline := map[string]bool{}
	for _, row := range rows {
		key := strings.Join([]string{
			row.Transport, row.Encryption, row.Profile, row.Datapath,
			row.CryptoPlacement, row.ValidationScope, row.GateFamily,
		}, ":")
		if seen[key] {
			t.Fatalf("duplicate production default row key %q", key)
		}
		seen[key] = true
		if !knownTransport[row.Transport] {
			t.Fatalf("unknown production transport %q in %+v", row.Transport, row)
		}
		switch row.Encryption {
		case "secure", "plaintext":
		default:
			t.Fatalf("unknown encryption %q in %+v", row.Encryption, row)
		}
		switch row.Profile {
		case "stable", "performance", "latency":
		default:
			t.Fatalf("unknown profile %q in %+v", row.Profile, row)
		}
		switch row.Datapath {
		case "userspace", "tc_xdp", "kernel_module", "auto":
		default:
			t.Fatalf("unknown datapath %q in %+v", row.Datapath, row)
		}
		switch row.CryptoPlacement {
		case "userspace", "kernel", "auto":
		default:
			t.Fatalf("unknown crypto placement %q in %+v", row.CryptoPlacement, row)
		}
		switch row.ValidationScope {
		case "single_host", "cross_host":
		default:
			t.Fatalf("unknown validation scope %q in %+v", row.ValidationScope, row)
		}
		if !knownGate[row.GateFamily] {
			t.Fatalf("unknown gate family %q in %+v", row.GateFamily, row)
		}
		assertProductionGateFamilySemantics(
			t,
			"production default "+key,
			row.Transport,
			row.Encryption,
			row.Datapath,
			row.CryptoPlacement,
			row.GateFamily,
		)
		minGbps, err := strconv.ParseFloat(row.MinGbps, 64)
		if err != nil || minGbps < 0 {
			t.Fatalf("invalid min_gbps %q in %+v", row.MinGbps, row)
		}
		minSeconds, err := strconv.Atoi(row.MinSeconds)
		if err != nil || minSeconds <= 0 {
			t.Fatalf("invalid min_seconds %q in %+v", row.MinSeconds, row)
		}
		if row.ValidationScope == "cross_host" {
			if !crossHostGate[row.GateFamily] {
				t.Fatalf("cross-host production row uses non-production gate %q: %+v", row.GateFamily, row)
			}
			if minGbps <= 0 || minSeconds < 900 {
				t.Fatalf("cross-host production row lacks throughput/soak gate: %+v", row)
			}
			if minSeconds < 3600 {
				t.Fatalf("cross-host production row must stay on long-soak evidence, got %+v", row)
			}
		}
		if crossHostOnlyGate[row.GateFamily] && row.ValidationScope != "cross_host" {
			t.Fatalf("production gate %q must be cross_host, got %+v", row.GateFamily, row)
		}
		if row.GateFamily == "userspace" &&
			row.Profile == "stable" &&
			row.Datapath == "userspace" &&
			row.CryptoPlacement == "userspace" {
			baseline[row.Transport+":"+row.Encryption] = true
		}
	}
	for _, transport := range []string{"udp", "tcp", "quic", "websocket", "http_connect", "experimental_tcp"} {
		for _, encryption := range []string{"secure", "plaintext"} {
			key := transport + ":" + encryption
			if !baseline[key] {
				t.Fatalf("missing stable userspace baseline for %s", key)
			}
		}
	}
}

func TestE2ESmokeDefaultsAvoidUnsafeDirectKfuncCrypto(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-e2e-smoke.sh"))
	if err != nil {
		t.Fatalf("read linux-e2e-smoke.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT:-50ms",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL:-0",
		"TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN:-0",
		"TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT must be a Go duration or 0",
		"route_tcp_gso_async_worker_emit_budget=0",
		"route_tcp_gso_async_worker_dequeue_batch=4",
		"route_tcp_gso_async_hash_tx_queue=1",
		"route_tcp_gso_async_worker_min_queue_depth=1",
		"route_tcp_gso_async_worker_schedule_delay_usecs=0",
		"experimental_tcp_route_gso_async_worker_item_budget=64",
		"experimental_tcp_route_gso_async_worker_segment_budget=2048",
		"route_tcp_gso_async_worker_item_budget=${experimental_tcp_route_gso_async_worker_item_budget}",
		"route_tcp_gso_async_worker_segment_budget=${experimental_tcp_route_gso_async_worker_segment_budget}",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-e2e-smoke.sh default missing %q", want)
		}
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
		"TRUSTIX_PRODUCTION_SOAK_PERF_FAST:-1",
		"TRUSTIX_PRODUCTION_SOAK_MATRIX_SCOPE:-single_host",
		"TRUSTIX_PRODUCTION_SOAK_CASE_TIMEOUT:-15m",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SCOPE=\"$matrix_scope\"",
		"TRUSTIX_PRODUCTION_SOAK_MATRIX_SCOPE must be single_host, cross_host, or all",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASES",
		"linux-production-transport-matrix.sh",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-production-soak.sh missing %q", want)
		}
	}
}

func TestCrossHostProductionGateRequiresFastPathArtifacts(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-cross-host-production-gate.sh"))
	if err != nil {
		t.Fatalf("read linux-cross-host-production-gate.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"gate_min_gbps=\"${TRUSTIX_CROSS_HOST_GATE_MIN_GBPS:-}\"",
		"TRUSTIX_CROSS_HOST_USERSPACE_MIN_GBPS:-${gate_min_gbps:-0.5}",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_MIN_GBPS:-${gate_min_gbps:-1}",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_MIN_GBPS:-${gate_min_gbps:-0}",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS:-${gate_min_gbps:-3}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS:-${gate_min_gbps:-1.5}",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS:-${gate_min_gbps:-2.5}",
		"max_decimal()",
		"min_decimal()",
		"max_integer()",
		"min_integer()",
		"userspace_min_gbps=\"$(max_decimal \"$userspace_min_gbps\" \"0.5\")\"",
		"userspace_tc_min_gbps=\"$(max_decimal \"$userspace_tc_min_gbps\" \"1\")\"",
		"tc_direct_min_gbps=\"$(max_decimal \"$tc_direct_min_gbps\" \"3\")\"",
		"full_kmod_min_gbps=\"$(max_decimal \"$full_kmod_min_gbps\" \"3\")\"",
		"secure_kudp_min_gbps=\"$(max_decimal \"$secure_kudp_min_gbps\" \"1.5\")\"",
		"route_gso_min_gbps=\"$(max_decimal \"$route_gso_min_gbps\" \"2.5\")\"",
		"TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS:-3600",
		"min_seconds=\"$(max_decimal \"$min_seconds\" \"3600\")\"",
		"seconds_slop=\"$(min_decimal \"$seconds_slop\" \"1\")\"",
		"TRUSTIX_CROSS_HOST_GATE_MIN_IPERF_INTERVALS:-600",
		"min_iperf_intervals=\"$(max_integer \"$min_iperf_intervals\" \"600\")\"",
		"TRUSTIX_CROSS_HOST_GATE_MIN_INTERVAL_GBPS_RATIO:-0.25",
		"min_interval_gbps_ratio=\"$(max_decimal \"$min_interval_gbps_ratio\" \"0.25\")\"",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_CRYPTO_FLOWS:-1",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_DIRECT_ERROR_BUDGET:-64",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_REPLAY_SEEN_RATIO_BUDGET:-0.00002",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_DROP_RATIO_BUDGET:-0.00002",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET:-2",
		"TRUSTIX_CROSS_HOST_COMPAT_MIN_SESSIONS:-1",
		"TRUSTIX_CROSS_HOST_USERSPACE_CASES",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_CASES",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_CASES",
		"TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_DD_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_OWDEB_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_DD_SECURE_KUDP",
		"TRUSTIX_CROSS_HOST_OWDEB_SECURE_KUDP",
		"TRUSTIX_CROSS_HOST_DD_ROUTE_GSO",
		"TRUSTIX_CROSS_HOST_OWDEB_ROUTE_GSO",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS",
		"validate_number TRUSTIX_CROSS_HOST_USERSPACE_MIN_GBPS \"$userspace_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_USERSPACE_TC_MIN_GBPS \"$userspace_tc_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_TC_DIRECT_MIN_GBPS \"$tc_direct_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS \"$full_kmod_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS \"$secure_kudp_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS \"$route_gso_min_gbps\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_SESSIONS \"$full_kmod_min_sessions\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_SESSIONS \"$secure_kudp_min_sessions\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_CRYPTO_FLOWS \"$secure_kudp_min_crypto_flows\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_KUDP_DIRECT_ERROR_BUDGET \"$secure_kudp_direct_error_budget\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_REPLAY_SEEN_RATIO_BUDGET \"$secure_kudp_replay_seen_ratio_budget\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_DROP_RATIO_BUDGET \"$secure_kudp_drop_ratio_budget\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_SESSIONS \"$route_gso_min_sessions\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET \"$route_gso_session_error_budget\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_COMPAT_MIN_SESSIONS \"$compat_min_sessions\"",
		"full_kmod_min_sessions=\"$(max_integer \"$full_kmod_min_sessions\" \"8\")\"",
		"secure_kudp_min_sessions=\"$(max_integer \"$secure_kudp_min_sessions\" \"8\")\"",
		"secure_kudp_min_crypto_flows=\"$(max_integer \"$secure_kudp_min_crypto_flows\" \"1\")\"",
		"secure_kudp_direct_error_budget=\"$(min_integer \"$secure_kudp_direct_error_budget\" \"64\")\"",
		"secure_kudp_replay_seen_ratio_budget=\"$(min_decimal \"$secure_kudp_replay_seen_ratio_budget\" \"0.00002\")\"",
		"secure_kudp_drop_ratio_budget=\"$(min_decimal \"$secure_kudp_drop_ratio_budget\" \"0.00002\")\"",
		"route_gso_min_sessions=\"$(max_integer \"$route_gso_min_sessions\" \"8\")\"",
		"route_gso_session_error_budget=\"$(min_integer \"$route_gso_session_error_budget\" \"2\")\"",
		"compat_min_sessions=\"$(max_integer \"$compat_min_sessions\" \"1\")\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS \"$userspace_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS \"$userspace_tc_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_GBPS \"$tc_direct_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS \"$full_kmod_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS \"$secure_kudp_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS \"$route_gso_case_min_gbps_raw\"",
		"validate_case_seconds_map TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_SECONDS \"$full_kmod_case_min_seconds_raw\"",
		"validate_case_seconds_map TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_SECONDS \"$secure_kudp_case_min_seconds_raw\"",
		"validate_case_seconds_map TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_SECONDS \"$route_gso_case_min_seconds_raw\"",
		"case_min_gbps()",
		"case_min_seconds()",
		"case_policy_stat_args()",
		"session_transport_for_matrix_transport()",
		"session_endpoint_suffix_for_matrix_transport()",
		"case_session_args()",
		"write_gate_manifest()",
		"production-gate-manifest.json",
		"trustix-cross-host-production-gate-manifest-v1",
		"TRUSTIX_GATE_MANIFEST_USERSPACE_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_USERSPACE_TC_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_TC_DIRECT_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_FULL_KMOD_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_SECURE_KUDP_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_ROUTE_GSO_CASE_MIN_GBPS",
		"production_gate",
		"verifier",
		"thresholds",
		"case_min_gbps",
		"write_gate_manifest",
		"must use canonical NAME=PATH from the transport matrix",
		"--require-transport-policy-stat \"encryption=${encryption}\"",
		"--require-transport-policy-stat \"profile=${profile}\"",
		"--require-transport-policy-stat \"datapath=${datapath}\"",
		"--require-transport-policy-stat \"crypto_placement=${placement}\"",
		"--require-transport-session-stat",
		"--require-transport-session-endpoint-suffix",
		"stats.encryption=${encryption}",
		"stats.encrypted=true",
		"stats.send_encrypted=true",
		"stats.receive_encrypted=true",
		"stats.crypto_placement=${placement}",
		"stats.link_tls=true",
		"--require-transport-session-any-min \"stats.bytes_sent=1\"",
		"--require-transport-session-any-min \"stats.bytes_received=1\"",
		"--require-transport-session-any-min \"stats.packets_sent=1\"",
		"--require-transport-session-any-min \"stats.packets_received=1\"",
		"run_gate_case_list()",
		"--min-iperf-intervals \"$min_iperf_intervals\"",
		"--min-iperf-interval-gbps-ratio \"$min_interval_gbps_ratio\"",
		"--require-run-timing",
		"--require-run-timing-stat iperf_mode=forward",
		"--require-run-timing-stat iperf_directions=both",
		"--require-binary-identity",
		"--require-strong-build-identity",
		"--require-stable-boot-id",
		"--require-uname-artifacts",
		"--min-uname-nodes 2",
		"--require-os-release-artifacts",
		"--min-os-release-nodes 2",
		"--require-iperf-pair-directions",
		"--require-kernel-log-artifacts",
		"--min-kernel-log-nodes 2",
		"--require-pstore-artifacts",
		"--min-pstore-nodes 2",
		"--require-lsmod-artifacts",
		"--min-lsmod-nodes 2",
		"--require-lan-state-artifacts",
		"--min-lan-state-nodes 2",
		"--min-lan-tx-queue-len 1",
		"run_gate_case_list userspace \"$userspace_min_gbps\"",
		"run_gate_case_list userspace-tc \"$userspace_tc_min_gbps\"",
		"run_gate_case_list tc-direct \"$tc_direct_min_gbps\"",
		"--require-transport-sessions-min \"${compat_min_sessions}\"",
		"--forbid-lsmod-prefix trustix_",
		"--require-datapath-stat kernel_udp.provider=tc_direct",
		"--require-datapath-stat kernel_udp.fast_path=true",
		"--require-datapath-stat kernel_udp.direct_only=true",
		"--require-datapath-any-min kernel_udp.active_flows=1",
		"--require-transport-policy-stat encryption=secure",
		"--require-transport-policy-stat crypto_placement=kernel",
		"--require-transport-policy-stat datapath=tc_xdp",
		"--require-transport-policy-min session_pool_size=\"${full_kmod_min_sessions}\"",
		"--require-transport-policy-min session_pool_size=\"${secure_kudp_min_sessions}\"",
		"--require-transport-policy-min session_pool_size=\"${route_gso_min_sessions}\"",
		"--require-transport-policy-stat session_pool_strategy=flow",
		"--require-transport-policy-stat session_pool_warmup=true",
		"--require-transport-sessions-min \"${full_kmod_min_sessions}\"",
		"--require-status-min data_path.active_sessions=\"${route_gso_min_sessions}\"",
		"--require-status-max data_path.counters.session_dial_errors=\"${route_gso_session_error_budget}\"",
		"--require-status-max data_path.counters.session_heartbeat_timeouts=0",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1",
		"--require-datapath-stat kernel_udp.kernel_crypto=true",
		"--require-datapath-stat kernel_udp.requested_crypto=kernel",
		"--require-datapath-stat kernel_udp.effective_crypto=kernel",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_flow_map_ready=1",
		"--require-datapath-min kernel_udp.provider_stats.kernel_crypto_flow_map_entries=\"${secure_kudp_min_crypto_flows}\"",
		"--require-datapath-min kernel_udp.provider_stats.kernel_crypto_flow_map_updates=\"${secure_kudp_min_crypto_flows}\"",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_direct_slot_provider_ready=1",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_direct_kfunc_fastpath_ready=1",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_tc_direct_ready=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_only_enabled=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_attached=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_attached=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_kfunc_seal_enabled=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_route_tcp_gso_kfunc=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_enabled=1",
		"--require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_seal_errors=0",
		"--require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_open_errors=0",
		"--require-datapath-min experimental_tcp.provider_stats.kernel_crypto_module_direct_kfunc_seal_calls=1",
		"--require-datapath-min experimental_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=1",
		"--require-datapath-max experimental_tcp.provider_stats.kernel_crypto_module_direct_kfunc_errors=\"${secure_exp_tcp_kernel_direct_error_budget}\"",
		"--require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_encrypt_errors=0",
		"--require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_decrypt_errors=\"${secure_kudp_direct_error_budget}\"",
		"--require-datapath-min kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=1",
		"--require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_old_drops=0",
		"--require-datapath-ratio-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_seen_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=\"${secure_kudp_replay_seen_ratio_budget}\"",
		"--require-datapath-ratio-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=\"${secure_kudp_replay_seen_ratio_budget}\"",
		"--require-datapath-ratio-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=\"${secure_kudp_drop_ratio_budget}\"",
		"--require-module-param-min trustix_crypto.kfunc_simd_fastpath=1",
		"--require-module-param-min trustix_crypto.kfunc_simd_irq_fpu_fastpath=1",
		"--require-module-param-any-min trustix_crypto.direct_kfunc_seal_calls=1",
		"--require-module-param-any-min trustix_crypto.direct_kfunc_open_calls=1",
		"--require-module-param-max trustix_crypto.direct_kfunc_errors=\"${secure_kudp_direct_error_budget}\"",
		"--require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_secure_seal_batch=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_xmit_packets=1",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_flow_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_plan_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_mtu_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_bytes_full=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_alloc_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_clone_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_segment_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_prepare_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_txq_stopped_drops=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_xmit_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_direct_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_cross_item_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_cross_item_tail_stitch_errors=0",
		"--require-datapath-min kernel_rx_stage.rx_worker_injected=1",
		"--require-datapath-min counters.session_dials=\"${full_kmod_min_sessions}\"",
		"--require-datapath-max counters.session_dial_errors=0",
		"--require-module-param-min trustix_datapath.enable_features=128",
		"--require-module-param-min trustix_datapath.features=128",
		"--require-module-param-min trustix_datapath.safe_features=128",
		"--require-module-param-max trustix_datapath.unsafe_features=0",
		"--require-module-param-max trustix_datapath.selftest_failures=0",
		"--require-module-param-min trustix_datapath.rx_worker_inject=1",
		"--require-module-param-min trustix_datapath.tx_plaintext=1",
		"--require-module-param-max trustix_datapath.rx_worker_hot_stats=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_skip_inner_tcp_checksum=0",
		"--require-module-param-min trustix_datapath.session_records=\"${full_kmod_min_sessions}\"",
		"--require-module-param-min trustix_datapath.session_wire_records=\"${full_kmod_min_sessions}\"",
		"--require-module-param-min trustix_datapath.rx_worker_single_coalesce_max_frames=32",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_outer_gso_segments=1",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_direct_xmit_dst_mac_cache_hits=1",
		"--require-module-param-any-min trustix_datapath.rx_worker_gso_xmit_segments=1",
		"--require-module-param-max trustix_datapath.rx_worker_alloc_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_deliver_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_gso_xmit_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_xmit_ret_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_xmit_peer_forward_errors=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_no_sessions=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_no_wires=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_stale_wires=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_xmit_errors=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_queue_drops=0",
		"--require-lsmod-module trustix_datapath",
		"--require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_experimental_tcp_only=1",
		"--require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_hash_tx_queue=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_frames=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_xmit_packets=1",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_full=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_xmit_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_blocked=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_verify_errors=0",
		"--require-lsmod-module trustix_crypto",
		"--require-lsmod-module trustix_datapath_helpers",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-production-gate.sh missing %q", want)
		}
	}
	if got := strings.Count(text, "--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_frames=1"); got != 1 {
		t.Fatalf("linux-cross-host-production-gate.sh should require outer-GSO frames only for route-GSO, got %d occurrences", got)
	}
	if strings.Contains(text, "TRUSTIX_CROSS_HOST_GATE_REQUIRE_BINARY_IDENTITY") {
		t.Fatalf("linux-cross-host-production-gate.sh must not allow disabling binary identity checks")
	}
	for _, unwanted := range []string{
		"TRUSTIX_CROSS_HOST_DD_FULL_KMOD_EXPERIMENTAL_TCP",
		"dd-fullkmod-experimental-tcp",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-cross-host-production-gate.sh still promotes diagnostic full-kmod experimental_tcp case %q", unwanted)
		}
	}
}

func shellIfBlock(t *testing.T, text, marker string) string {
	t.Helper()
	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatalf("script block marker missing %q", marker)
	}
	block := text[start:]
	end := strings.Index(block, "\n  fi")
	if end < 0 {
		t.Fatalf("script block for marker %q has no closing fi", marker)
	}
	return block[:end]
}

func TestCrossHostProductionGateFastPathBlocksPinTransportPolicy(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-cross-host-production-gate.sh"))
	if err != nil {
		t.Fatalf("read linux-cross-host-production-gate.sh: %v", err)
	}
	text := string(payload)
	tests := []struct {
		name   string
		marker string
		want   []string
	}{
		{
			name:   "tc-direct",
			marker: `if [[ "$tc_direct_case_count" -gt 0 ]]; then`,
			want: []string{
				"run_gate_case_list tc-direct \"$tc_direct_min_gbps\"",
				"--require-transport-policy-stat encryption=plaintext",
				"--require-transport-policy-stat profile=performance",
				"--require-transport-policy-stat datapath=tc_xdp",
				"--require-transport-policy-stat crypto_placement=userspace",
				"--require-status-max data_path.counters.session_heartbeat_timeouts=0",
			},
		},
		{
			name:   "full-kmod",
			marker: `if [[ "$full_kmod_case_count" -gt 0 ]]; then`,
			want: []string{
				"run_gate_case_list full-kmod \"$full_kmod_min_gbps\"",
				"--require-transport-policy-stat encryption=plaintext",
				"--require-transport-policy-stat profile=performance",
				"--require-transport-policy-stat datapath=kernel_module",
				"--require-transport-policy-stat crypto_placement=userspace",
				"--require-status-max data_path.counters.session_heartbeat_timeouts=0",
			},
		},
		{
			name:   "route-gso",
			marker: `if [[ "$route_gso_case_count" -gt 0 ]]; then`,
			want: []string{
				"run_gate_case_list route-gso \"$route_gso_min_gbps\"",
				"--require-transport-policy-stat encryption=plaintext",
				"--require-transport-policy-stat profile=performance",
				"--require-transport-policy-stat datapath=kernel_module",
				"--require-transport-policy-stat crypto_placement=userspace",
				"--require-status-max data_path.counters.session_heartbeat_timeouts=0",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			block := shellIfBlock(t, text, tc.marker)
			for _, want := range tc.want {
				if !strings.Contains(block, want) {
					t.Fatalf("%s gate block missing %q:\n%s", tc.name, want, block)
				}
			}
		})
	}
}

func requirePython3(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, "-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)")
		if err := cmd.Run(); err == nil {
			return path
		}
	}
	t.Skip("usable python3 not available")
	return ""
}

func requireBashAndPython3(t *testing.T) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}
	requirePython3(t)
	return bash
}

func slashPath(path string) string {
	return filepath.ToSlash(path)
}

func TestCrossHostProductionGateUsesPerCaseMinGbps(t *testing.T) {
	bash := requireBashAndPython3(t)
	workdir := t.TempDir()
	verifier := filepath.Join(workdir, "verifier.py")
	calls := filepath.Join(workdir, "calls.jsonl")
	summaryDir := filepath.Join(workdir, "summary")
	if err := os.WriteFile(verifier, []byte(strings.Join([]string{
		"import json, os, sys",
		"with open(os.environ['TRUSTIX_CAPTURE'], 'a', encoding='utf-8') as handle:",
		"    handle.write(json.dumps(sys.argv[1:]) + '\\n')",
		"",
	}, "\n")), 0o755); err != nil {
		t.Fatalf("write verifier stub: %v", err)
	}

	fastName := "udp-secure-stable-userspace-userspace"
	slowName := "tcp-plaintext-stable-userspace-userspace"
	secureTLSName := "tcp-secure-stable-userspace-userspace"
	userspaceTCName := "gre-plaintext-performance-tc_xdp-userspace"
	fastDir := slashPath(filepath.Join(workdir, "fast"))
	slowDir := slashPath(filepath.Join(workdir, "slow"))
	secureTLSDir := slashPath(filepath.Join(workdir, "secure-tls"))
	userspaceTCDir := slashPath(filepath.Join(workdir, "userspace-tc"))
	tcDirectDir := slashPath(filepath.Join(workdir, "tc-direct"))
	fullKmodDir := slashPath(filepath.Join(workdir, "full-kmod"))
	secureKUDPDir := slashPath(filepath.Join(workdir, "secure-kudp"))
	routeGSODir := slashPath(filepath.Join(workdir, "route-gso"))
	cmd := exec.Command(bash, "linux-cross-host-production-gate.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CAPTURE="+slashPath(calls),
		"TRUSTIX_CROSS_HOST_GATE_VERIFIER="+slashPath(verifier),
		"TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR="+slashPath(summaryDir),
		"TRUSTIX_CROSS_HOST_GATE_REQUIRE_BINARY_IDENTITY=0",
		"TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS=30",
		"TRUSTIX_CROSS_HOST_GATE_SECONDS_SLOP=999",
		"TRUSTIX_CROSS_HOST_GATE_MIN_IPERF_INTERVALS=0",
		"TRUSTIX_CROSS_HOST_GATE_MIN_INTERVAL_GBPS_RATIO=0",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_SESSIONS=0",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_SESSIONS=0",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_CRYPTO_FLOWS=0",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_DIRECT_ERROR_BUDGET=999",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_REPLAY_SEEN_RATIO_BUDGET=999999",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_DROP_RATIO_BUDGET=999999",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_SESSIONS=0",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET=999",
		"TRUSTIX_CROSS_HOST_COMPAT_MIN_SESSIONS=0",
		"TRUSTIX_CROSS_HOST_USERSPACE_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_USERSPACE_CASES="+fastName+"="+fastDir+" "+slowName+"="+slowDir+" "+secureTLSName+"="+secureTLSDir,
		"TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS="+fastName+"=1.5 "+slowName+"=0 "+secureTLSName+"=0",
		"TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_SECONDS="+fastName+"=900 "+slowName+"=900 "+secureTLSName+"=900",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_CASES="+userspaceTCName+"="+userspaceTCDir,
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS="+userspaceTCName+"=0",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_SECONDS="+userspaceTCName+"=900",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_CASES=tc="+tcDirectDir,
		"TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_GBPS=tc=0",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_SECONDS=tc=3600",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_CASES=full="+fullKmodDir,
		"TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS=full=0",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_SECONDS=full=3600",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES=secure="+secureKUDPDir,
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS=secure=0",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_SECONDS=secure=3600",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_CASES=route="+routeGSODir,
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS=route=0",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_SECONDS=route=3600",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production gate with per-case min_gbps failed: %v\n%s", err, output)
	}
	manifestPayload, err := os.ReadFile(filepath.Join(summaryDir, "production-gate-manifest.json"))
	if err != nil {
		t.Fatalf("read production gate manifest: %v", err)
	}
	var manifest struct {
		Schema         string `json:"schema"`
		ProductionGate struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Size   int    `json:"size"`
		} `json:"production_gate"`
		Verifier struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Size   int    `json:"size"`
		} `json:"verifier"`
		Thresholds     map[string]string `json:"thresholds"`
		Cases          map[string]string `json:"cases"`
		CaseMinGbps    map[string]string `json:"case_min_gbps"`
		CaseMinSeconds map[string]string `json:"case_min_seconds"`
	}
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		t.Fatalf("decode production gate manifest: %v\n%s", err, manifestPayload)
	}
	if manifest.Schema != "trustix-cross-host-production-gate-manifest-v1" {
		t.Fatalf("manifest schema = %q", manifest.Schema)
	}
	if manifest.ProductionGate.SHA256 == "" || manifest.ProductionGate.Size <= 0 || !strings.Contains(filepath.ToSlash(manifest.ProductionGate.Path), "linux-cross-host-production-gate.sh") {
		t.Fatalf("manifest production gate identity is incomplete: %+v", manifest.ProductionGate)
	}
	if manifest.Verifier.SHA256 == "" || manifest.Verifier.Size <= 0 || filepath.ToSlash(manifest.Verifier.Path) != slashPath(verifier) {
		t.Fatalf("manifest verifier identity is incomplete: %+v", manifest.Verifier)
	}
	for key, want := range map[string]string{
		"min_seconds":                          "3600",
		"seconds_slop":                         "1",
		"min_iperf_intervals":                  "600",
		"min_interval_gbps_ratio":              "0.25",
		"full_kmod_min_sessions":               "8",
		"secure_kudp_min_sessions":             "8",
		"secure_kudp_min_crypto_flows":         "1",
		"secure_kudp_direct_error_budget":      "64",
		"secure_kudp_replay_seen_ratio_budget": "0.00002",
		"secure_kudp_drop_ratio_budget":        "0.00002",
		"route_gso_min_sessions":               "8",
		"route_gso_session_error_budget":       "2",
		"compat_min_sessions":                  "1",
	} {
		if manifest.Thresholds[key] != want {
			t.Fatalf("manifest threshold %s = %q, want %q\n%s", key, manifest.Thresholds[key], want, manifestPayload)
		}
	}
	for key, wantSubstring := range map[string]string{
		"userspace":    secureTLSName + "=" + secureTLSDir,
		"userspace_tc": userspaceTCName + "=" + userspaceTCDir,
		"tc_direct":    "tc=" + tcDirectDir,
		"full_kmod":    "full=" + fullKmodDir,
		"secure_kudp":  "secure=" + secureKUDPDir,
		"route_gso":    "route=" + routeGSODir,
	} {
		if !strings.Contains(manifest.Cases[key], wantSubstring) {
			t.Fatalf("manifest cases[%s] missing %q:\n%s", key, wantSubstring, manifestPayload)
		}
	}
	for key, wantSubstring := range map[string]string{
		"userspace":    fastName + "=1.5",
		"userspace_tc": userspaceTCName + "=0",
		"tc_direct":    "tc=0",
		"full_kmod":    "full=0",
		"secure_kudp":  "secure=0",
		"route_gso":    "route=0",
	} {
		if !strings.Contains(manifest.CaseMinGbps[key], wantSubstring) {
			t.Fatalf("manifest case_min_gbps[%s] missing %q:\n%s", key, wantSubstring, manifestPayload)
		}
	}
	for key, wantSubstring := range map[string]string{
		"userspace":    fastName + "=900",
		"userspace_tc": userspaceTCName + "=900",
		"tc_direct":    "tc=3600",
		"full_kmod":    "full=3600",
		"secure_kudp":  "secure=3600",
		"route_gso":    "route=3600",
	} {
		if !strings.Contains(manifest.CaseMinSeconds[key], wantSubstring) {
			t.Fatalf("manifest case_min_seconds[%s] missing %q:\n%s", key, wantSubstring, manifestPayload)
		}
	}
	payload, err := os.ReadFile(calls)
	if err != nil {
		t.Fatalf("read verifier calls: %v", err)
	}
	gotMinGbps := map[string]string{}
	gotMinSeconds := map[string]string{}
	gotMinIperfIntervals := map[string]string{}
	gotMinIntervalGbpsRatio := map[string]string{}
	gotMinKernelLogNodes := map[string]string{}
	gotRequireRunTiming := map[string]bool{}
	gotRequireIdentity := map[string]bool{}
	gotRequireStableBootID := map[string]bool{}
	gotRequireUname := map[string]bool{}
	gotMinUnameNodes := map[string]string{}
	gotRequireOSRelease := map[string]bool{}
	gotMinOSReleaseNodes := map[string]string{}
	gotRequirePairDirections := map[string]bool{}
	gotRequireKernelLogs := map[string]bool{}
	gotArgs := map[string][]string{}
	gotRequirePstore := map[string]bool{}
	gotMinPstoreNodes := map[string]string{}
	gotRequireLsmod := map[string]bool{}
	gotMinLsmodNodes := map[string]string{}
	gotRequireLANState := map[string]bool{}
	gotMinLANStateNodes := map[string]string{}
	gotMinLANTxQueueLen := map[string]string{}
	gotRequireStrongIdentity := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var args []string
		if err := json.Unmarshal([]byte(line), &args); err != nil {
			t.Fatalf("decode verifier args %q: %v", line, err)
		}
		var caseName, minGbps, minSeconds string
		var minIperfIntervals, minIntervalGbpsRatio string
		var minKernelLogNodes string
		requireIdentity := false
		for i := 0; i+1 < len(args); i++ {
			switch args[i] {
			case "--case":
				caseName = strings.SplitN(args[i+1], "=", 2)[0]
			case "--min-gbps":
				minGbps = args[i+1]
			case "--min-seconds":
				minSeconds = args[i+1]
			case "--min-iperf-intervals":
				minIperfIntervals = args[i+1]
			case "--min-iperf-interval-gbps-ratio":
				minIntervalGbpsRatio = args[i+1]
			case "--min-uname-nodes":
				gotMinUnameNodes[caseName] = args[i+1]
			case "--min-os-release-nodes":
				gotMinOSReleaseNodes[caseName] = args[i+1]
			case "--min-kernel-log-nodes":
				minKernelLogNodes = args[i+1]
			case "--min-pstore-nodes":
				gotMinPstoreNodes[caseName] = args[i+1]
			case "--min-lsmod-nodes":
				gotMinLsmodNodes[caseName] = args[i+1]
			case "--min-lan-state-nodes":
				gotMinLANStateNodes[caseName] = args[i+1]
			case "--min-lan-tx-queue-len":
				gotMinLANTxQueueLen[caseName] = args[i+1]
			}
		}
		for _, arg := range args {
			if arg == "--require-run-timing" {
				gotRequireRunTiming[caseName] = true
			}
			if arg == "--require-binary-identity" {
				requireIdentity = true
			}
			if arg == "--require-strong-build-identity" {
				gotRequireStrongIdentity[caseName] = true
			}
		}
		requireStableBootID := false
		for _, arg := range args {
			if arg == "--require-stable-boot-id" {
				requireStableBootID = true
			}
		}
		requireUname := false
		for _, arg := range args {
			if arg == "--require-uname-artifacts" {
				requireUname = true
			}
		}
		requireOSRelease := false
		for _, arg := range args {
			if arg == "--require-os-release-artifacts" {
				requireOSRelease = true
			}
		}
		requirePairDirections := false
		for _, arg := range args {
			if arg == "--require-iperf-pair-directions" {
				requirePairDirections = true
			}
		}
		requireKernelLogs := false
		for _, arg := range args {
			if arg == "--require-kernel-log-artifacts" {
				requireKernelLogs = true
			}
		}
		requirePstore := false
		for _, arg := range args {
			if arg == "--require-pstore-artifacts" {
				requirePstore = true
			}
		}
		requireLsmod := false
		for _, arg := range args {
			if arg == "--require-lsmod-artifacts" {
				requireLsmod = true
			}
		}
		requireLANState := false
		for _, arg := range args {
			if arg == "--require-lan-state-artifacts" {
				requireLANState = true
			}
		}
		if caseName != "" {
			gotMinGbps[caseName] = minGbps
			gotMinSeconds[caseName] = minSeconds
			gotMinIperfIntervals[caseName] = minIperfIntervals
			gotMinIntervalGbpsRatio[caseName] = minIntervalGbpsRatio
			gotMinKernelLogNodes[caseName] = minKernelLogNodes
			gotRequireIdentity[caseName] = requireIdentity
			gotRequireStableBootID[caseName] = requireStableBootID
			gotRequireUname[caseName] = requireUname
			gotRequireOSRelease[caseName] = requireOSRelease
			gotRequirePairDirections[caseName] = requirePairDirections
			gotRequireKernelLogs[caseName] = requireKernelLogs
			gotRequirePstore[caseName] = requirePstore
			gotRequireLsmod[caseName] = requireLsmod
			gotRequireLANState[caseName] = requireLANState
			gotArgs[caseName] = args
		}
	}
	for name, want := range map[string]string{
		fastName:        "1.5",
		slowName:        "0.5",
		userspaceTCName: "1",
		"tc":            "3",
		"full":          "3",
		"secure":        "1.5",
		"route":         "2.5",
	} {
		if gotMinGbps[name] != want {
			t.Fatalf("case %s min_gbps got %q want %q; calls=%s", name, gotMinGbps[name], want, payload)
		}
		wantSeconds := "3600"
		if gotMinSeconds[name] != wantSeconds {
			t.Fatalf("case %s min_seconds got %q want %s; calls=%s", name, gotMinSeconds[name], wantSeconds, payload)
		}
		if gotMinIperfIntervals[name] != "600" {
			t.Fatalf("case %s min iperf intervals got %q want 600; calls=%s", name, gotMinIperfIntervals[name], payload)
		}
		if gotMinIntervalGbpsRatio[name] != "0.25" {
			t.Fatalf("case %s min interval gbps ratio got %q want 0.25; calls=%s", name, gotMinIntervalGbpsRatio[name], payload)
		}
		if !gotRequireRunTiming[name] {
			t.Fatalf("case %s did not force --require-run-timing; calls=%s", name, payload)
		}
		if !gotRequireIdentity[name] {
			t.Fatalf("case %s did not force --require-binary-identity; calls=%s", name, payload)
		}
		if !gotRequireStrongIdentity[name] {
			t.Fatalf("case %s did not force --require-strong-build-identity; calls=%s", name, payload)
		}
		if !gotRequireStableBootID[name] {
			t.Fatalf("case %s did not force --require-stable-boot-id; calls=%s", name, payload)
		}
		if !gotRequireUname[name] {
			t.Fatalf("case %s did not force --require-uname-artifacts; calls=%s", name, payload)
		}
		if gotMinUnameNodes[name] != "2" {
			t.Fatalf("case %s min uname nodes got %q want 2; calls=%s", name, gotMinUnameNodes[name], payload)
		}
		if !gotRequireOSRelease[name] {
			t.Fatalf("case %s did not force --require-os-release-artifacts; calls=%s", name, payload)
		}
		if gotMinOSReleaseNodes[name] != "2" {
			t.Fatalf("case %s min os-release nodes got %q want 2; calls=%s", name, gotMinOSReleaseNodes[name], payload)
		}
		if !gotRequirePairDirections[name] {
			t.Fatalf("case %s did not force --require-iperf-pair-directions; calls=%s", name, payload)
		}
		if !gotRequireKernelLogs[name] {
			t.Fatalf("case %s did not force --require-kernel-log-artifacts; calls=%s", name, payload)
		}
		if gotMinKernelLogNodes[name] != "2" {
			t.Fatalf("case %s min kernel log nodes got %q want 2; calls=%s", name, gotMinKernelLogNodes[name], payload)
		}
		if !gotRequirePstore[name] {
			t.Fatalf("case %s did not force --require-pstore-artifacts; calls=%s", name, payload)
		}
		if gotMinPstoreNodes[name] != "2" {
			t.Fatalf("case %s min pstore nodes got %q want 2; calls=%s", name, gotMinPstoreNodes[name], payload)
		}
		if !gotRequireLsmod[name] {
			t.Fatalf("case %s did not force --require-lsmod-artifacts; calls=%s", name, payload)
		}
		if gotMinLsmodNodes[name] != "2" {
			t.Fatalf("case %s min lsmod nodes got %q want 2; calls=%s", name, gotMinLsmodNodes[name], payload)
		}
		if !gotRequireLANState[name] {
			t.Fatalf("case %s did not force --require-lan-state-artifacts; calls=%s", name, payload)
		}
		if gotMinLANStateNodes[name] != "2" {
			t.Fatalf("case %s min LAN state nodes got %q want 2; calls=%s", name, gotMinLANStateNodes[name], payload)
		}
		if gotMinLANTxQueueLen[name] != "1" {
			t.Fatalf("case %s min LAN tx queue len got %q want 1; calls=%s", name, gotMinLANTxQueueLen[name], payload)
		}
	}
	requireArgPair := func(caseName, key, value string) {
		t.Helper()
		args := gotArgs[caseName]
		for i := 0; i+1 < len(args); i++ {
			if args[i] == key && args[i+1] == value {
				return
			}
		}
		t.Fatalf("case %s missing %s %s; calls=%s", caseName, key, value, payload)
	}
	requireArg := func(caseName, value string) {
		t.Helper()
		args := gotArgs[caseName]
		for _, arg := range args {
			if arg == value {
				return
			}
		}
		t.Fatalf("case %s missing %s; calls=%s", caseName, value, payload)
	}
	for _, name := range []string{fastName, slowName, userspaceTCName, "tc", "full", "secure", "route"} {
		requireArgPair(name, "--require-run-timing-stat", "iperf_mode=forward")
		requireArgPair(name, "--require-run-timing-stat", "iperf_directions=both")
	}
	requireTrafficArgs := func(caseName string) {
		t.Helper()
		requireArgPair(caseName, "--require-transport-session-any-min", "stats.bytes_sent=1")
		requireArgPair(caseName, "--require-transport-session-any-min", "stats.bytes_received=1")
		requireArgPair(caseName, "--require-transport-session-any-min", "stats.packets_sent=1")
		requireArgPair(caseName, "--require-transport-session-any-min", "stats.packets_received=1")
	}
	requireEndpointArgs := func(caseName, transport, profile, datapath, encryption string) {
		t.Helper()
		requireArgPair(caseName, "--require-transport-local-endpoint-stat", "transport="+transport)
		requireArgPair(caseName, "--require-transport-local-endpoint-stat", "usable=true")
		requireArgPair(caseName, "--require-transport-local-endpoint-stat", "profile="+profile)
		requireArgPair(caseName, "--require-transport-local-endpoint-stat", "datapath="+datapath)
		requireArgPair(caseName, "--require-transport-local-endpoint-stat", "encryption="+encryption)
		requireArgPair(caseName, "--require-transport-peer-endpoint-stat", "transport="+transport)
		requireArgPair(caseName, "--require-transport-peer-endpoint-stat", "usable=true")
		requireArgPair(caseName, "--require-transport-peer-endpoint-stat", "profile_compatible=true")
		requireArgPair(caseName, "--require-transport-peer-endpoint-stat", "security_compatible=true")
	}
	forbidArgPair := func(caseName, key, value string) {
		t.Helper()
		args := gotArgs[caseName]
		for i := 0; i+1 < len(args); i++ {
			if args[i] == key && args[i+1] == value {
				t.Fatalf("case %s unexpectedly has %s %s; calls=%s", caseName, key, value, payload)
			}
		}
	}
	forbidPeerEndpointEncryption := func(caseName, encryption string) {
		t.Helper()
		forbidArgPair(caseName, "--require-transport-peer-endpoint-stat", "encryption="+encryption)
	}
	requireSecureEndpointPlacement := func(caseName, placement string) {
		t.Helper()
		requireArgPair(caseName, "--require-transport-local-endpoint-stat", "crypto_placements="+placement)
	}
	requireArgPair(fastName, "--require-transport-policy-stat", "encryption=secure")
	requireArgPair(fastName, "--require-transport-policy-stat", "profile=stable")
	requireArgPair(fastName, "--require-transport-policy-stat", "datapath=userspace")
	requireArgPair(fastName, "--require-transport-policy-stat", "crypto_placement=userspace")
	requireEndpointArgs(fastName, "udp", "stable", "userspace", "secure")
	forbidPeerEndpointEncryption(fastName, "secure")
	requireSecureEndpointPlacement(fastName, "userspace")
	requireArgPair(fastName, "--seconds-slop", "1")
	requireArgPair(fastName, "--require-transport-sessions-min", "1")
	requireArgPair(fastName, "--require-transport-session-stat", "transport=udp")
	requireArg(fastName, "--require-transport-session-endpoint-suffix=-udp")
	requireArgPair(fastName, "--require-transport-session-stat", "stats.encryption=secure")
	requireArgPair(fastName, "--require-transport-session-stat", "stats.encrypted=true")
	requireArgPair(fastName, "--require-transport-session-stat", "stats.send_encrypted=true")
	requireArgPair(fastName, "--require-transport-session-stat", "stats.receive_encrypted=true")
	requireArgPair(fastName, "--require-transport-session-stat", "stats.crypto_placement=userspace")
	requireTrafficArgs(fastName)
	requireArgPair(slowName, "--require-transport-policy-stat", "encryption=plaintext")
	requireArgPair(slowName, "--require-transport-policy-stat", "profile=stable")
	requireArgPair(slowName, "--require-transport-policy-stat", "datapath=userspace")
	requireArgPair(slowName, "--require-transport-policy-stat", "crypto_placement=userspace")
	requireEndpointArgs(slowName, "tcp", "stable", "userspace", "plaintext")
	forbidPeerEndpointEncryption(slowName, "plaintext")
	requireArgPair(slowName, "--require-transport-session-stat", "transport=tcp")
	requireArg(slowName, "--require-transport-session-endpoint-suffix=-tcp")
	requireArgPair(slowName, "--require-transport-session-stat", "stats.encryption=plaintext")
	requireArgPair(slowName, "--require-transport-session-stat", "stats.link_tls=true")
	requireTrafficArgs(slowName)
	requireEndpointArgs(secureTLSName, "tcp", "stable", "userspace", "secure")
	forbidPeerEndpointEncryption(secureTLSName, "secure")
	forbidArgPair(secureTLSName, "--require-transport-local-endpoint-stat", "crypto_placements=userspace")
	requireArgPair(secureTLSName, "--require-transport-session-stat", "transport=tcp")
	requireArg(secureTLSName, "--require-transport-session-endpoint-suffix=-tcp")
	requireArgPair(secureTLSName, "--require-transport-session-stat", "stats.encryption=secure")
	requireArgPair(secureTLSName, "--require-transport-session-stat", "stats.encrypted=true")
	requireArgPair(secureTLSName, "--require-transport-session-stat", "stats.send_encrypted=true")
	requireArgPair(secureTLSName, "--require-transport-session-stat", "stats.receive_encrypted=true")
	requireArgPair(secureTLSName, "--require-transport-session-stat", "stats.crypto_placement=userspace")
	requireArgPair(secureTLSName, "--require-transport-session-stat", "stats.link_tls=true")
	requireTrafficArgs(secureTLSName)
	requireArgPair(userspaceTCName, "--require-transport-policy-stat", "encryption=plaintext")
	requireArgPair(userspaceTCName, "--require-transport-policy-stat", "profile=performance")
	requireArgPair(userspaceTCName, "--require-transport-policy-stat", "datapath=tc_xdp")
	requireArgPair(userspaceTCName, "--require-transport-policy-stat", "crypto_placement=userspace")
	requireEndpointArgs(userspaceTCName, "gre", "performance", "tc_xdp", "plaintext")
	forbidPeerEndpointEncryption(userspaceTCName, "plaintext")
	requireArgPair(userspaceTCName, "--require-transport-session-stat", "transport=gre")
	requireArg(userspaceTCName, "--require-transport-session-endpoint-suffix=-gre")
	requireArgPair(userspaceTCName, "--require-transport-session-stat", "stats.encryption=plaintext")
	requireTrafficArgs(userspaceTCName)
	requireArgPair(fastName, "--forbid-lsmod-prefix", "trustix_")
	requireArgPair(slowName, "--forbid-lsmod-prefix", "trustix_")
	requireArgPair(userspaceTCName, "--forbid-lsmod-prefix", "trustix_")
	requireEndpointArgs("tc", "udp", "performance", "tc_xdp", "plaintext")
	requireArgPair("tc", "--require-datapath-any-min", "kernel_udp.active_flows=1")
	requireArgPair("tc", "--forbid-lsmod-prefix", "trustix_")
	requireArgPair("full", "--require-transport-policy-min", "session_pool_size=8")
	requireEndpointArgs("full", "udp", "performance", "kernel_module", "plaintext")
	requireArgPair("full", "--require-transport-sessions-min", "8")
	requireArgPair("full", "--require-transport-session-stat", "transport=udp")
	requireArg("full", "--require-transport-session-endpoint-suffix=-udp")
	requireArgPair("full", "--require-transport-session-stat", "stats.encryption=plaintext")
	requireArgPair("full", "--require-datapath-min", "counters.session_dials=8")
	requireArgPair("full", "--require-module-param-min", "trustix_datapath.features=128")
	requireArgPair("full", "--require-module-param-min", "trustix_datapath.safe_features=128")
	requireArgPair("full", "--require-module-param-max", "trustix_datapath.unsafe_features=0")
	requireArgPair("full", "--require-module-param-max", "trustix_datapath.selftest_failures=0")
	requireArgPair("full", "--require-module-param-min", "trustix_datapath.rx_worker_inject=1")
	requireArgPair("full", "--require-module-param-min", "trustix_datapath.tx_plaintext=1")
	requireArgPair("full", "--require-module-param-min", "trustix_datapath.session_records=8")
	requireArgPair("full", "--require-lsmod-module", "trustix_datapath")
	requireArgPair("secure", "--require-transport-policy-min", "session_pool_size=8")
	requireEndpointArgs("secure", "udp", "performance", "tc_xdp", "secure")
	requireSecureEndpointPlacement("secure", "kernel")
	requireArgPair("secure", "--require-transport-session-stat", "transport=udp")
	requireArg("secure", "--require-transport-session-endpoint-suffix=-udp")
	requireArgPair("secure", "--require-transport-session-stat", "stats.encryption=secure")
	requireArgPair("secure", "--require-transport-session-stat", "stats.encrypted=true")
	requireArgPair("secure", "--require-transport-session-stat", "stats.send_encrypted=true")
	requireArgPair("secure", "--require-transport-session-stat", "stats.receive_encrypted=true")
	requireArgPair("secure", "--require-transport-session-stat", "stats.crypto_placement=kernel")
	requireArgPair("secure", "--require-datapath-min", "kernel_udp.provider_stats.kernel_crypto_flow_map_entries=1")
	requireArgPair("secure", "--require-datapath-min", "kernel_udp.provider_stats.kernel_crypto_flow_map_updates=1")
	requireArgPair("secure", "--require-datapath-max", "kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_decrypt_errors=64")
	requireArgPair("secure", "--require-datapath-min", "kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=1")
	requireArgPair("secure", "--require-datapath-max", "kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_old_drops=0")
	requireArgPair("secure", "--require-datapath-ratio-max", "kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_seen_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=0.00002")
	requireArgPair("secure", "--require-datapath-ratio-max", "kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=0.00002")
	requireArgPair("secure", "--require-datapath-ratio-max", "kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=0.00002")
	requireArgPair("secure", "--require-module-param-max", "trustix_crypto.direct_kfunc_errors=64")
	requireArgPair("secure", "--require-lsmod-module", "trustix_crypto")
	requireArgPair("secure", "--require-lsmod-module", "trustix_datapath_helpers")
	requireArgPair("route", "--require-transport-policy-min", "session_pool_size=8")
	requireEndpointArgs("route", "experimental_tcp", "performance", "kernel_module", "plaintext")
	requireArgPair("route", "--require-transport-sessions-min", "8")
	requireArgPair("route", "--require-transport-session-stat", "transport=experimental_tcp")
	requireArg("route", "--require-transport-session-endpoint-suffix=-experimental-tcp")
	requireArgPair("route", "--require-transport-session-stat", "stats.encryption=plaintext")
	requireArgPair("route", "--require-status-min", "data_path.active_sessions=8")
	requireArgPair("route", "--require-status-max", "data_path.counters.session_dial_errors=2")
	requireArgPair("route", "--require-lsmod-module", "trustix_datapath_helpers")
}

func TestCrossHostTransportMatrixPassesSelectedGatePerCaseMinGbps(t *testing.T) {
	bash := requireBashAndPython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	runner := filepath.Join(workdir, "runner.sh")
	verifier := filepath.Join(workdir, "verifier.py")
	productionGate := filepath.Join(workdir, "production-gate.sh")
	capture := filepath.Join(workdir, "selected-gate.env")
	matrixWorkdir := filepath.Join(workdir, "matrix")
	if err := os.WriteFile(defaults, []byte(strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t1.5\t30\tselected UDP userspace gate",
		"tcp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t0.75\t30\tselected TCP userspace gate",
		"gre\tplaintext\tperformance\ttc_xdp\tuserspace\tcross_host\tuserspace_tc\t4\t30\tselected GRE userspace-TC gate",
		"experimental_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\troute_gso\t2.5\t3600\tselected route-GSO gate",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	if err := os.WriteFile(runner, []byte(strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -e",
		"mkdir -p \"$TRUSTIX_CROSS_HOST_WORKDIR\"",
		"",
	}, "\n")), 0o755); err != nil {
		t.Fatalf("write runner stub: %v", err)
	}
	if err := os.WriteFile(verifier, []byte("import sys\nsys.exit(0)\n"), 0o755); err != nil {
		t.Fatalf("write verifier stub: %v", err)
	}
	if err := os.WriteFile(productionGate, []byte(strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -e",
		"{",
		"  printf 'GATE_MIN_SECONDS=%s\\n' \"${TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS:-}\"",
		"  printf 'GATE_SECONDS_SLOP=%s\\n' \"${TRUSTIX_CROSS_HOST_GATE_SECONDS_SLOP:-}\"",
		"  printf 'GATE_SUMMARY_DIR=%s\\n' \"${TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR:-}\"",
		"  printf 'USERSPACE_CASES=%s\\n' \"$TRUSTIX_CROSS_HOST_USERSPACE_CASES\"",
		"  printf 'USERSPACE_CASE_MIN_GBPS=%s\\n' \"$TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS\"",
		"  printf 'USERSPACE_CASE_MIN_SECONDS=%s\\n' \"$TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_SECONDS\"",
		"  printf 'USERSPACE_TC_CASE_MIN_GBPS=%s\\n' \"$TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS\"",
		"  printf 'USERSPACE_TC_CASE_MIN_SECONDS=%s\\n' \"$TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_SECONDS\"",
		"  printf 'ROUTE_GSO_CASE_MIN_GBPS=%s\\n' \"$TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS\"",
		"  printf 'ROUTE_GSO_CASE_MIN_SECONDS=%s\\n' \"$TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_SECONDS\"",
		"} > \"$TRUSTIX_CAPTURE\"",
		"",
	}, "\n")), 0o755); err != nil {
		t.Fatalf("write production gate stub: %v", err)
	}

	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CAPTURE="+slashPath(capture),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+slashPath(defaults),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+slashPath(matrixWorkdir),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER="+slashPath(runner),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER="+slashPath(verifier),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE="+slashPath(productionGate),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_REQUIRE_BINARY_IDENTITY=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SECONDS=5",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SECONDS_SLOP=999",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("matrix selected gate capture failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("read selected gate capture: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"GATE_MIN_SECONDS=",
		"GATE_SECONDS_SLOP=1",
		"GATE_SUMMARY_DIR=" + slashPath(filepath.Join(matrixWorkdir, "selected-production-gate")),
		"udp-secure-stable-userspace-userspace=1.5",
		"tcp-secure-stable-userspace-userspace=0.75",
		"udp-secure-stable-userspace-userspace=30",
		"tcp-secure-stable-userspace-userspace=30",
		"gre-plaintext-performance-tc_xdp-userspace=4",
		"gre-plaintext-performance-tc_xdp-userspace=30",
		"experimental_tcp-plaintext-performance-kernel_module-userspace=2.5",
		"experimental_tcp-plaintext-performance-kernel_module-userspace=3600",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("selected gate capture missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "GATE_MIN_SECONDS=3600") || strings.Contains(text, "GATE_MIN_SECONDS=30") {
		t.Fatalf("selected gate should pass per-case min seconds instead of a global max:\n%s", text)
	}
}

func TestCrossHostTransportMatrixEmitsManifestBackedEvidence(t *testing.T) {
	bash := requireBashAndPython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	runner := filepath.Join(workdir, "runner.sh")
	verifier := filepath.Join(workdir, "verifier.py")
	productionGate := filepath.Join(workdir, "production-gate.sh")
	matrixWorkdir := filepath.Join(workdir, "matrix")
	evidenceOut := filepath.Join(workdir, "evidence.tsv")
	if err := os.WriteFile(defaults, []byte(strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t1.5\t30\tselected UDP userspace gate",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	if err := os.WriteFile(runner, []byte(strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -e",
		"mkdir -p \"$TRUSTIX_CROSS_HOST_WORKDIR\"",
		"printf 'pass\\n' > \"$TRUSTIX_CROSS_HOST_WORKDIR/userspace.result\"",
		"",
	}, "\n")), 0o755); err != nil {
		t.Fatalf("write runner stub: %v", err)
	}
	if err := os.WriteFile(verifier, []byte("import sys\nsys.exit(0)\n"), 0o755); err != nil {
		t.Fatalf("write verifier stub: %v", err)
	}
	if err := os.WriteFile(productionGate, []byte(strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -e",
		"mkdir -p \"$TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR\"",
		"case_token=\"$TRUSTIX_CROSS_HOST_USERSPACE_CASES\"",
		"case_path=\"${case_token#*=}\"",
		"cat > \"$TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR/production-gate-manifest.json\" <<JSON",
		`{"schema":"trustix-cross-host-production-gate-manifest-v1","production_gate":{"path":"production-gate.sh","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":123},"verifier":{"path":"verifier.py","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":456},"cases":{"userspace":"${case_token}"},"case_min_gbps":{"userspace":"udp-secure-stable-userspace-userspace=1.5"},"case_min_seconds":{"userspace":"udp-secure-stable-userspace-userspace=3600"}}`,
		"JSON",
		"cat > \"$TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR/userspace-udp-secure.jsonl\" <<JSON",
		`{"case":"udp-secure-stable-userspace-userspace","path":"${case_path}","status":"pass","min_gbps_required":1.5,"min_seconds_required":3600,"seconds_slop":0,"min_sent_gbps":1.9,"min_received_gbps":1.8,"min_required_received_gbps":1.7,"min_seconds":3600.1,"min_iperf_intervals_required":600,"min_iperf_interval_gbps_ratio_required":0.25,"iperf_json_count":2,"iperf_direction_count":2,"iperf_pair_directions":["a-to-b","b-to-a"],"iperf":[{"direction":"forward","sent_gbps":1.9,"received_gbps":1.8,"seconds":3600.1,"intervals":600,"interval_min_gbps":1.0,"sent_required":true,"received_required":true},{"direction":"forward","sent_gbps":1.8,"received_gbps":1.7,"seconds":3600.1,"intervals":600,"interval_min_gbps":1.0,"sent_required":true,"received_required":true}],"result_markers":["pass"],"binary_identities":[{"source":"collect/a/binary-identity.json","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},{"source":"collect/b/binary-identity.json","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"build_identities":[{"source":"collect/a/status.json","version":"trustix-test","commit":"0123456789ab","built_at":"2026-06-25T00:00:00Z","go_version":"go1.25.0","goos":"linux","goarch":"amd64","strong":true},{"source":"collect/b/status.json","version":"trustix-test","commit":"0123456789ab","built_at":"2026-06-25T00:00:00Z","go_version":"go1.25.0","goos":"linux","goarch":"amd64","strong":true}],"lsmod_artifacts":[{"source":"collect/a/lsmod.txt","node":"a","modules":[]},{"source":"collect/b/lsmod.txt","node":"b","modules":[]}],"lsmod_nodes":["a","b"],"lan_state_artifacts":[{"source":"collect/a/lan-state.txt","node":"a","interface":"tix-lan-a","tx_queue_len":1000},{"source":"collect/b/lan-state.txt","node":"b","interface":"tix-lan-b","tx_queue_len":1000}],"lan_state_nodes":["a","b"],"run_timing":[{"source":"run-timing.json","iperf_mode":"forward","iperf_directions":"both","iperf_seconds_requested":3600,"start_epoch":1000,"end_epoch":4600.1,"elapsed_seconds":3600.1}],"uname_artifacts":[{"node":"a","phase":"before","kernel_release":"6.12.90+deb13.1-amd64"},{"node":"a","phase":"after","kernel_release":"6.12.90+deb13.1-amd64"},{"node":"b","phase":"before","kernel_release":"6.12.90+deb13.1-amd64"},{"node":"b","phase":"after","kernel_release":"6.12.90+deb13.1-amd64"}],"os_release_artifacts":[{"node":"a","phase":"before","identity":"debian:13"},{"node":"a","phase":"after","identity":"debian:13"},{"node":"b","phase":"before","identity":"debian:13"},{"node":"b","phase":"after","identity":"debian:13"}],"boot_ids":[{"node":"a","phase":"before","boot_id":"boot-a"},{"node":"a","phase":"after","boot_id":"boot-a"},{"node":"b","phase":"before","boot_id":"boot-b"},{"node":"b","phase":"after","boot_id":"boot-b"}],"errors":[],"log_findings":[],"kernel_log_artifacts":["collect/a/kernel.log","collect/b/kernel.log"],"kernel_log_nodes":["a","b"],"kernel_log_rejected_artifacts":[],"pstore_artifacts":["collect/a/pstore.txt","collect/b/pstore.txt"],"pstore_nodes":["a","b"],"pstore_rejected_artifacts":[]}`,
		"JSON",
		"",
	}, "\n")), 0o755); err != nil {
		t.Fatalf("write production gate stub: %v", err)
	}

	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+slashPath(defaults),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+slashPath(matrixWorkdir),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER="+slashPath(runner),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER="+slashPath(verifier),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE="+slashPath(productionGate),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_GENERATOR="+slashPath(filepath.Join(".", "production-evidence-from-gate-summary.py")),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_REQUIRE_BINARY_IDENTITY=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT="+slashPath(evidenceOut),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_ARTIFACT=docs/trustix-performance-log.md#matrix-evidence-example",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_NOTE_TEMPLATE={transport} {encryption} {gate_family} matrix evidence",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("matrix evidence run failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(evidenceOut)
	if err != nil {
		t.Fatalf("read evidence output: %v", err)
	}
	fields := strings.Split(strings.TrimSpace(string(payload)), "\t")
	if len(fields) != 17 {
		t.Fatalf("expected 17 evidence fields, got %d:\n%s", len(fields), payload)
	}
	wantFields := map[int]string{
		0:  "userspace",
		1:  "udp",
		2:  "secure",
		3:  "stable",
		4:  "userspace",
		5:  "userspace",
		6:  "cross_host",
		7:  "debian13-debian13",
		8:  "6.12.90+deb13.1-amd64_to_6.12.90+deb13.1-amd64",
		9:  "pass",
		10: "1.700000",
		11: "3600",
		12: productionGateManifestSchema,
		13: strings.Repeat("a", 64),
		14: strings.Repeat("b", 64),
		15: "docs/trustix-performance-log.md#matrix-evidence-example",
		16: "udp secure userspace matrix evidence",
	}
	for idx, want := range wantFields {
		if fields[idx] != want {
			t.Fatalf("field %d = %q, want %q\n%s", idx, fields[idx], want, payload)
		}
	}
}

func TestCrossHostTransportMatrixWrapsProductionDefaults(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-cross-host-transport-matrix.sh"))
	if err != nil {
		t.Fatalf("read linux-cross-host-transport-matrix.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS:-${repo_root}/scripts/production-transport-defaults.tsv",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER:-${repo_root}/scripts/linux-cross-host-soak-runner.sh",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER:-${repo_root}/scripts/linux-cross-host-soak-verify.py",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE:-${repo_root}/scripts/linux-cross-host-production-gate.sh",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_GENERATOR:-${repo_root}/scripts/production-evidence-from-gate-summary.py",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE:-all",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_KEEP_REMOTE:-0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE:-1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_GATE_SUMMARY_DIR:-",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT:-",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OS_MATRIX:-",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_KERNEL_MATRIX:-",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_ARTIFACT:-",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_NOTE_TEMPLATE:-",
		"evidence_note_template='{transport} {encryption} {gate_family} production gate evidence'",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_INCLUDE_FAIL:-0",
		"selected-production-gate",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN:-0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0 is only allowed with DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0 is only allowed for dry-run or non-production scopes",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT cannot be used with DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT requires VERIFY=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_EVIDENCE_OUT requires SELECTED_GATE=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_CASES is diagnostic-only for production scopes",
		"selected production gate cannot represent",
		"selected_gate_unmapped_case_count",
		"selected_gate_case_count",
		"min_decimal()",
		"seconds_slop=\"$(min_decimal \"$seconds_slop\" \"1\")\"",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SECONDS",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET:-2",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET \"$route_gso_session_error_budget\"",
		"validation_scope",
		"gate_family",
		"\"runner_case\":\"%s\"",
		"runner_case_name",
		"gate_family_class",
		"matrix_case_name",
		"full_kmod|dd_full_kmod) printf 'dd-fullkmod\\n'",
		"owdeb_full_kmod) printf 'owdeb-fullkmod\\n'",
		"secure_kudp|dd_secure_kudp) printf 'secure-kudp\\n'",
		"owdeb_secure_kudp) printf 'owdeb-secure-kudp\\n'",
		"route_gso|dd_route_gso) printf 'dd-routegso\\n'",
		"owdeb_route_gso) printf 'owdeb-routegso\\n'",
		"owdeb_*) printf '%s-owdeb\\n' \"$base\"",
		"append_case_token userspace_cases",
		"append_case_token userspace_tc_cases",
		"append_case_token tc_direct_cases",
		"append_case_token userspace_case_min_gbps",
		"append_case_token userspace_tc_case_min_gbps",
		"append_case_token tc_direct_case_min_gbps",
		"append_case_token full_kmod_case_min_gbps",
		"append_case_token secure_kudp_case_min_gbps",
		"append_case_token route_gso_case_min_gbps",
		"append_case_token full_kmod_case_min_seconds",
		"append_case_token secure_kudp_case_min_seconds",
		"append_case_token route_gso_case_min_seconds",
		"full_kmod|dd_full_kmod|owdeb_full_kmod) printf 'full_kmod\\n'",
		"secure_kudp|dd_secure_kudp|owdeb_secure_kudp) printf 'secure_kudp\\n'",
		"route_gso|dd_route_gso|owdeb_route_gso) printf 'route_gso\\n'",
		"TRUSTIX_CROSS_HOST_CASE=\"$runner_case\"",
		"TRUSTIX_CROSS_HOST_TRANSPORT=\"$token\"",
		"TRUSTIX_CROSS_HOST_PROFILE=\"$profile\"",
		"TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH=\"$datapath\"",
		"TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT=\"$placement\"",
		"TRUSTIX_CROSS_HOST_KEEP_REMOTE=\"$keep_remote\"",
		"record_result \"dry_run\"",
		"--require-transport-policy-stat\" \"encryption=${encryption}",
		"--require-transport-policy-stat\" \"profile=${profile}",
		"--require-transport-policy-stat\" \"datapath=${datapath}",
		"--require-transport-policy-stat\" \"crypto_placement=${placement}",
		"if [[ \"$validation_scope\" == \"cross_host\" ]]; then",
		"family_class=\"$(gate_family_class \"$gate_family\")\"",
		"if [[ \"$family_class\" == \"route_gso\" ]]; then",
		"session_dial_error_budget=\"$route_gso_session_error_budget\"",
		"--require-transport-sessions-min\" \"1",
		"--require-status-max\" \"data_path.counters.session_dial_errors=${session_dial_error_budget}",
		"--require-status-max\" \"data_path.counters.session_heartbeat_timeouts=0",
		"TRUSTIX_CROSS_HOST_USERSPACE_CASES=${userspace_cases}",
		"TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS=${userspace_case_min_gbps}",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_CASES=${userspace_tc_cases}",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS=${userspace_tc_case_min_gbps}",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_CASES=${tc_direct_cases}",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_GBPS=${tc_direct_case_min_gbps}",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_CASES=${full_kmod_cases}",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS=${full_kmod_case_min_gbps}",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_SECONDS=${full_kmod_case_min_seconds}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES=${secure_kudp_cases}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS=${secure_kudp_case_min_gbps}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_SECONDS=${secure_kudp_case_min_seconds}",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_CASES=${route_gso_cases}",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS=${route_gso_case_min_gbps}",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_SECONDS=${route_gso_case_min_seconds}",
		"TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR=${selected_gate_summary_dir}",
		"emit_selected_gate_evidence",
		"production evidence output requires at least one selected production gate case",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-transport-matrix.sh missing %q", want)
		}
	}
}

func TestCrossHostTransportMatrixUsesRouteGSODialErrorBudget(t *testing.T) {
	bash := requireBashAndPython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	runner := filepath.Join(workdir, "runner.sh")
	verifier := filepath.Join(workdir, "verifier.py")
	productionGate := filepath.Join(workdir, "production-gate.sh")
	capture := filepath.Join(workdir, "verifier-args.jsonl")
	matrixWorkdir := filepath.Join(workdir, "matrix")
	if err := os.WriteFile(defaults, []byte(strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t0.5\t30\tselected UDP userspace gate",
		"experimental_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\troute_gso\t2.5\t30\tselected route-GSO gate",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	if err := os.WriteFile(runner, []byte(strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -e",
		"mkdir -p \"$TRUSTIX_CROSS_HOST_WORKDIR\"",
		"printf 'pass\\n' > \"$TRUSTIX_CROSS_HOST_WORKDIR/${TRUSTIX_CROSS_HOST_CASE}.result\"",
		"",
	}, "\n")), 0o755); err != nil {
		t.Fatalf("write runner stub: %v", err)
	}
	if err := os.WriteFile(verifier, []byte(strings.Join([]string{
		"import json",
		"import os",
		"import sys",
		"with open(os.environ['TRUSTIX_CAPTURE'], 'a', encoding='utf-8') as fh:",
		"    fh.write(json.dumps(sys.argv[1:]) + '\\n')",
		"",
	}, "\n")), 0o755); err != nil {
		t.Fatalf("write verifier stub: %v", err)
	}
	if err := os.WriteFile(productionGate, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write production gate stub: %v", err)
	}

	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CAPTURE="+slashPath(capture),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+slashPath(defaults),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+slashPath(matrixWorkdir),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER="+slashPath(runner),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER="+slashPath(verifier),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE="+slashPath(productionGate),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_REQUIRE_BINARY_IDENTITY=0",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET=2",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("matrix verifier capture failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("read verifier capture: %v", err)
	}
	gotByCase := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var args []string
		if err := json.Unmarshal([]byte(line), &args); err != nil {
			t.Fatalf("decode verifier args %q: %v", line, err)
		}
		caseName := ""
		for idx, arg := range args {
			if arg == "--case" && idx+1 < len(args) {
				caseName = strings.SplitN(args[idx+1], "=", 2)[0]
			}
			if arg == "--require-status-max" && idx+1 < len(args) && strings.HasPrefix(args[idx+1], "data_path.counters.session_dial_errors=") {
				gotByCase[caseName] = args[idx+1]
			}
		}
	}
	for name, want := range map[string]string{
		"udp-secure-stable-userspace-userspace":                          "data_path.counters.session_dial_errors=0",
		"experimental_tcp-plaintext-performance-kernel_module-userspace": "data_path.counters.session_dial_errors=2",
	} {
		if gotByCase[name] != want {
			t.Fatalf("case %s dial-error gate got %q want %q\ncapture:\n%s", name, gotByCase[name], want, payload)
		}
	}
}

func TestCrossHostTransportMatrixRejectsCustomCasesForProductionScope(t *testing.T) {
	bash := requireBashAndPython3(t)
	workdir := t.TempDir()
	runner := filepath.Join(workdir, "runner.sh")
	verifier := filepath.Join(workdir, "verifier.py")
	productionGate := filepath.Join(workdir, "production-gate.sh")
	if err := os.WriteFile(runner, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write runner stub: %v", err)
	}
	if err := os.WriteFile(verifier, []byte("import sys\nsys.exit(0)\n"), 0o755); err != nil {
		t.Fatalf("write verifier stub: %v", err)
	}
	if err := os.WriteFile(productionGate, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write production gate stub: %v", err)
	}

	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+slashPath(filepath.Join(workdir, "matrix")),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER="+slashPath(runner),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER="+slashPath(verifier),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE="+slashPath(productionGate),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_CASES=udp:secure:stable:userspace:userspace:0.5:900",
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("matrix unexpectedly accepted custom CASES in production scope:\n%s", output)
	}
	if !strings.Contains(string(output), "TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_CASES is diagnostic-only for production scopes") {
		t.Fatalf("matrix output did not report custom CASES production guard:\n%s", output)
	}
}

func TestCrossHostTransportMatrixRejectsGateFamilySemanticMismatch(t *testing.T) {
	bash := requireBashAndPython3(t)
	tests := []struct {
		name string
		row  string
		want string
	}{
		{
			name: "secure_kudp_wrong_transport",
			row:  "experimental_tcp\tsecure\tperformance\ttc_xdp\tkernel\tcross_host\tsecure_kudp\t1.5\t3600\tsecure kernel TCP must not reuse secure-kUDP gate",
			want: "gate_family=secure_kudp requires transport=kernel_udp; got transport=experimental_tcp",
		},
		{
			name: "route_gso_wrong_transport",
			row:  "udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\troute_gso\t2.5\t3600\tUDP full-kmod must not reuse route-GSO gate",
			want: "gate_family=route_gso requires transport=experimental_tcp; got transport=udp",
		},
		{
			name: "secure_exp_tcp_kernel_wrong_datapath",
			row:  "experimental_tcp\tsecure\tperformance\ttc_xdp\tkernel\tcross_host\tsecure_exp_tcp_kernel\t1.5\t3600\tsecure experimental TCP kernel crypto must use kernel-module datapath",
			want: "gate_family=secure_exp_tcp_kernel requires datapath=kernel_module; got datapath=tc_xdp",
		},
		{
			name: "full_kmod_wrong_crypto",
			row:  "udp\tsecure\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\t3\t3600\tfull-kmod production gate is plaintext-only",
			want: "gate_family=full_kmod requires encryption=plaintext; got encryption=secure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workdir := t.TempDir()
			defaults := filepath.Join(workdir, "defaults.tsv")
			runner := filepath.Join(workdir, "runner.sh")
			verifier := filepath.Join(workdir, "verifier.py")
			productionGate := filepath.Join(workdir, "production-gate.sh")
			if err := os.WriteFile(defaults, []byte(strings.Join([]string{
				"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
				tt.row,
				"",
			}, "\n")), 0o644); err != nil {
				t.Fatalf("write defaults: %v", err)
			}
			if err := os.WriteFile(runner, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
				t.Fatalf("write runner stub: %v", err)
			}
			if err := os.WriteFile(verifier, []byte("import sys\nsys.exit(0)\n"), 0o755); err != nil {
				t.Fatalf("write verifier stub: %v", err)
			}
			if err := os.WriteFile(productionGate, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
				t.Fatalf("write production gate stub: %v", err)
			}

			cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
			cmd.Dir = "."
			cmd.Env = append(os.Environ(),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+slashPath(defaults),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+slashPath(filepath.Join(workdir, "matrix")),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER="+slashPath(runner),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER="+slashPath(verifier),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE="+slashPath(productionGate),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=1",
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0",
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0",
			)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("matrix unexpectedly accepted semantically invalid gate family row:\n%s", output)
			}
			if !strings.Contains(string(output), tt.want) {
				t.Fatalf("matrix output missing %q:\n%s", tt.want, output)
			}
		})
	}
}

func TestCrossHostTransportMatrixRejectsUnmappedProductionGateFamily(t *testing.T) {
	bash := requireBashAndPython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	runner := filepath.Join(workdir, "runner.sh")
	verifier := filepath.Join(workdir, "verifier.py")
	productionGate := filepath.Join(workdir, "production-gate.sh")
	if err := os.WriteFile(defaults, []byte(strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tcustom\t0.5\t900\tcustom cross-host diagnostic must not pass production gate",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	if err := os.WriteFile(runner, []byte(strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -e",
		"mkdir -p \"$TRUSTIX_CROSS_HOST_WORKDIR\"",
		"",
	}, "\n")), 0o755); err != nil {
		t.Fatalf("write runner stub: %v", err)
	}
	if err := os.WriteFile(verifier, []byte("import sys\nsys.exit(0)\n"), 0o755); err != nil {
		t.Fatalf("write verifier stub: %v", err)
	}
	if err := os.WriteFile(productionGate, []byte("#!/usr/bin/env bash\nexit 99\n"), 0o755); err != nil {
		t.Fatalf("write production gate stub: %v", err)
	}

	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+slashPath(defaults),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+slashPath(filepath.Join(workdir, "matrix")),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER="+slashPath(runner),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER="+slashPath(verifier),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE="+slashPath(productionGate),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=1",
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("matrix unexpectedly accepted custom cross-host case as production:\n%s", output)
	}
	if !strings.Contains(string(output), "selected production gate cannot represent") {
		t.Fatalf("matrix output did not report unmapped production gate family:\n%s", output)
	}
}

func TestCrossHostTransportMatrixRejectsUnverifiedProductionRuns(t *testing.T) {
	bash := requireBashAndPython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	runner := filepath.Join(workdir, "runner.sh")
	verifier := filepath.Join(workdir, "verifier.py")
	productionGate := filepath.Join(workdir, "production-gate.sh")
	if err := os.WriteFile(defaults, []byte(strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t0.5\t900\tselected UDP userspace gate",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	if err := os.WriteFile(runner, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write runner stub: %v", err)
	}
	if err := os.WriteFile(verifier, []byte("import sys\nsys.exit(0)\n"), 0o755); err != nil {
		t.Fatalf("write verifier stub: %v", err)
	}
	if err := os.WriteFile(productionGate, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write production gate stub: %v", err)
	}

	tests := []struct {
		name string
		env  []string
		want string
	}{
		{
			name: "verify disabled",
			env: []string{
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0",
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=1",
			},
			want: "VERIFY=0 is only allowed with DRY_RUN=1",
		},
		{
			name: "selected gate disabled",
			env: []string{
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=1",
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0",
			},
			want: "SELECTED_GATE=0 is only allowed for dry-run or non-production scopes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
			cmd.Dir = "."
			cmd.Env = append(os.Environ(),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+slashPath(defaults),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+slashPath(filepath.Join(workdir, tt.name)),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER="+slashPath(runner),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER="+slashPath(verifier),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE="+slashPath(productionGate),
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
				"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=0",
			)
			cmd.Env = append(cmd.Env, tt.env...)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("matrix unexpectedly accepted unverified production run:\n%s", output)
			}
			if !strings.Contains(string(output), tt.want) {
				t.Fatalf("matrix output missing %q:\n%s", tt.want, output)
			}
		})
	}
}

func TestCrossHostTransportMatrixCanRepresentCompatibilityCrossHostGates(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	summary := filepath.Join(workdir, "summary.jsonl")
	if err := os.WriteFile(defaults, []byte(strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t0\t900\texplicit UDP userspace cross-host validation input",
		"gre\tplaintext\tperformance\ttc_xdp\tuserspace\tcross_host\tuserspace_tc\t0\t900\texplicit GRE userspace-TC cross-host validation input",
		"kernel_udp\tplaintext\tperformance\ttc_xdp\tuserspace\tcross_host\ttc_direct\t0\t900\texplicit kernel UDP TC-direct cross-host validation input",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+defaults,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SUMMARY="+summary,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run explicit compatibility matrix failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read dry-run summary: %v", err)
	}
	type row struct {
		RunnerCase string `json:"runner_case"`
		GateFamily string `json:"gate_family"`
	}
	got := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var decoded row
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("decode dry-run summary row %q: %v", line, err)
		}
		got[decoded.RunnerCase+":"+decoded.GateFamily] = true
	}
	for _, want := range []string{
		"userspace-udp-secure:userspace",
		"tc-gre-plaintext:userspace_tc",
		"tc-udp-plaintext:tc_direct",
	} {
		if !got[want] {
			t.Fatalf("dry-run summary missing %s:\n%s", want, payload)
		}
	}
}

type crossHostTransportMatrixDryRunRow struct {
	Status          string  `json:"status"`
	Case            string  `json:"case"`
	RunnerCase      string  `json:"runner_case"`
	Transport       string  `json:"transport"`
	Encryption      string  `json:"encryption"`
	Profile         string  `json:"profile"`
	Datapath        string  `json:"datapath"`
	CryptoPlacement string  `json:"crypto_placement"`
	ValidationScope string  `json:"validation_scope"`
	GateFamily      string  `json:"gate_family"`
	MinGbps         float64 `json:"min_gbps"`
	MinSeconds      int     `json:"min_seconds"`
}

func productionDefaultRunnerCase(row productionTransportDefault) string {
	switch row.GateFamily {
	case "full_kmod", "dd_full_kmod":
		return "dd-fullkmod"
	case "owdeb_full_kmod":
		return "owdeb-fullkmod"
	case "secure_kudp", "dd_secure_kudp":
		return "secure-kudp"
	case "owdeb_secure_kudp":
		return "owdeb-secure-kudp"
	case "secure_exp_tcp_kernel", "dd_secure_exp_tcp_kernel", "owdeb_secure_exp_tcp_kernel":
		return "secure-exp-tcp-kernel"
	case "route_gso", "dd_route_gso":
		return "dd-routegso"
	case "owdeb_route_gso":
		return "owdeb-routegso"
	}
	token := row.Transport
	if token == "kernel_udp" {
		token = "udp"
	}
	kind := "userspace"
	if row.Datapath == "tc_xdp" || row.Transport == "kernel_udp" {
		kind = "tc"
	}
	return kind + "-" + token + "-" + row.Encryption
}

func productionDefaultMatrixCase(row productionTransportDefault) string {
	token := row.Transport
	if token == "kernel_udp" {
		token = "udp"
	}
	name := strings.Join([]string{
		token,
		row.Encryption,
		row.Profile,
		row.Datapath,
		row.CryptoPlacement,
	}, "-")
	switch {
	case strings.HasPrefix(row.GateFamily, "owdeb_"):
		return name + "-owdeb"
	case strings.HasPrefix(row.GateFamily, "dd_"):
		return name + "-dd"
	default:
		return name
	}
}

func TestCrossHostTransportMatrixDryRunMatchesProductionDefaults(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}
	workdir := t.TempDir()
	summary := filepath.Join(workdir, "summary.jsonl")
	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SUMMARY="+summary,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run cross-host transport matrix failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read dry-run summary: %v", err)
	}

	got := map[string]crossHostTransportMatrixDryRunRow{}
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row crossHostTransportMatrixDryRunRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("decode dry-run summary row %q: %v", line, err)
		}
		key := strings.Join([]string{
			row.Transport,
			row.Encryption,
			row.Profile,
			row.Datapath,
			row.CryptoPlacement,
			row.ValidationScope,
			row.GateFamily,
		}, ":")
		if _, exists := got[key]; exists {
			t.Fatalf("duplicate dry-run production matrix row %s:\n%s", key, payload)
		}
		got[key] = row
	}

	expected := map[string]productionTransportDefault{}
	for _, row := range loadProductionTransportDefaults(t) {
		if row.ValidationScope != "cross_host" {
			continue
		}
		expected[productionDefaultEvidenceKey(row)] = row
	}
	for key, row := range expected {
		dryRun, ok := got[key]
		if !ok {
			t.Fatalf("cross-host transport matrix dry-run missing production default %s:\n%s", key, payload)
		}
		if dryRun.Status != "dry_run" {
			t.Fatalf("unexpected dry-run status for %s: %+v", key, dryRun)
		}
		if dryRun.Case != productionDefaultMatrixCase(row) {
			t.Fatalf("unexpected dry-run case for %s: got %q want %q", key, dryRun.Case, productionDefaultMatrixCase(row))
		}
		if dryRun.RunnerCase != productionDefaultRunnerCase(row) {
			t.Fatalf("unexpected dry-run runner case for %s: got %q want %q", key, dryRun.RunnerCase, productionDefaultRunnerCase(row))
		}
		wantGbps, err := strconv.ParseFloat(row.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid production default min_gbps %q in %+v", row.MinGbps, row)
		}
		if dryRun.MinGbps != wantGbps {
			t.Fatalf("unexpected dry-run min_gbps for %s: got %v want %v", key, dryRun.MinGbps, wantGbps)
		}
		wantSeconds, err := strconv.Atoi(row.MinSeconds)
		if err != nil {
			t.Fatalf("invalid production default min_seconds %q in %+v", row.MinSeconds, row)
		}
		if dryRun.MinSeconds != wantSeconds {
			t.Fatalf("unexpected dry-run min_seconds for %s: got %v want %v", key, dryRun.MinSeconds, wantSeconds)
		}
	}
	for key, row := range got {
		if _, ok := expected[key]; !ok {
			t.Fatalf("cross-host transport matrix dry-run emitted non-default row %s: %+v", key, row)
		}
	}
}

func TestCrossHostTransportMatrixDryRunIncludesOpenWrtDebianFullKmod(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}
	workdir := t.TempDir()
	summary := filepath.Join(workdir, "summary.jsonl")
	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SUMMARY="+summary,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run cross-host transport matrix failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read dry-run summary: %v", err)
	}
	var sawDebianFullKmod, sawOpenWrtDebianFullKmod bool
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row struct {
			Case       string `json:"case"`
			RunnerCase string `json:"runner_case"`
			GateFamily string `json:"gate_family"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("decode dry-run summary row %q: %v", line, err)
		}
		if row.RunnerCase == "dd-fullkmod" && row.GateFamily == "full_kmod" {
			sawDebianFullKmod = true
		}
		if row.RunnerCase == "owdeb-fullkmod" &&
			row.GateFamily == "owdeb_full_kmod" &&
			strings.HasSuffix(row.Case, "-owdeb") {
			sawOpenWrtDebianFullKmod = true
		}
		if row.RunnerCase == "owdeb-secure-kudp" || row.GateFamily == "owdeb_secure_kudp" {
			t.Fatalf("OpenWrt-Debian secure-kudp was promoted without a passing OpenWrt route-GSO/kfunc gate:\n%s", payload)
		}
		if row.GateFamily == "owdeb_secure_exp_tcp_kernel" {
			t.Fatalf("OpenWrt-Debian secure experimental TCP kernel path was promoted without a passing OpenWrt route-GSO/kfunc gate:\n%s", payload)
		}
		if strings.Contains(row.Case, "route-gso") && strings.HasSuffix(row.Case, "-owdeb") {
			t.Fatalf("OpenWrt-Debian route-GSO was promoted without a passing OpenWrt route-GSO/kfunc gate:\n%s", payload)
		}
	}
	if !sawDebianFullKmod || !sawOpenWrtDebianFullKmod {
		t.Fatalf("dry-run summary missing full-kmod target cases: debian=%t owdeb=%t\n%s", sawDebianFullKmod, sawOpenWrtDebianFullKmod, payload)
	}
}

func TestCrossHostTransportMatrixCanRepresentOpenWrtRouteGSOWhenExplicitlyValidated(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	summary := filepath.Join(workdir, "summary.jsonl")
	if err := os.WriteFile(defaults, []byte(strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"experimental_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\towdeb_route_gso\t2.5\t900\texplicit OpenWrt-Debian route-GSO validation input",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+defaults,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SUMMARY="+summary,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run explicit owdeb route-GSO matrix failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read dry-run summary: %v", err)
	}
	var row struct {
		Case       string `json:"case"`
		RunnerCase string `json:"runner_case"`
		GateFamily string `json:"gate_family"`
	}
	lines := strings.Fields(strings.TrimSpace(string(payload)))
	if len(lines) != 1 {
		t.Fatalf("expected one summary row, got %d:\n%s", len(lines), payload)
	}
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatalf("decode summary row: %v\n%s", err, payload)
	}
	if row.RunnerCase != "owdeb-routegso" ||
		row.GateFamily != "owdeb_route_gso" ||
		!strings.HasSuffix(row.Case, "-owdeb") {
		t.Fatalf("unexpected owdeb route-GSO dry-run row: %+v\n%s", row, payload)
	}
}

func TestProductionDefaultsDoNotPromoteOpenWrtRouteGSOWithoutRuntimeEvidence(t *testing.T) {
	rows := loadProductionTransportDefaults(t)
	for _, row := range rows {
		switch row.GateFamily {
		case "owdeb_secure_kudp", "owdeb_secure_exp_tcp_kernel", "owdeb_route_gso":
			t.Fatalf("production defaults include %s before OpenWrt route-GSO/kfunc runtime validation: %+v", row.GateFamily, row)
		}
	}
}

func TestOpenWrtKmodMatrixTracksCurrentStablePatchReleases(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "openwrt-full-datapath-kmod-matrix.sh"))
	if err != nil {
		t.Fatalf("read openwrt-full-datapath-kmod-matrix.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"https://mirrors.tuna.tsinghua.edu.cn/openwrt/releases",
		"https://mirrors.ustc.edu.cn/openwrt/releases",
		"https://mirrors.aliyun.com/openwrt/releases",
		"https://downloads.openwrt.org/releases",
		"21.02.7-x86_64|21.02.7|x86/64",
		"22.03.7-x86_64|22.03.7|x86/64",
		"23.05.6-x86_64|23.05.6|x86/64",
		"23.05.6-arm64|23.05.6|armsr/armv8",
		"24.10.7-x86_64|24.10.7|x86/64",
		"24.10.7-arm64|24.10.7|armsr/armv8",
		"25.12.4-x86_64|25.12.4|x86/64",
		"25.12.4-arm64|25.12.4|armsr/armv8",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("openwrt-full-datapath-kmod-matrix.sh missing %q", want)
		}
	}
	for _, stale := range []string{
		"23.05.5-x86_64|23.05.5|x86/64",
		"23.05.5-arm64|23.05.5|armsr/armv8",
		"24.10.2-x86_64|24.10.2|x86/64",
		"24.10.2-arm64|24.10.2|armsr/armv8",
		"25.12.1-x86_64|25.12.1|x86/64",
		"25.12.1-arm64|25.12.1|armsr/armv8",
	} {
		if strings.Contains(text, stale) {
			t.Fatalf("openwrt-full-datapath-kmod-matrix.sh still defaults stale release %q", stale)
		}
	}
}

func TestOpenWrtKmodMatrixParsesKernelVersionMk(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "openwrt-full-datapath-kmod-matrix.sh"))
	if err != nil {
		t.Fatalf("read openwrt-full-datapath-kmod-matrix.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"include/kernel-version.mk",
		"KERNEL_PATCHVER",
		"LINUX_VERSION",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("openwrt-full-datapath-kmod-matrix.sh should parse %s for OpenWrt SDKs without include/kernel-* files", want)
		}
	}
}

func TestCrossHostSoakRunnerCoversKernelFastPathsAndCleanup(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-cross-host-soak-runner.sh"))
	if err != nil {
		t.Fatalf("read linux-cross-host-soak-runner.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_CASE:-dd-fullkmod",
		"case_transport_override=\"${TRUSTIX_CROSS_HOST_TRANSPORT:-}\"",
		"case_encryption_override=\"${TRUSTIX_CROSS_HOST_ENCRYPTION:-}\"",
		"case_profile_override=\"${TRUSTIX_CROSS_HOST_PROFILE:-}\"",
		"case_datapath_override=\"${TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH:-}\"",
		"case_crypto_placement_override=\"${TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT:-}\"",
		"data_a_port=\"${TRUSTIX_CROSS_HOST_DATA_A_PORT:-}\"",
		"data_b_port=\"${TRUSTIX_CROSS_HOST_DATA_B_PORT:-}\"",
		"default_data_port",
		"node_value \"$node\" 13000 13001",
		"TRUSTIX_CROSS_HOST_IPERF_SECONDS:-3600",
		"iperf_parallel_explicit=\"${TRUSTIX_CROSS_HOST_IPERF_PARALLEL+x}\"",
		"health_port=\"${TRUSTIX_CROSS_HOST_HEALTH_PORT:-}\"",
		"TRUSTIX_CROSS_HOST_IPERF_MODE:-forward",
		"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS:-both",
		"daemon_ready_sleep=\"${TRUSTIX_CROSS_HOST_READY_SLEEP:-1}\"",
		"iperf_parallel=\"${TRUSTIX_CROSS_HOST_IPERF_PARALLEL:-8}\"",
		"iptunnel_iperf_parallel=\"${TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL:-4}\"",
		"transport_snapshot_delay=\"${TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY:-5}\"",
		"session_pool_size_explicit=\"${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE+x}\"",
		"session_pool_size=\"${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE:-$iperf_parallel}\"",
		"session_pool:",
		"size: ${session_pool_size}",
		"strategy: ${session_pool_strategy}",
		"warmup: ${session_pool_warmup}",
		"heartbeat:",
		"mode: ${session_pool_heartbeat_mode}",
		"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS must be both, a2b, or b2a",
		"TRUSTIX_CROSS_HOST_HEALTH_PORT must differ from TRUSTIX_CROSS_HOST_IPERF_PORT",
		"TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL must be >= 1",
		"case \"$iperf_mode\" in bidir|forward|reverse)",
		"apply_case_runtime_defaults",
		"TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE must be >= 1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY must be >= 0",
		"TRUSTIX_CROSS_HOST_SESSION_POOL_STRATEGY must be flow, five_tuple, 5tuple, packet, or round_robin",
		"ssh -n \"${ssh_opts[@]}\" \"$dest\" \"bash -c $(remote_quote \"$script\")\"",
		"iperf_artifact_suffix",
		"dd-fullkmod|owdeb-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod",
		"dd-secure-kudp|owdeb-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel",
		"dd-routegso|owdeb-routegso|route-gso|experimental-tcp-route-gso|experimental_tcp_route_gso",
		"ow-tc-direct|tc-direct|experimental-tcp-tc-direct|experimental_tcp_tc_direct",
		"userspace-*-secure|userspace-*-plaintext|crosshost-userspace-*-secure|crosshost-userspace-*-plaintext",
		"tc-*-secure|tc-*-plaintext|crosshost-tc-*-secure|crosshost-tc-*-plaintext",
		"supported_case_transport",
		"case_transport_profile",
		"case_fast_path",
		"case_encryption",
		"case_crypto_placement",
		"case_transport_datapath",
		"case_uses_tc_direct_fast_path",
		"case_tc_requested_but_falls_back_to_userspace",
		"has no safe TC direct fast path with this configuration; using userspace datapath",
		"route_gso|secure_exp_tcp_kernel)",
		"secure_kudp|tc_direct) printf 'tc_xdp\\n'",
		"tc_direct) printf 'tc_xdp\\n'",
		"capability_profile: full_plaintext",
		"capability_profile: performance",
		"capability_profile: disabled",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH:-embedded",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH_A:-$secure_kudp_crypto_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH_B:-$secure_kudp_crypto_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH_A:-$secure_kudp_helpers_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH_B:-$secure_kudp_helpers_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PARAMETERS",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPER_PARAMETERS",
		"infer_helpers_path_from_module_path",
		"embedded://trustix_crypto.ko|embedded://trustix_datapath.ko",
		"route authorize -out \"$workdir/certs\" -domain \"$domain_id\" -ix \"$ix_a\" -prefix \"$lan_a_cidr\"",
		"route authorize -out \"$workdir/certs\" -domain \"$domain_id\" -ix \"$ix_b\" -prefix \"$lan_b_cidr\"",
		"copy_to_node a \"$workdir/certs/.\"",
		"copy_to_node b \"$workdir/certs/.\"",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PARAMETERS",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPER_PARAMETERS",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PATH:-embedded",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPERS_PATH:-embedded",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPERS_PATH_A:-$route_gso_helpers_path",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPERS_PATH_B:-$route_gso_helpers_path",
		"path=\"$(node_value \"$node\" \"$route_gso_helpers_path_a\" \"$route_gso_helpers_path_b\")\"",
		"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORT",
		"case_endpoint_transport",
		"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORT is unsupported",
		"TRUSTIX_CROSS_HOST_TRANSPORT is unsupported",
		"TRUSTIX_CROSS_HOST_ENCRYPTION/case encryption must be secure or plaintext",
		"TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH/case datapath must be userspace, tc_xdp, kernel_module, or auto",
		"endpoint_security_yaml",
		"link_tls: required",
		"crypto_key_source: tls_exporter",
		"tls_identity:",
		"${local_ix}-transport.crt",
		"ssh_no_stdin()",
		"ssh -n \"${ssh_opts[@]}\" \"$dest\" \"$@\"",
		"ssh_no_stdin \"$dest\" \"mkdir -p $(remote_quote \"$dest_path\")\"",
		"ssh_no_stdin \"$dest\" \"test -d $(remote_quote \"$src\")\"",
		"collect_boot_id()",
		"boot-id-${phase}.txt",
		"collect_boot_id a before",
		"collect_boot_id b before",
		"collect_boot_id a after",
		"collect_boot_id b after",
		"rx_worker_experimental_tcp=1",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP=%s",
		"TRUSTIX_EXPERIMENTAL_TCP_ALLOW_MIXED_TCP_FAST_PATH=1",
		"full-kmod with experimental_tcp endpoint is diagnostic only",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER_EXPERIMENTS=1",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_RX_WORKER_EXPERIMENTS=1",
		"TRUSTIX_CROSS_HOST_OPENWRT_RX_SINGLE_COALESCE",
		"TRUSTIX_KERNEL_DATAPATH_OPENWRT_RX_SINGLE_COALESCE=%s",
		"daemon_env_exports",
		"env ${env_exports} $(remote_quote \"$trustixd\") -config",
		"yaml_single_quote",
		"endpoint_security_yaml \"    \" \"$encryption\"",
		"crypto_placement: ${crypto_placement}",
		"TRUSTIX_KERNEL_UDP_TC_SECURE_DIRECT_ONLY=1",
		"TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_KFUNC_FASTPATH=1",
		"TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_IRQ_FPU_KFUNC_FASTPATH=1",
		"TRUSTIX_KERNEL_CRYPTO_KFUNC_FASTPATH_STATS=1",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL=1",
		"TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN=1",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS=1",
		"TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT=1",
		"TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT=1",
		"TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUMS=1",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_ROUTE_GSO:-0",
		"printf 'TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO_KFUNC=%s\\n' \"$route_gso\"",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=1",
		"TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO=0",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=0",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1",
		"unload_on_exit: true",
		"-cleanup-dataplane",
		"rmmod trustix_datapath",
		"rmmod trustix_datapath_helpers",
		"printf 'pass\\n' >\"$workdir/${case_name}.result\"",
		"collect_binary_identity a",
		"version_output=\\$(",
		"collect_kernel_logs a",
		"if command -v journalctl >/dev/null 2>&1; then",
		"tmp=\\\"\\${dir}/.\\${prefix}-kernel.log.tmp\\\"",
		"journalctl -k -b --since '1 hour ago' --no-pager -o short-iso >\\\"\\$tmp\\\"",
		"if command -v dmesg >/dev/null 2>&1; then",
		"tmp=\\\"\\${dir}/.\\${prefix}-dmesg.log.tmp\\\"",
		"if dmesg -T >\\\"\\$tmp\\\"",
		"elif dmesg >\\\"\\$tmp\\\"",
		"collect_all",
		"collect_module_parameters a",
		"${dir}/module-parameters.txt",
		"stop_daemon a",
		"collect_one status status",
		"collect_one datapath datapath",
		"collect_one transports transports",
		"collect_transport_snapshot",
		"run_iperf_client_with_snapshot",
		"run_connectivity_checks",
		"run_tcp_health_checks",
		"run_tcp_health_direction",
		"collect_one bpf bpf maps",
		"${dir}/binary-identity.json",
		"ip_cmd=\\$(command -v ip)",
		"nohup \\\"\\$ip_cmd\\\" netns exec",
		"setsid \\\"\\$ip_cmd\\\" netns exec",
		"timeout ${iperf_timeout}s \\\"\\$ip_cmd\\\" netns exec",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-soak-runner.sh missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"xargs -r",
		"${prefix}-status.json",
		"${prefix}-datapath.json",
		"${prefix}-binary-identity.json",
		"find \"$workdir/a\" \"$workdir/b\" -type f -name 'iperf3-*.json' -exec cp",
		"trustixd\") -version 2>/dev/null | awk -F= '/^version=/{print $2; exit}'",
		"ip netns exec",
		"ip netns del",
		"ip netns pids",
		"nohup ip netns exec",
		"setsid ip netns exec",
		"\"$dest\" bash -s <<<\"$script\"",
		"sh -c \"$iperf_cmd\"",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-cross-host-soak-runner.sh contains non-portable %q", unwanted)
		}
	}
}
