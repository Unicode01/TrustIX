package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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
	GateFamily              string
	Transport               string
	Encryption              string
	Profile                 string
	Datapath                string
	CryptoPlacement         string
	ValidationScope         string
	OSMatrix                string
	KernelMatrix            string
	Result                  string
	MinGbps                 string
	MinSeconds              string
	GateManifestSchema      string
	ProductionGateSHA256    string
	VerifierSHA256          string
	Artifact                string
	Note                    string
	BinarySHA256            string
	BuildVersion            string
	BuildCommit             string
	BuildBuiltAt            string
	BuildGoVersion          string
	RunnerSHA256            string
	TransportMatrixSHA256   string
	EvidenceGeneratorSHA256 string
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
		note := strings.Join(fields[16:], "\t")
		binarySHA256 := ""
		buildVersion := ""
		buildCommit := ""
		buildBuiltAt := ""
		buildGoVersion := ""
		if len(fields) >= 22 {
			note = fields[16]
			binarySHA256 = fields[17]
			buildVersion = fields[18]
			buildCommit = fields[19]
			buildBuiltAt = fields[20]
			buildGoVersion = fields[21]
		}
		runnerSHA256 := ""
		transportMatrixSHA256 := ""
		evidenceGeneratorSHA256 := ""
		if len(fields) >= 25 {
			runnerSHA256 = fields[22]
			transportMatrixSHA256 = fields[23]
			evidenceGeneratorSHA256 = fields[24]
		}
		rows = append(rows, productionTransportEvidence{
			GateFamily:              fields[0],
			Transport:               fields[1],
			Encryption:              fields[2],
			Profile:                 fields[3],
			Datapath:                fields[4],
			CryptoPlacement:         fields[5],
			ValidationScope:         fields[6],
			OSMatrix:                fields[7],
			KernelMatrix:            fields[8],
			Result:                  fields[9],
			MinGbps:                 fields[10],
			MinSeconds:              fields[11],
			GateManifestSchema:      fields[12],
			ProductionGateSHA256:    fields[13],
			VerifierSHA256:          fields[14],
			Artifact:                fields[15],
			Note:                    note,
			BinarySHA256:            binarySHA256,
			BuildVersion:            buildVersion,
			BuildCommit:             buildCommit,
			BuildBuiltAt:            buildBuiltAt,
			BuildGoVersion:          buildGoVersion,
			RunnerSHA256:            runnerSHA256,
			TransportMatrixSHA256:   transportMatrixSHA256,
			EvidenceGeneratorSHA256: evidenceGeneratorSHA256,
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
	case "tix_tcp_full_kmod", "dd_tix_tcp_full_kmod", "owdeb_tix_tcp_full_kmod":
		return "tix_tcp_full_kmod"
	case "secure_kudp", "dd_secure_kudp", "owdeb_secure_kudp":
		return "secure_kudp"
	case "secure_tix_tcp_kernel", "dd_secure_tix_tcp_kernel", "owdeb_secure_tix_tcp_kernel":
		return "secure_tix_tcp_kernel"
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
		requireTransport("udp", "tcp", "quic", "websocket", "http_connect", "tix_tcp")
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
	case "tix_tcp_full_kmod":
		require("transport", transport, "tix_tcp")
		require("encryption", encryption, "plaintext")
		require("datapath", datapath, "kernel_module")
		require("crypto_placement", placement, "userspace")
	case "secure_kudp":
		require("transport", transport, "kernel_udp")
		require("encryption", encryption, "secure")
		require("datapath", datapath, "tc_xdp")
		require("crypto_placement", placement, "kernel")
	case "secure_tix_tcp_kernel":
		require("transport", transport, "tix_tcp")
		require("encryption", encryption, "secure")
		require("datapath", datapath, "kernel_module")
		require("crypto_placement", placement, "kernel")
	case "route_gso":
		require("transport", transport, "tix_tcp")
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

func sha256File(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func withMatrixToolchain(row map[string]any) map[string]any {
	if _, ok := row["runner_sha256"]; !ok {
		row["runner_sha256"] = strings.Repeat("d", 64)
	}
	if _, ok := row["transport_matrix_sha256"]; !ok {
		row["transport_matrix_sha256"] = strings.Repeat("e", 64)
	}
	return row
}

func latestRuntimeParentCommit(t *testing.T, path string) string {
	t.Helper()
	args := []string{"-C", "..", "log", "--format=%H", "-n", "1", "--", path}
	output, err := exec.Command("git", args...).CombinedOutput()
	if err != nil {
		t.Skipf("git log unavailable for runtime tree audit test: %v\n%s", err, output)
	}
	commit := strings.TrimSpace(string(output))
	if commit == "" {
		t.Skipf("no runtime commit found for %s", path)
	}
	parentOutput, err := exec.Command("git", "-C", "..", "rev-parse", commit+"^").CombinedOutput()
	if err != nil {
		t.Skipf("latest runtime commit %s for %s has no parent: %v\n%s", commit, path, err, parentOutput)
	}
	return strings.TrimSpace(string(parentOutput))
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
	toolchainFields := []string{
		evidence.RunnerSHA256,
		evidence.TransportMatrixSHA256,
		evidence.EvidenceGeneratorSHA256,
	}
	toolchainPresent := false
	for _, value := range toolchainFields {
		if value != "" {
			toolchainPresent = true
		}
	}
	if toolchainPresent {
		for _, value := range toolchainFields {
			if !isSHA256Hex(value) {
				t.Fatalf("production evidence has incomplete or invalid toolchain SHA256 fields in %+v", evidence)
			}
		}
	}
}

type currentProductionEvidenceRequirement struct {
	OSMatrix                string
	KernelMatrix            string
	Artifact                string
	GateManifestSchema      string
	ProductionGateSHA256    string
	VerifierSHA256          string
	BinarySHA256            string
	BuildVersion            string
	BuildCommit             string
	BuildBuiltAt            string
	BuildGoVersion          string
	RunnerSHA256            string
	TransportMatrixSHA256   string
	EvidenceGeneratorSHA256 string
}

func loadCurrentProductionEvidenceRequirements(t *testing.T) map[string]currentProductionEvidenceRequirement {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(".", "production-transport-current-evidence.tsv"))
	if err != nil {
		t.Fatalf("read production-transport-current-evidence.tsv: %v", err)
	}
	requirements := map[string]currentProductionEvidenceRequirement{}
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 19 {
			t.Fatalf("invalid current production evidence requirement row %q", line)
		}
		if len(fields) != 19 && len(fields) != 22 {
			t.Fatalf("current production evidence requirement must have 19 legacy columns or 22 toolchain columns, got %d in %q", len(fields), line)
		}
		runnerSHA256 := ""
		transportMatrixSHA256 := ""
		evidenceGeneratorSHA256 := ""
		if len(fields) == 22 {
			runnerSHA256 = fields[19]
			transportMatrixSHA256 = fields[20]
			evidenceGeneratorSHA256 = fields[21]
		}
		row := productionTransportDefault{
			Transport:       fields[0],
			Encryption:      fields[1],
			Profile:         fields[2],
			Datapath:        fields[3],
			CryptoPlacement: fields[4],
			ValidationScope: fields[5],
			GateFamily:      fields[6],
		}
		key := productionDefaultEvidenceKey(row)
		if _, ok := requirements[key]; ok {
			t.Fatalf("duplicate current production evidence requirement for %s", key)
		}
		requirements[key] = currentProductionEvidenceRequirement{
			OSMatrix:                fields[7],
			KernelMatrix:            fields[8],
			GateManifestSchema:      fields[9],
			ProductionGateSHA256:    fields[10],
			VerifierSHA256:          fields[11],
			Artifact:                fields[12],
			BinarySHA256:            fields[14],
			BuildVersion:            fields[15],
			BuildCommit:             fields[16],
			BuildBuiltAt:            fields[17],
			BuildGoVersion:          fields[18],
			RunnerSHA256:            runnerSHA256,
			TransportMatrixSHA256:   transportMatrixSHA256,
			EvidenceGeneratorSHA256: evidenceGeneratorSHA256,
		}
	}
	return requirements
}

func currentProductionEvidenceRequirementForDefault(requirements map[string]currentProductionEvidenceRequirement, row productionTransportDefault) (currentProductionEvidenceRequirement, bool) {
	requirement, ok := requirements[productionDefaultEvidenceKey(row)]
	return requirement, ok
}

func loadAuditCurrentToolchainLegacyRequirementKeys(t *testing.T) map[string]bool {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(".", "production-transport-audit.py"))
	if err != nil {
		t.Fatalf("read production-transport-audit.py: %v", err)
	}
	text := string(payload)
	start := strings.Index(text, "CURRENT_TOOLCHAIN_LEGACY_REQUIREMENTS = {")
	if start < 0 {
		t.Fatalf("production-transport-audit.py is missing CURRENT_TOOLCHAIN_LEGACY_REQUIREMENTS")
	}
	rest := text[start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("production-transport-audit.py has unterminated CURRENT_TOOLCHAIN_LEGACY_REQUIREMENTS")
	}
	block := rest[:end]
	keys := map[string]bool{}
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		line = strings.TrimPrefix(line, `"`)
		quote := strings.Index(line, `"`)
		if quote < 0 {
			t.Fatalf("invalid CURRENT_TOOLCHAIN_LEGACY_REQUIREMENTS line: %q", line)
		}
		key := line[:quote]
		if keys[key] {
			t.Fatalf("duplicate CURRENT_TOOLCHAIN_LEGACY_REQUIREMENTS key: %s", key)
		}
		keys[key] = true
	}
	if len(keys) != 0 {
		t.Fatalf("CURRENT_TOOLCHAIN_LEGACY_REQUIREMENTS should be empty after the current userspace refresh, got %d", len(keys))
	}
	return keys
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

func TestProductionMatrixDefaultsAvoidUnsafeTIXTCPSecureFastPath(t *testing.T) {
	for _, name := range []string{"linux-production-transport-matrix.sh"} {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join(".", name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			text := string(payload)
			if strings.Contains(text, "tix_tcp:secure:stable:kernel_module:userspace") {
				t.Fatalf("%s production defaults still select unsafe secure userspace-crypto tix_tcp kernel fast path", name)
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
				"vxlan:secure:stable:tc_xdp:userspace:cross_host:userspace_tc:0.75:3600",
				"vxlan:plaintext:performance:tc_xdp:userspace:cross_host:userspace_tc:4:3600",
				"kernel_udp:plaintext:performance:tc_xdp:userspace:cross_host:tc_direct:3:3600",
				"kernel_udp:secure:performance:tc_xdp:kernel:cross_host:secure_kudp:1.5:3600",
				"tix_tcp:plaintext:performance:kernel_module:userspace:cross_host:tix_tcp_full_kmod:4:3600",
				"tix_tcp:plaintext:performance:kernel_module:userspace:cross_host:owdeb_tix_tcp_full_kmod:4:3600",
				"tix_tcp:plaintext:performance:kernel_module:userspace:cross_host:route_gso:2.5:3600",
				"tix_tcp:secure:stable:userspace:userspace:single_host:userspace:0:30",
				"tix_tcp:secure:stable:userspace:userspace:cross_host:userspace:0.5:3600",
				"tix_tcp:secure:performance:kernel_module:kernel:cross_host:secure_tix_tcp_kernel:1.5:3600",
				"tix_tcp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
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

func TestCrossHostProductionDefaultsCoverTransportEncryptionPairsWithCurrentEvidence(t *testing.T) {
	rows := loadProductionTransportDefaults(t)
	requirements := loadCurrentProductionEvidenceRequirements(t)
	expected := map[string]bool{
		"udp:secure":             false,
		"udp:plaintext":          false,
		"tcp:secure":             false,
		"tcp:plaintext":          false,
		"quic:secure":            false,
		"quic:plaintext":         false,
		"websocket:secure":       false,
		"websocket:plaintext":    false,
		"http_connect:secure":    false,
		"http_connect:plaintext": false,
		"gre:secure":             false,
		"gre:plaintext":          false,
		"ipip:secure":            false,
		"ipip:plaintext":         false,
		"vxlan:secure":           false,
		"vxlan:plaintext":        false,
		"kernel_udp:secure":      false,
		"kernel_udp:plaintext":   false,
		"tix_tcp:secure":         false,
		"tix_tcp:plaintext":      false,
	}
	for _, row := range rows {
		if row.ValidationScope != "cross_host" {
			continue
		}
		key := row.Transport + ":" + row.Encryption
		if _, ok := expected[key]; !ok {
			continue
		}
		requirement, ok := currentProductionEvidenceRequirementForDefault(requirements, row)
		if !ok {
			t.Fatalf("cross-host production default lacks current evidence requirement: %+v", row)
		}
		if requirement.GateManifestSchema != productionGateManifestSchema {
			t.Fatalf("cross-host production default must use manifest-backed current evidence: row=%+v requirement=%+v", row, requirement)
		}
		expected[key] = true
	}
	var missing []string
	for key, found := range expected {
		if !found {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("missing cross-host production defaults with current evidence for transport/encryption pairs: %v", missing)
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
		"tx_plaintext_payload_fast_copy=1",
		"tx_plaintext_hash_tx_queue=1",
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
		"full_kmod":               true,
		"owdeb_full_kmod":         true,
		"tix_tcp_full_kmod":       true,
		"owdeb_tix_tcp_full_kmod": true,
		"secure_kudp":             true,
		"secure_tix_tcp_kernel":   true,
		"route_gso":               true,
	}
	forbiddenFastPathKey := map[string]bool{
		"udp:plaintext:performance:kernel_module:userspace":        true,
		"kernel_udp:secure:performance:tc_xdp:kernel":              true,
		"tix_tcp:plaintext:performance:kernel_module:userspace":    true,
		"tix_tcp:secure:performance:kernel_module:kernel":          true,
		"tix_tcp:secure:performance:kernel_module:userspace":       true,
		"tix_tcp:plaintext:performance:tc_xdp:userspace":           true,
		"tix_tcp:secure:performance:tc_xdp:kernel":                 true,
		"tix_tcp:secure:performance:tc_xdp:userspace":              true,
		"kernel_udp:plaintext:performance:kernel_module:userspace": true,
		"kernel_udp:plaintext:performance:kernel_module:kernel":    true,
		"kernel_udp:secure:performance:kernel_module:kernel":       true,
		"kernel_udp:secure:performance:kernel_module:userspace":    true,
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
		"binary_sha256",
		"build_commit",
		"runner_sha256",
		"transport_matrix_sha256",
		"evidence_generator_sha256",
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
		"status":                  "pass",
		"case":                    "udp-secure-stable-userspace-userspace-userspace",
		"runner_case":             "userspace-udp-secure",
		"transport":               "udp",
		"encryption":              "secure",
		"profile":                 "stable",
		"datapath":                "userspace",
		"crypto_placement":        "userspace",
		"validation_scope":        "cross_host",
		"gate_family":             "userspace",
		"min_gbps":                1.5,
		"min_seconds":             3600,
		"exit_code":               0,
		"workdir":                 filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace"),
		"runner_sha256":           strings.Repeat("d", 64),
		"transport_matrix_sha256": strings.Repeat("e", 64),
	}
	matrixPayload, err := json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace-userspace",
		"path":                       filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace"),
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
			"userspace": "udp-secure-stable-userspace-userspace-userspace=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace")),
		},
		"case_min_gbps": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace-userspace=1.5",
		},
		"case_min_seconds": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace-userspace=3600",
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
	if len(fields) != 25 {
		t.Fatalf("expected 25 evidence fields, got %d:\n%s", len(fields), output)
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
		17: strings.Repeat("c", 64),
		18: "trustix-test",
		19: "0123456789ab",
		20: "2026-06-25T00:00:00Z",
		21: "go1.25.0",
		22: strings.Repeat("d", 64),
		23: strings.Repeat("e", 64),
		24: sha256File(t, "production-evidence-from-gate-summary.py"),
	}
	for idx, want := range wantFields {
		if fields[idx] != want {
			t.Fatalf("field %d = %q, want %q\n%s", idx, fields[idx], want, output)
		}
	}

	originalIperf := gateRow["iperf"]
	originalMinSent := gateRow["min_sent_gbps"]
	gateRow["min_sent_gbps"] = 0.0
	gateRow["min_required_received_gbps"] = 1.654321
	gateRow["iperf"] = []map[string]any{
		{
			"direction":         "forward",
			"sent_gbps":         0.0,
			"received_gbps":     1.765432,
			"seconds":           3600.05,
			"intervals":         600,
			"interval_min_gbps": 1.0,
			"sent_required":     false,
			"received_required": true,
		},
		{
			"direction":         "forward",
			"sent_gbps":         0.0,
			"received_gbps":     1.654321,
			"seconds":           3600.05,
			"intervals":         600,
			"interval_min_gbps": 1.0,
			"sent_required":     false,
			"received_required": true,
		},
	}
	gatePayload, err = json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal receiver-only gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write receiver-only gate summary: %v", err)
	}
	receiverOnlyCmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#example-production-gate",
		"--note-template", "{transport} {encryption} {gate_family} evidence",
	)
	receiverOnlyCmd.Dir = "."
	receiverOnlyOutput, err := receiverOnlyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production evidence generator rejected receiver-only server summary: %v\n%s", err, receiverOnlyOutput)
	}
	receiverOnlyFields := strings.Split(strings.TrimSpace(string(receiverOnlyOutput)), "\t")
	if len(receiverOnlyFields) != 25 {
		t.Fatalf("expected 25 receiver-only evidence fields, got %d:\n%s", len(receiverOnlyFields), receiverOnlyOutput)
	}
	if receiverOnlyFields[10] != "1.654321" {
		t.Fatalf("receiver-only min_gbps = %q, want receiver metric\n%s", receiverOnlyFields[10], receiverOnlyOutput)
	}
	gateRow["iperf"] = originalIperf
	gateRow["min_sent_gbps"] = originalMinSent
	gateRow["min_required_received_gbps"] = 1.654321
	gatePayload, err = json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal restored gate row after receiver-only check: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("restore gate summary after receiver-only check: %v", err)
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
		"userspace": runnerCase + "=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace")),
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

	directGateCase := "direct-production-gate-userspace"
	matrixRow["gate_case"] = directGateCase
	matrixPayload, err = json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal matrix row with direct gate case: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary with direct gate case: %v", err)
	}
	gateRow["case"] = directGateCase
	gatePayload, err = json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal direct-gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write direct-gate summary: %v", err)
	}
	manifest["cases"] = map[string]any{
		"userspace": directGateCase + "=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace")),
	}
	manifest["case_min_gbps"] = map[string]any{
		"userspace": directGateCase + "=1.5",
	}
	manifest["case_min_seconds"] = map[string]any{
		"userspace": directGateCase + "=3600",
	}
	manifestPayload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal direct-gate manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write direct-gate manifest: %v", err)
	}
	directGateCmd := exec.Command(python, "production-evidence-from-gate-summary.py",
		"--matrix-summary", slashPath(matrixSummary),
		"--gate-summary-dir", slashPath(gateSummaryDir),
		"--artifact", "docs/trustix-performance-log.md#example-production-gate",
		"--note-template", "{transport} {encryption} {gate_family} evidence",
	)
	directGateCmd.Dir = "."
	directGateOutput, err := directGateCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production evidence generator rejected direct gate case alias: %v\n%s", err, directGateOutput)
	}
	directGateLines := strings.Split(strings.TrimSpace(string(directGateOutput)), "\n")
	if len(directGateLines) != 1 {
		t.Fatalf("expected one direct-gate evidence row, got %d:\n%s", len(directGateLines), directGateOutput)
	}
	directGateFields := strings.Split(directGateLines[0], "\t")
	for idx, want := range wantFields {
		if directGateFields[idx] != want {
			t.Fatalf("direct-gate field %d = %q, want %q\n%s", idx, directGateFields[idx], want, directGateOutput)
		}
	}

	delete(matrixRow, "gate_case")
	matrixPayload, err = json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal restored matrix row after direct gate case: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write restored matrix summary after direct gate case: %v", err)
	}

	gateRow["case"] = "udp-secure-stable-userspace-userspace-userspace"
	gatePayload, err = json.Marshal(gateRow)
	if err != nil {
		t.Fatalf("marshal restored gate row: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "userspace-udp-secure.jsonl"), append(gatePayload, '\n'), 0o644); err != nil {
		t.Fatalf("write restored gate summary: %v", err)
	}
	manifest["cases"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace-userspace=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace")),
	}
	manifest["case_min_gbps"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace-userspace=1.5",
	}
	manifest["case_min_seconds"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace-userspace=3600",
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
		"userspace": "udp-secure-stable-userspace-userspace-userspace=" + slashPath(filepath.Join(workdir, "wrong-evidence-dir")),
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
		"userspace": "udp-secure-stable-userspace-userspace-userspace=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace")),
	}
	manifestPayload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal restored manifest path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gateSummaryDir, "production-gate-manifest.json"), append(manifestPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write restored manifest path: %v", err)
	}
	matrixRow["workdir"] = filepath.Join(workdir, "wrong-matrix-dir")
	matrixPayload, err = json.Marshal(withMatrixToolchain(matrixRow))
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
	matrixRow["workdir"] = filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace")
	matrixPayload, err = json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal restored matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write restored matrix summary: %v", err)
	}

	manifest["case_min_gbps"] = map[string]any{
		"userspace": "udp-secure-stable-userspace-userspace-userspace=1.0",
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
		"case":             "udp-secure-stable-userspace-userspace-userspace",
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
		"workdir":          filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace"),
	}
	matrixPayload, err := json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace-userspace",
		"path":                       filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace"),
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
			"userspace": "udp-secure-stable-userspace-userspace-userspace=" + slashPath(filepath.Join(workdir, "udp-secure-stable-userspace-userspace-userspace")),
		},
		"case_min_gbps": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace-userspace=1.5",
		},
		"case_min_seconds": map[string]any{
			"userspace": "udp-secure-stable-userspace-userspace-userspace=3600",
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
				"case":             "tix_tcp-plaintext-performance-kernel_module-userspace-route_gso",
				"runner_case":      "userspace-tcp-plaintext",
				"transport":        "tix_tcp",
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
			name: "tix_tcp_full_kmod_wrong_transport",
			matrixRow: map[string]any{
				"status":           "pass",
				"case":             "udp-plaintext-performance-kernel_module-userspace",
				"runner_case":      "tix-tcp-full-kmod",
				"transport":        "udp",
				"encryption":       "plaintext",
				"profile":          "performance",
				"datapath":         "kernel_module",
				"crypto_placement": "userspace",
				"validation_scope": "cross_host",
				"gate_family":      "tix_tcp_full_kmod",
				"min_gbps":         4,
				"min_seconds":      3600,
			},
			want: []string{
				"gate_family=tix_tcp_full_kmod",
				"requires transport='tix_tcp'",
				"got 'udp'",
			},
		},
		{
			name: "secure_tix_tcp_kernel_wrong_datapath",
			matrixRow: map[string]any{
				"status":           "pass",
				"case":             "tix_tcp-secure-performance-tc_xdp-kernel",
				"runner_case":      "secure-tix-tcp-kernel",
				"transport":        "tix_tcp",
				"encryption":       "secure",
				"profile":          "performance",
				"datapath":         "tc_xdp",
				"crypto_placement": "kernel",
				"validation_scope": "cross_host",
				"gate_family":      "secure_tix_tcp_kernel",
				"min_gbps":         1.5,
				"min_seconds":      3600,
			},
			want: []string{
				"gate_family=secure_tix_tcp_kernel",
				"requires datapath='kernel_module'",
				"got 'tc_xdp'",
			},
		},
		{
			name: "owdeb_route_gso_missing_case_suffix",
			matrixRow: map[string]any{
				"status":           "pass",
				"case":             "tix_tcp-plaintext-performance-kernel_module-userspace-route_gso",
				"runner_case":      "owdeb-routegso",
				"transport":        "tix_tcp",
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
				"requires case='tix_tcp-plaintext-performance-kernel_module-userspace-route_gso-owdeb'",
				"got 'tix_tcp-plaintext-performance-kernel_module-userspace-route_gso'",
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
			matrixPayload, err := json.Marshal(withMatrixToolchain(tt.matrixRow))
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
		"case":             "udp-secure-stable-userspace-userspace-userspace",
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
	matrixPayload, err := json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace-userspace",
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
		"case":   "udp-secure-stable-userspace-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace-userspace",
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
		"case":   "udp-secure-stable-userspace-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace-userspace",
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
		"case":   "udp-secure-stable-userspace-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace-userspace",
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
		"case":   "udp-secure-stable-userspace-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace-userspace",
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
		"case":   "udp-secure-stable-userspace-userspace-userspace",
	}
	matrixPayload, err := json.Marshal(withMatrixToolchain(matrixRow))
	if err != nil {
		t.Fatalf("marshal matrix row: %v", err)
	}
	if err := os.WriteFile(matrixSummary, append(matrixPayload, '\n'), 0o644); err != nil {
		t.Fatalf("write matrix summary: %v", err)
	}
	gateRow := map[string]any{
		"case":                       "udp-secure-stable-userspace-userspace-userspace",
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
	requirements := loadCurrentProductionEvidenceRequirements(t)
	evidenceByKey := map[string][]productionTransportEvidence{}
	for _, evidence := range loadProductionTransportEvidence(t) {
		evidenceByKey[productionEvidenceKey(evidence)] = append(evidenceByKey[productionEvidenceKey(evidence)], evidence)
	}

	checkedByFamily := map[string]int{}
	for _, row := range defaults {
		if row.ValidationScope != "cross_host" {
			continue
		}
		requirement, ok := currentProductionEvidenceRequirementForDefault(requirements, row)
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
				evidence.ProductionGateSHA256,
				evidence.VerifierSHA256,
				evidence.BinarySHA256,
				evidence.BuildCommit,
				evidence.Artifact,
			}, " "))
			if evidence.OSMatrix != requirement.OSMatrix ||
				evidence.KernelMatrix != requirement.KernelMatrix ||
				evidence.GateManifestSchema != requirement.GateManifestSchema ||
				evidence.ProductionGateSHA256 != requirement.ProductionGateSHA256 ||
				evidence.VerifierSHA256 != requirement.VerifierSHA256 ||
				evidence.Artifact != requirement.Artifact ||
				evidence.BinarySHA256 != requirement.BinarySHA256 ||
				evidence.BuildVersion != requirement.BuildVersion ||
				evidence.BuildCommit != requirement.BuildCommit ||
				evidence.BuildBuiltAt != requirement.BuildBuiltAt ||
				evidence.BuildGoVersion != requirement.BuildGoVersion ||
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
		"tix_tcp_full_kmod",
		"owdeb_tix_tcp_full_kmod",
		"secure_kudp",
		"secure_tix_tcp_kernel",
		"route_gso",
	} {
		if checkedByFamily[family] == 0 {
			t.Fatalf("no current cross-host production defaults checked for gate family %s", family)
		}
	}
}

func TestCurrentProductionEvidenceRequirementsCoverCrossHostDefaults(t *testing.T) {
	defaults := loadProductionTransportDefaults(t)
	requirements := loadCurrentProductionEvidenceRequirements(t)
	crossHostDefaults := map[string]productionTransportDefault{}
	for _, row := range defaults {
		if row.ValidationScope != "cross_host" {
			continue
		}
		crossHostDefaults[productionDefaultEvidenceKey(row)] = row
	}
	for key, row := range crossHostDefaults {
		requirement, ok := requirements[key]
		if !ok {
			t.Fatalf("cross-host production default lacks current evidence requirement: %+v", row)
		}
		if requirement.GateManifestSchema != productionGateManifestSchema {
			t.Fatalf("current production evidence requirement must be manifest-backed: %s %+v", key, requirement)
		}
		if !isSHA256Hex(requirement.ProductionGateSHA256) || !isSHA256Hex(requirement.VerifierSHA256) {
			t.Fatalf("current production evidence requirement must pin gate/verifier SHA256 values: %s %+v", key, requirement)
		}
		if !isSHA256Hex(requirement.BinarySHA256) || requirement.BuildVersion == "" ||
			requirement.BuildCommit == "" || requirement.BuildBuiltAt == "" || requirement.BuildGoVersion == "" {
			t.Fatalf("current production evidence requirement must pin binary/build identity: %s %+v", key, requirement)
		}
		if !strings.HasPrefix(requirement.Artifact, "docs/") || !strings.Contains(requirement.Artifact, "#") {
			t.Fatalf("current production evidence requirement should point to a docs anchor: %s %+v", key, requirement)
		}
	}
	for key := range requirements {
		if _, ok := crossHostDefaults[key]; !ok {
			t.Fatalf("current production evidence requirement has no matching cross-host default: %s", key)
		}
	}
}

func TestCurrentProductionEvidenceToolchainLegacyAllowlistIsExact(t *testing.T) {
	requirements := loadCurrentProductionEvidenceRequirements(t)
	legacyAllowlist := loadAuditCurrentToolchainLegacyRequirementKeys(t)
	seenLegacy := map[string]bool{}
	for key, requirement := range requirements {
		values := []string{
			requirement.RunnerSHA256,
			requirement.TransportMatrixSHA256,
			requirement.EvidenceGeneratorSHA256,
		}
		present := 0
		for _, value := range values {
			if value != "" {
				present++
			}
		}
		legacyKey := key + "|" + requirement.Artifact
		switch present {
		case 0:
			if !legacyAllowlist[legacyKey] {
				t.Fatalf("current evidence requirement without toolchain hashes is not allowlisted: %s", legacyKey)
			}
			seenLegacy[legacyKey] = true
		case 3:
			for _, value := range values {
				if !isSHA256Hex(value) {
					t.Fatalf("current evidence requirement has invalid toolchain SHA256 fields: %s %+v", key, requirement)
				}
			}
		default:
			t.Fatalf("current evidence requirement must set all or none of runner/matrix/generator SHA256 fields: %s %+v", key, requirement)
		}
	}
	for key := range legacyAllowlist {
		if !seenLegacy[key] {
			t.Fatalf("CURRENT_TOOLCHAIN_LEGACY_REQUIREMENTS contains stale or mismatched key: %s", key)
		}
	}
}

func TestProductionTransportAuditReportsCurrentRefreshGaps(t *testing.T) {
	python := requirePython3(t)
	cmd := exec.Command(python, "production-transport-audit.py",
		"--scope", "cross_host",
		"--require-manifest",
		"--require-current",
		"--require-artifact-reference",
		"--require-current-build-ancestor",
		"--require-current-gate-tools",
		"--require-current-runtime-tree",
		"--fail-on-missing",
		"--report-refresh-gaps",
		"--json",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production transport audit with refresh report failed: %v\n%s", err, output)
	}
	var rows []struct {
		Key     string `json:"key"`
		Default struct {
			GateFamily string `json:"gate_family"`
		} `json:"default"`
		CurrentRefresh struct {
			Status  string   `json:"status"`
			Reasons []string `json:"reasons"`
		} `json:"current_refresh"`
		CurrentRequirement struct {
			Artifact string `json:"artifact"`
		} `json:"current_requirement"`
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		t.Fatalf("decode audit refresh JSON: %v\n%s", err, output)
	}
	legacyAllowlist := loadAuditCurrentToolchainLegacyRequirementKeys(t)
	refreshNeeded := map[string]bool{}
	for _, row := range rows {
		legacyKey := row.Key + "|" + row.CurrentRequirement.Artifact
		if row.CurrentRefresh.Status == "refresh_needed" {
			refreshNeeded[legacyKey] = true
			if row.Default.GateFamily != "userspace" {
				t.Fatalf("low-level production default current evidence is stale: key=%s gate_family=%s reasons=%v\n%s", row.Key, row.Default.GateFamily, row.CurrentRefresh.Reasons, output)
			}
			if len(row.CurrentRefresh.Reasons) == 0 {
				t.Fatalf("refresh-needed row lacks reasons: %+v\n%s", row, output)
			}
			continue
		}
		if legacyAllowlist[legacyKey] {
			t.Fatalf("legacy current evidence row was not reported as refresh-needed: %s\n%s", legacyKey, output)
		}
	}
	for legacyKey := range legacyAllowlist {
		if !refreshNeeded[legacyKey] {
			t.Fatalf("legacy current evidence row missing from refresh report: %s\n%s", legacyKey, output)
		}
	}
}

func TestProductionTransportAuditScriptCoversCrossHostDefaults(t *testing.T) {
	python := requirePython3(t)
	cmd := exec.Command(python, "production-transport-audit.py",
		"--scope", "cross_host",
		"--require-manifest",
		"--require-current",
		"--require-artifact-reference",
		"--require-current-build-ancestor",
		"--require-current-gate-tools",
		"--require-current-runtime-tree",
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
			MinGbps              string `json:"min_gbps"`
			MinSeconds           string `json:"min_seconds"`
			GateManifestSchema   string `json:"gate_manifest_schema"`
			ProductionGateSHA256 string `json:"production_gate_sha256"`
			VerifierSHA256       string `json:"verifier_sha256"`
			Artifact             string `json:"artifact"`
			BinarySHA256         string `json:"binary_sha256"`
			BuildVersion         string `json:"build_version"`
			BuildCommit          string `json:"build_commit"`
			BuildBuiltAt         string `json:"build_built_at"`
			BuildGoVersion       string `json:"build_go_version"`
		} `json:"evidence"`
		CurrentRequirement struct {
			OSMatrix             string `json:"os_matrix"`
			KernelMatrix         string `json:"kernel_matrix"`
			GateManifestSchema   string `json:"gate_manifest_schema"`
			ProductionGateSHA256 string `json:"production_gate_sha256"`
			VerifierSHA256       string `json:"verifier_sha256"`
			Artifact             string `json:"artifact"`
			BinarySHA256         string `json:"binary_sha256"`
			BuildVersion         string `json:"build_version"`
			BuildCommit          string `json:"build_commit"`
			BuildBuiltAt         string `json:"build_built_at"`
			BuildGoVersion       string `json:"build_go_version"`
		} `json:"current_requirement"`
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
		if row.CurrentRequirement.GateManifestSchema != productionGateManifestSchema {
			t.Fatalf("audit did not report current manifest requirement for %s: %+v", row.Key, row.CurrentRequirement)
		}
		if row.Evidence.Artifact != row.CurrentRequirement.Artifact {
			t.Fatalf("audit accepted stale artifact for %s: evidence=%+v current=%+v", row.Key, row.Evidence, row.CurrentRequirement)
		}
		if row.Evidence.ProductionGateSHA256 != row.CurrentRequirement.ProductionGateSHA256 ||
			row.Evidence.VerifierSHA256 != row.CurrentRequirement.VerifierSHA256 {
			t.Fatalf("audit accepted stale gate/verifier hashes for %s: evidence=%+v current=%+v", row.Key, row.Evidence, row.CurrentRequirement)
		}
		if row.Evidence.BinarySHA256 != row.CurrentRequirement.BinarySHA256 ||
			row.Evidence.BuildVersion != row.CurrentRequirement.BuildVersion ||
			row.Evidence.BuildCommit != row.CurrentRequirement.BuildCommit ||
			row.Evidence.BuildBuiltAt != row.CurrentRequirement.BuildBuiltAt ||
			row.Evidence.BuildGoVersion != row.CurrentRequirement.BuildGoVersion {
			t.Fatalf("audit accepted stale binary/build identity for %s: evidence=%+v current=%+v", row.Key, row.Evidence, row.CurrentRequirement)
		}
		if row.CurrentRequirement.ProductionGateSHA256 == "" || row.CurrentRequirement.VerifierSHA256 == "" {
			t.Fatalf("audit did not report pinned current gate/verifier hashes for %s: %+v", row.Key, row.CurrentRequirement)
		}
		if row.CurrentRequirement.BinarySHA256 == "" || row.CurrentRequirement.BuildCommit == "" {
			t.Fatalf("audit did not report pinned current binary/build identity for %s: %+v", row.Key, row.CurrentRequirement)
		}
		if !strings.HasPrefix(row.Evidence.Artifact, "docs/") || !strings.Contains(row.Evidence.Artifact, "#") {
			t.Fatalf("audit evidence artifact should be a docs anchor for %s: %+v", row.Key, row.Evidence)
		}
	}
}

func TestProductionTransportAuditScriptDefaultsResolveFromRepoRoot(t *testing.T) {
	python := requirePython3(t)
	cmd := exec.Command(python, "scripts/production-transport-audit.py",
		"--scope", "cross_host",
		"--require-manifest",
		"--require-current",
		"--require-artifact-reference",
		"--require-current-build-ancestor",
		"--require-current-gate-tools",
		"--require-current-runtime-tree",
		"--fail-on-missing",
		"--json",
	)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production transport audit should resolve default TSVs from repo root: %v\n%s", err, output)
	}
	var rows []struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		t.Fatalf("decode audit JSON: %v\n%s", err, output)
	}
	if len(rows) == 0 {
		t.Fatalf("audit from repo root returned no rows:\n%s", output)
	}
	for _, row := range rows {
		if row.Status != "pass" {
			t.Fatalf("audit from repo root emitted non-pass row: %+v\n%s", row, output)
		}
	}
}

func TestCIWorkflowRunsCurrentProductionTransportAudit(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci workflow: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"fetch-depth: 0",
		"Production Transport Evidence Audit",
		"python3 scripts/production-transport-audit.py",
		"--scope cross_host",
		"--require-manifest",
		"--require-current",
		"--require-artifact-reference",
		"--require-current-build-ancestor",
		"--require-current-gate-tools",
		"--require-current-runtime-tree",
		"--fail-on-missing",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("ci workflow production audit step missing %q", want)
		}
	}
}

func TestProductionTransportAuditScriptRequireArtifactReferenceRejectsMissingAnchor(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t0.5\t30\trequire artifact reference",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	evidencePayload := strings.Join([]string{
		"# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note",
		strings.Join([]string{
			"userspace",
			"udp",
			"secure",
			"stable",
			"userspace",
			"userspace",
			"cross_host",
			"debian13-debian13",
			"6.12.90_to_6.12.90",
			"pass",
			"2.0",
			"3600",
			productionGateManifestSchema,
			strings.Repeat("a", 64),
			strings.Repeat("b", 64),
			"docs/trustix-performance-log.md#missing-production-audit-anchor",
			"missing docs anchor",
		}, "\t"),
		"",
	}, "\n")
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--scope", "cross_host",
		"--require-manifest",
		"--require-artifact-reference",
		"--fail-on-missing",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted missing artifact anchor:\n%s", output)
	}
	text := string(output)
	if !strings.Contains(text, "lack matching evidence") ||
		!strings.Contains(text, "artifact anchor") {
		t.Fatalf("audit failure did not explain missing artifact anchor:\n%s", output)
	}
}

func TestProductionTransportAuditScriptRejectsGateFamilySemanticMismatch(t *testing.T) {
	python := requirePython3(t)
	tests := []struct {
		name     string
		defaults []string
		evidence []string
		want     string
	}{
		{
			name: "default_secure_kudp_wrong_transport",
			defaults: []string{
				"tix_tcp\tsecure\tperformance\ttc_xdp\tkernel\tcross_host\tsecure_kudp\t1.5\t3600\tsecure kernel TCP must not reuse secure-kUDP gate",
			},
			want: "production defaults:2: gate_family=secure_kudp requires transport=kernel_udp; got transport=tix_tcp",
		},
		{
			name: "evidence_route_gso_wrong_transport",
			defaults: []string{
				"tix_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\troute_gso\t2.5\t3600\tselected route-GSO gate",
			},
			evidence: []string{
				strings.Join([]string{
					"route_gso",
					"udp",
					"plaintext",
					"performance",
					"kernel_module",
					"userspace",
					"cross_host",
					"debian13-debian13",
					"6.12.90_to_6.12.90",
					"pass",
					"3",
					"3600",
					productionGateManifestSchema,
					strings.Repeat("a", 64),
					strings.Repeat("b", 64),
					"docs/trustix-performance-log.md#2026-06-27-zaozhuang-pve-973a020-kmod-6-12-94-3600s-production-gates",
					"route-GSO evidence with wrong transport",
				}, "\t"),
			},
			want: "production evidence:2: gate_family=route_gso requires transport=tix_tcp; got transport=udp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workdir := t.TempDir()
			defaults := filepath.Join(workdir, "defaults.tsv")
			evidence := filepath.Join(workdir, "evidence.tsv")
			defaultPayload := append([]string{
				"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
			}, tt.defaults...)
			defaultPayload = append(defaultPayload, "")
			if err := os.WriteFile(defaults, []byte(strings.Join(defaultPayload, "\n")), 0o644); err != nil {
				t.Fatalf("write defaults: %v", err)
			}
			evidencePayload := append([]string{
				"# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note",
			}, tt.evidence...)
			evidencePayload = append(evidencePayload, "")
			if err := os.WriteFile(evidence, []byte(strings.Join(evidencePayload, "\n")), 0o644); err != nil {
				t.Fatalf("write evidence: %v", err)
			}

			cmd := exec.Command(python, "production-transport-audit.py",
				"--defaults", slashPath(defaults),
				"--evidence", slashPath(evidence),
				"--scope", "cross_host",
				"--require-manifest",
				"--fail-on-missing",
			)
			cmd.Dir = "."
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("audit accepted semantic mismatch:\n%s", output)
			}
			if !strings.Contains(string(output), tt.want) {
				t.Fatalf("audit output missing %q:\n%s", tt.want, output)
			}
		})
	}
}

func TestProductionTransportAuditScriptPrefersLongerSoakBeforeSourceOrder(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t0.5\t30\tprefer strongest evidence",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	strongerEarly := strings.Join([]string{
		"userspace",
		"udp",
		"secure",
		"stable",
		"userspace",
		"userspace",
		"cross_host",
		"debian13-debian13",
		"6.12.90_to_6.12.90",
		"pass",
		"2.0",
		"3600",
		productionGateManifestSchema,
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
		"docs/trustix-performance-log.md#stronger-early",
		"stronger evidence listed first",
	}, "\t")
	weakerLater := strings.Join([]string{
		"userspace",
		"udp",
		"secure",
		"stable",
		"userspace",
		"userspace",
		"cross_host",
		"debian13-debian13",
		"6.12.69_to_6.12.69",
		"pass",
		"0.75",
		"60",
		productionGateManifestSchema,
		strings.Repeat("c", 64),
		strings.Repeat("d", 64),
		"docs/trustix-performance-log.md#weaker-later",
		"weaker evidence listed later",
	}, "\t")
	evidencePayload := strings.Join([]string{
		"# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note",
		strongerEarly,
		weakerLater,
		"",
	}, "\n")
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
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
		Evidence struct {
			Artifact   string `json:"artifact"`
			MinGbps    string `json:"min_gbps"`
			MinSeconds string `json:"min_seconds"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		t.Fatalf("decode audit JSON: %v\n%s", err, output)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1\n%s", len(rows), output)
	}
	if rows[0].Evidence.Artifact != "docs/trustix-performance-log.md#stronger-early" ||
		rows[0].Evidence.MinSeconds != "3600" ||
		rows[0].Evidence.MinGbps != "2.0" {
		t.Fatalf("audit chose weaker accepted evidence: %+v\n%s", rows[0].Evidence, output)
	}
}

func TestProductionTransportAuditScriptPrefersNewestEqualDurationEvidence(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\t3\t3600\tprefer current equal-duration evidence",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	olderHigherGbps := strings.Join([]string{
		"full_kmod",
		"udp",
		"plaintext",
		"performance",
		"kernel_module",
		"userspace",
		"cross_host",
		"debian13-debian13",
		"6.12.94_to_6.12.94",
		"pass",
		"3.6",
		"3600",
		productionGateManifestSchema,
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
		"docs/trustix-performance-log.md#older-higher-gbps",
		"older equal-duration evidence",
	}, "\t")
	newerCurrent := strings.Join([]string{
		"full_kmod",
		"udp",
		"plaintext",
		"performance",
		"kernel_module",
		"userspace",
		"cross_host",
		"debian13-debian13",
		"6.12.90_to_6.12.90",
		"pass",
		"3.1",
		"3600",
		productionGateManifestSchema,
		strings.Repeat("c", 64),
		strings.Repeat("d", 64),
		"docs/trustix-performance-log.md#newer-current",
		"newer equal-duration evidence",
	}, "\t")
	evidencePayload := strings.Join([]string{
		"# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note",
		olderHigherGbps,
		newerCurrent,
		"",
	}, "\n")
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
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
		Evidence struct {
			Artifact   string `json:"artifact"`
			MinGbps    string `json:"min_gbps"`
			MinSeconds string `json:"min_seconds"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		t.Fatalf("decode audit JSON: %v\n%s", err, output)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1\n%s", len(rows), output)
	}
	if rows[0].Evidence.Artifact != "docs/trustix-performance-log.md#newer-current" ||
		rows[0].Evidence.MinSeconds != "3600" ||
		rows[0].Evidence.MinGbps != "3.1" {
		t.Fatalf("audit chose stale equal-duration evidence: %+v\n%s", rows[0].Evidence, output)
	}
}

func TestProductionTransportAuditScriptRequireCurrentRejectsStaleEvidence(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	current := filepath.Join(workdir, "current.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\t3\t3600\trequire current artifact",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	evidencePayload := strings.Join([]string{
		"# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note",
		strings.Join([]string{
			"full_kmod",
			"udp",
			"plaintext",
			"performance",
			"kernel_module",
			"userspace",
			"cross_host",
			"debian13-debian13",
			"6.12.90_to_6.12.90",
			"pass",
			"3.5",
			"3600",
			productionGateManifestSchema,
			strings.Repeat("a", 64),
			strings.Repeat("b", 64),
			"docs/trustix-performance-log.md#stale-but-fast",
			"stale evidence that still clears thresholds",
		}, "\t"),
		"",
	}, "\n")
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	currentPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\tdebian13-debian13\t6.12.94_to_6.12.94\t" + productionGateManifestSchema + "\t" + strings.Repeat("c", 64) + "\t" + strings.Repeat("d", 64) + "\tdocs/trustix-performance-log.md#current-required\tcurrent requirement\t" + strings.Repeat("e", 64) + "\ttrustix-current\tcurrent-commit\t2026-06-25T00:00:00Z\tgo1.25.0",
		"",
	}, "\n")
	if err := os.WriteFile(current, []byte(currentPayload), 0o644); err != nil {
		t.Fatalf("write current requirements: %v", err)
	}

	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-manifest",
		"--require-current",
		"--fail-on-missing",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted stale evidence with --require-current:\n%s", output)
	}
	if !strings.Contains(string(output), "lack matching evidence") {
		t.Fatalf("audit failure did not explain missing current evidence:\n%s", output)
	}
}

func TestProductionTransportAuditScriptRequireCurrentRejectsStaleBinaryIdentity(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	current := filepath.Join(workdir, "current.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\t3\t3600\trequire current binary identity",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	evidencePayload := strings.Join([]string{
		"# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version",
		strings.Join([]string{
			"full_kmod",
			"udp",
			"plaintext",
			"performance",
			"kernel_module",
			"userspace",
			"cross_host",
			"debian13-debian13",
			"6.12.90_to_6.12.90",
			"pass",
			"3.5",
			"3600",
			productionGateManifestSchema,
			strings.Repeat("a", 64),
			strings.Repeat("b", 64),
			"docs/trustix-performance-log.md#current-required",
			"stale binary identity",
			strings.Repeat("c", 64),
			"trustix-current",
			"old-commit",
			"2026-06-25T00:00:00Z",
			"go1.25.0",
		}, "\t"),
		"",
	}, "\n")
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	currentPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\tdebian13-debian13\t6.12.90_to_6.12.90\t" + productionGateManifestSchema + "\t" + strings.Repeat("a", 64) + "\t" + strings.Repeat("b", 64) + "\tdocs/trustix-performance-log.md#current-required\tcurrent requirement\t" + strings.Repeat("d", 64) + "\ttrustix-current\tnew-commit\t2026-06-25T00:00:00Z\tgo1.25.0",
		"",
	}, "\n")
	if err := os.WriteFile(current, []byte(currentPayload), 0o644); err != nil {
		t.Fatalf("write current requirements: %v", err)
	}

	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-manifest",
		"--require-current",
		"--fail-on-missing",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted stale binary/build identity with --require-current:\n%s", output)
	}
	text := string(output)
	if !strings.Contains(text, "lack matching evidence") ||
		!strings.Contains(text, "binary_sha256") ||
		!strings.Contains(text, "build_commit") {
		t.Fatalf("audit failure did not explain stale binary/build identity:\n%s", output)
	}
}

func TestProductionTransportAuditScriptRequireCurrentRejectsInvalidCurrentIdentity(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	current := filepath.Join(workdir, "current.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\t3\t3600\trequire current identity",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	evidencePayload := "# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note\n"
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	currentPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\tdebian13-debian13\t6.12.94_to_6.12.94\tlegacy-pre-manifest\tnot-a-sha\t" + strings.Repeat("d", 64) + "\tdocs/trustix-performance-log.md#2026-06-27-zaozhuang-pve-973a020-kmod-6-12-94-3600s-production-gates\tinvalid current requirement\tlegacy-pre-manifest\ttrustix-current\t\t2026-06-25T00:00:00Z\tgo1.25.0",
		"",
	}, "\n")
	if err := os.WriteFile(current, []byte(currentPayload), 0o644); err != nil {
		t.Fatalf("write current requirements: %v", err)
	}

	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-current",
		"--require-artifact-reference",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted invalid current identity:\n%s", output)
	}
	text := string(output)
	for _, want := range []string{
		"current evidence requirements:2",
		"gate_manifest_schema must be " + productionGateManifestSchema,
		"production_gate_sha256 must be 64 lowercase hex",
		"binary_sha256 must be 64 lowercase hex",
		"build_commit must be non-empty current build metadata",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit failure missing %q:\n%s", want, output)
		}
	}
}

func TestProductionTransportAuditScriptRequireCurrentRejectsUnknownBuildCommit(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	current := filepath.Join(workdir, "current.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\t3\t3600\trequire resolvable build commit",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	evidencePayload := "# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note\n"
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	currentPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\tdebian13-debian13\t6.12.94_to_6.12.94\t" + productionGateManifestSchema + "\t" + strings.Repeat("a", 64) + "\t" + strings.Repeat("b", 64) + "\tdocs/trustix-performance-log.md#unknown-build-commit\tunknown build commit\t" + strings.Repeat("c", 64) + "\ttrustix-current\tffffffffffffffffffffffffffffffffffffffff\t2026-06-25T00:00:00Z\tgo1.25.0",
		"",
	}, "\n")
	if err := os.WriteFile(current, []byte(currentPayload), 0o644); err != nil {
		t.Fatalf("write current requirements: %v", err)
	}

	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-current",
		"--require-current-build-ancestor",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted unknown current build commit:\n%s", output)
	}
	text := string(output)
	for _, want := range []string{
		"current evidence requirements:2",
		"build_commit",
		"must resolve to a commit in this repository",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit failure missing %q:\n%s", want, output)
		}
	}
}

func TestProductionTransportAuditScriptRequireCurrentRuntimeTree(t *testing.T) {
	python := requirePython3(t)
	staleRuntimeParent := latestRuntimeParentCommit(t, "kernel/trustix_crypto/trustix_crypto.c")
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	current := filepath.Join(workdir, "current.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"tix_tcp\tsecure\tperformance\tkernel_module\tkernel\tcross_host\tsecure_tix_tcp_kernel\t1.5\t3600\trequire runtime tree freshness",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	evidencePayload := "# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note\n"
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	currentPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version",
		"tix_tcp\tsecure\tperformance\tkernel_module\tkernel\tcross_host\tsecure_tix_tcp_kernel\tdebian13-debian13\t6.12.94_to_6.12.94\t" + productionGateManifestSchema + "\t" + strings.Repeat("a", 64) + "\t" + strings.Repeat("b", 64) + "\tdocs/trustix-performance-log.md#stale-runtime-tree\tstale runtime tree\t" + strings.Repeat("c", 64) + "\ttrustix-current\t" + staleRuntimeParent + "\t2026-06-25T00:00:00Z\tgo1.25.0",
		"",
	}, "\n")
	if err := os.WriteFile(current, []byte(currentPayload), 0o644); err != nil {
		t.Fatalf("write current requirements: %v", err)
	}

	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-current",
		"--require-current-build-ancestor",
		"--require-current-runtime-tree",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted stale runtime tree build commit:\n%s", output)
	}
	text := string(output)
	for _, want := range []string{
		"current evidence requirements:2",
		"runtime/dataplane tree changes",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit failure missing %q:\n%s", want, output)
		}
	}
}

func TestProductionTransportAuditScriptRuntimePathRelevance(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import subprocess
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

cases = [
    ({"gate_family": "full_kmod"}, "internal/webui/assets/app.js", False),
    ({"gate_family": "userspace"}, r"internal\webui\assets\app.css", False),
    ({"gate_family": "tix_tcp_full_kmod"}, "internal/daemon/ix_provision_resource.go", False),
    ({"gate_family": "tix_tcp_full_kmod"}, r"internal\daemon\ix_provision_resource.go", False),
    ({"gate_family": "tix_tcp_full_kmod"}, "internal/daemon/datapath.go", True),
    ({"gate_family": "tix_tcp_full_kmod"}, "internal/daemon/kernel_datapath_state_linux.go", True),
    ({"gate_family": "secure_kudp"}, "internal/daemon/kernel_datapath_state_linux.go", False),
    ({"gate_family": "userspace_tc"}, "internal/daemon/kernel_datapath_state_linux.go", False),
    ({"gate_family": "tix_tcp_full_kmod"}, "internal/daemon/kernel_modules.go", True),
    ({"gate_family": "tix_tcp_full_kmod"}, "internal/daemon/transports_status.go", True),
    ({"gate_family": "tix_tcp_full_kmod"}, "internal/transport/tixtcp/runtime.go", True),
    ({"gate_family": "tix_tcp_full_kmod"}, "internal/kernelmodule/aead_ioctl_linux.go", True),
    ({"gate_family": "full_kmod"}, "internal/kernelmodule/aead_ioctl_linux.go", True),
    ({"gate_family": "full_kmod"}, "kernel/trustix_datapath/trustix_datapath.c", True),
    ({"gate_family": "tix_tcp_full_kmod"}, "kernel/trustix_datapath/trustix_datapath.c", True),
    ({"gate_family": "route_gso"}, "kernel/trustix_datapath/trustix_datapath.c", False),
    ({"gate_family": "full_kmod"}, "kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c", False),
    ({"gate_family": "tix_tcp_full_kmod"}, "kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c", False),
    ({"gate_family": "route_gso"}, "kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c", True),
    ({"gate_family": "secure_kudp"}, "kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c", True),
    ({"gate_family": "secure_tix_tcp_kernel"}, "kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c", True),
    ({"gate_family": "full_kmod"}, "kernel/trustix_crypto/trustix_crypto.c", False),
    ({"gate_family": "route_gso"}, "kernel/trustix_crypto/trustix_crypto.c", False),
    ({"gate_family": "secure_kudp"}, "kernel/trustix_crypto/trustix_crypto.c", True),
    ({"gate_family": "secure_tix_tcp_kernel"}, "kernel/trustix_crypto/trustix_crypto.c", True),
    ({"gate_family": "full_kmod"}, "internal/dataplane/ebpf/manager_linux.go", False),
    ({"gate_family": "userspace_tc"}, "internal/dataplane/ebpf/manager_linux.go", False),
    ({"gate_family": "userspace_tc"}, "internal/kernelmodule/aead_ioctl_linux.go", False),
    ({"gate_family": "userspace_tc"}, "internal/daemon/datapath.go", False),
    ({"gate_family": "userspace_tc"}, "internal/daemon/kernel_modules.go", False),
    ({"gate_family": "tc_direct"}, "kernel/bpf/dataplane/kernel_udp_tx_tc.c", True),
    ({"gate_family": "tc_direct"}, "scripts/build-embedded-bpf.sh", True),
    ({"gate_family": "tc_direct"}, "internal/daemon/kernel_udp_direct_policy.go", True),
    ({"gate_family": "full_kmod"}, "internal/daemon/kernel_udp_direct_policy.go", False),
    ({"gate_family": "route_gso"}, "internal/kernelmodule/aead_ioctl_linux.go", True),
    ({"gate_family": "tix_tcp_full_kmod"}, "internal/daemon/kernel_modules_test.go", False),
    ({"gate_family": "userspace"}, "internal/daemon/datapath.go", False),
    ({"gate_family": "userspace"}, "internal/dataplane/ebpf/manager_linux.go", False),
    ({"gate_family": "userspace"}, "internal/kernelmodule/aead_ioctl_linux.go", False),
    ({"gate_family": "userspace", "transport": "tcp"}, "internal/transport/tixtcp/runtime.go", False),
    ({"gate_family": "userspace", "transport": "tix_tcp"}, "internal/transport/tixtcp/runtime.go", True),
    ({"gate_family": "userspace", "transport": "quic"}, "internal/transport/quic/quic.go", True),
    ({"gate_family": "userspace", "transport": "udp"}, "internal/transport/quic/quic.go", False),
    ({"gate_family": "userspace_tc", "transport": "gre"}, "internal/transport/quic/quic.go", False),
    ({"gate_family": "userspace", "transport": "udp"}, "internal/transport/iptunnel/carrier.go", False),
    ({"gate_family": "userspace_tc", "transport": "gre"}, "internal/transport/iptunnel/carrier.go", True),
    ({"gate_family": "userspace_tc", "transport": "vxlan"}, "internal/transport/iptunnel/iptunnel.go", True),
    ({"gate_family": "userspace"}, "internal/config/config.go", True),
]
for row, path, want in cases:
    got = module.current_runtime_path_relevant(row, path)
    if got != want:
        print(f"{path}: got {got}, want {want}", file=sys.stderr)
        sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runtime path relevance filter failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptProtocolNamingOnlyExemption(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

rename_commits = [
    "f0173d53b71513dbd9b781ad65e7e2744654cc8c",
    "a8ec4cb0f79cc75d8b6c21ae9ab452c1464413c6",
]
probe = {"commit": ""}
module.path_changed_only_by = lambda resolved, normalized, allowed: probe["commit"] in allowed
parent = "parent-does-not-matter-for-probed-history"
for rename_commit in rename_commits:
    probe["commit"] = rename_commit
    if not module.current_runtime_path_change_irrelevant(
        {"gate_family": "secure_tix_tcp_kernel", "transport": "tix_tcp"},
        parent,
        "internal/config/load.go",
    ):
        print(f"protocol naming-only change {rename_commit} was not exempt", file=sys.stderr)
        sys.exit(1)

probe["commit"] = "1111111111111111111111111111111111111111"
if module.current_runtime_path_change_irrelevant(
    {"gate_family": "secure_tix_tcp_kernel", "transport": "tix_tcp"},
    parent,
    "internal/config/load.go",
):
    print("protocol naming-only exemption covered an unrelated commit", file=sys.stderr)
    sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("protocol naming-only exemption regression failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptVXLANCarrierFragmentScope(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

probe = {"commit": "c7ea32e25422dea4849b7ae8abe885556eabfa62"}
module.path_changed_only_by = lambda resolved, normalized, allowed: probe["commit"] in allowed
parent = "parent-does-not-matter-for-probed-history"
for path in [
    "internal/transport/iptunnel/carrier.go",
    "internal/transport/iptunnel/iptunnel.go",
]:
    cases = [
        ({"gate_family": "userspace_tc", "transport": "vxlan"}, False),
        ({"gate_family": "userspace_tc", "transport": "gre"}, True),
        ({"gate_family": "userspace_tc", "transport": "ipip"}, True),
        ({"gate_family": "userspace", "transport": "udp"}, True),
    ]
    for row, want in cases:
        got = module.current_runtime_path_change_irrelevant(row, parent, path)
        if got != want:
            print(f"VXLAN carrier scope mismatch for {path} row={row}: got {got}, want {want}", file=sys.stderr)
            sys.exit(1)

probe["commit"] = "1111111111111111111111111111111111111111"
if module.current_runtime_path_change_irrelevant(
    {"gate_family": "userspace_tc", "transport": "gre"},
    parent,
    "internal/transport/iptunnel/carrier.go",
):
    print("VXLAN carrier exemption covered an unrelated commit", file=sys.stderr)
    sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("VXLAN carrier scope regression failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptD479UserspaceUDPDefaultOnlyExemptions(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import subprocess
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

commit = "d4796543b2640792bc28e1edc93f10def92ec47d"
parent = subprocess.check_output(["git", "rev-parse", commit + "^"], text=True).strip()
cases = [
    ({"gate_family": "full_kmod", "transport": "udp"}, "internal/daemon/gso_coalesce.go", True),
    ({"gate_family": "userspace_tc", "transport": "gre"}, "internal/daemon/gso_coalesce.go", True),
    ({"gate_family": "secure_kudp", "transport": "kernel_udp"}, "internal/daemon/gso_coalesce.go", True),
    ({"gate_family": "userspace", "transport": "udp"}, "internal/transport/udp/udp.go", False),
    ({"gate_family": "userspace", "transport": "udp"}, "internal/transport/udp/udp_read_packet_size_linux.go", False),
]
for row, path, want in cases:
    got = module.current_runtime_path_change_irrelevant(row, parent, path)
    if got != want:
        print(f"{path} row={row}: got {got}, want {want}", file=sys.stderr)
        sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("d479 userspace UDP exemption regression failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptSessionWarmupObservabilityExemption(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

probe = {"commit": "9a3fc75839a4dc1ba65810656f5686d988d92d33"}
module.path_changed_only_by = lambda resolved, normalized, allowed: probe["commit"] in allowed
parent = "parent-does-not-matter-for-probed-history"
path = "internal/daemon/datapath.go"
for row in [
    {"gate_family": "full_kmod", "transport": "udp"},
    {"gate_family": "userspace", "transport": "tix_tcp"},
]:
    if not module.current_runtime_path_change_irrelevant(row, parent, path):
        print(f"session warmup observability change not exempt for {row}", file=sys.stderr)
        sys.exit(1)

probe["commit"] = "1dfaf51caac8bc03177de4ec428e23659db69173"
row = {"gate_family": "userspace", "transport": "tix_tcp"}
if module.current_runtime_path_change_irrelevant(row, parent, path):
    print("exemption incorrectly covered unrelated datapath.go commits", file=sys.stderr)
    sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("session warmup observability exemption regression failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptSessionPoolLifecycleExemption(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

probe = {"commit": "55c8268fb4552f33c680b01a5faa08a8a1dd6bcc"}
module.path_changed_only_by = lambda resolved, normalized, allowed: probe["commit"] in allowed
parent = "parent-does-not-matter-for-probed-history"
path = "internal/daemon/datapath.go"
for row in [
    {"gate_family": "full_kmod", "transport": "udp"},
    {"gate_family": "userspace", "transport": "tix_tcp"},
]:
    if not module.current_runtime_path_change_irrelevant(row, parent, path):
        print(f"session pool lifecycle change not exempt for {row}", file=sys.stderr)
        sys.exit(1)

probe["commit"] = "1111111111111111111111111111111111111111"
if module.current_runtime_path_change_irrelevant(
    {"gate_family": "full_kmod", "transport": "udp"}, parent, path
):
    print("session pool lifecycle exemption covered an unrelated commit", file=sys.stderr)
    sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("session pool lifecycle exemption regression failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptAddressedReverseSessionPoolScope(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

probe = {"commit": "774ed8d5633c51079dc8fb9bcae6de970ea023ea"}
module.path_changed_only_by = lambda resolved, normalized, allowed: probe["commit"] in allowed
parent = "parent-does-not-matter-for-probed-history"
path = "internal/daemon/datapath.go"
cases = [
    ({"gate_family": "secure_kudp", "transport": "kernel_udp", "encryption": "secure"}, False),
    ({"gate_family": "owdeb_secure_kudp", "transport": "kernel_udp", "encryption": "secure"}, False),
    ({"gate_family": "userspace", "transport": "tix_tcp", "encryption": "plaintext"}, False),
    ({"gate_family": "userspace_tc", "transport": "tix_tcp", "encryption": "plaintext"}, False),
    ({"gate_family": "tc_direct", "transport": "tix_tcp", "encryption": "plaintext"}, False),
    ({"gate_family": "route_gso", "transport": "tix_tcp", "encryption": "plaintext"}, True),
    ({"gate_family": "tix_tcp_full_kmod", "transport": "tix_tcp", "encryption": "plaintext"}, True),
    ({"gate_family": "full_kmod", "transport": "tix_tcp", "encryption": "plaintext"}, True),
    ({"gate_family": "secure_tix_tcp_kernel", "transport": "tix_tcp", "encryption": "secure"}, True),
    ({"gate_family": "userspace", "transport": "tix_tcp", "encryption": "secure"}, True),
    ({"gate_family": "userspace", "transport": "udp", "encryption": "plaintext"}, True),
]
for row, want in cases:
    got = module.current_runtime_path_change_irrelevant(row, parent, path)
    if got != want:
        print(f"addressed reverse-session pool scope mismatch for {row}: got {got}, want {want}", file=sys.stderr)
        sys.exit(1)

probe["commit"] = "1111111111111111111111111111111111111111"
if module.current_runtime_path_change_irrelevant(
    {"gate_family": "route_gso", "transport": "tix_tcp", "encryption": "plaintext"},
    parent,
    path,
):
    print("addressed reverse-session pool exemption covered an unrelated commit", file=sys.stderr)
    sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("addressed reverse-session pool scope regression failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptVirtioRouteGSODeviceGuardScope(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

probe = {"commit": "5af52d414e1f120e78d0441ec5501ef6ae57e7ab"}
module.path_changed_only_by = lambda resolved, normalized, allowed: probe["commit"] in allowed
parent = "parent-does-not-matter-for-probed-history"
path = "kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c"
cases = [
    ({"gate_family": "route_gso", "transport": "tix_tcp"}, False),
    ({"gate_family": "dd_route_gso", "transport": "tix_tcp"}, False),
    ({"gate_family": "secure_tix_tcp_kernel", "transport": "tix_tcp"}, False),
    ({"gate_family": "owdeb_secure_tix_tcp_kernel", "transport": "tix_tcp"}, False),
    ({"gate_family": "secure_kudp", "transport": "kernel_udp"}, True),
    ({"gate_family": "owdeb_secure_kudp", "transport": "kernel_udp"}, True),
    ({"gate_family": "full_kmod", "transport": "udp"}, True),
    ({"gate_family": "tix_tcp_full_kmod", "transport": "tix_tcp"}, True),
    ({"gate_family": "userspace", "transport": "tix_tcp"}, True),
]
for row, want in cases:
    got = module.current_runtime_path_change_irrelevant(row, parent, path)
    if got != want:
        print(f"virtio route-GSO device guard scope mismatch for {row}: got {got}, want {want}", file=sys.stderr)
        sys.exit(1)

probe["commit"] = "1111111111111111111111111111111111111111"
if module.current_runtime_path_change_irrelevant(
    {"gate_family": "secure_kudp", "transport": "kernel_udp"}, parent, path
):
    print("virtio route-GSO device guard exemption covered an unrelated commit", file=sys.stderr)
    sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("virtio route-GSO device guard scope regression failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptKernelUDPSessionLifecycleExemption(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import subprocess
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

probe = {"commit": "f61fbaddd6bb8de8678be3a37bce3bc426622b7e"}
module.path_changed_only_by = lambda resolved, normalized, allowed: probe["commit"] in allowed
parent = "parent-does-not-matter-for-probed-history"
path = "internal/transport/udp/udp.go"
cases = [
    ({"gate_family": "userspace", "transport": "udp"}, True),
    ({"gate_family": "full_kmod", "transport": "udp"}, True),
    ({"gate_family": "secure_kudp", "transport": "kernel_udp"}, False),
    ({"gate_family": "owdeb_full_kmod", "transport": "udp"}, True),
]
for row, want in cases:
    got = module.current_runtime_path_change_irrelevant(row, parent, path)
    if got != want:
        print(f"kernel UDP lifecycle exemption mismatch for {row}: got {got}, want {want}", file=sys.stderr)
        sys.exit(1)

probe["commit"] = "d4796543b2640792bc28e1edc93f10def92ec47d"
row = {"gate_family": "userspace", "transport": "udp"}
if module.current_runtime_path_change_irrelevant(row, parent, path):
    print("exemption incorrectly covered unrelated udp.go commits", file=sys.stderr)
    sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kernel UDP session lifecycle exemption regression failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptPlaintextKernelUDPHeartbeatScope(t *testing.T) {
	python := requirePython3(t)
	code := `
import importlib.util
import pathlib
import sys

script = pathlib.Path("production-transport-audit.py")
spec = importlib.util.spec_from_file_location("audit", script)
module = importlib.util.module_from_spec(spec)
if spec.loader is None:
    print("missing import loader", file=sys.stderr)
    sys.exit(1)
spec.loader.exec_module(module)

probe = {"commit": "20c977829b7665996d65b9567e09a4b491c9c4e4"}
module.path_changed_only_by = lambda resolved, normalized, allowed: probe["commit"] in allowed
parent = "parent-does-not-matter-for-probed-history"
path = "internal/daemon/datapath.go"
cases = [
    ({"gate_family": "full_kmod", "transport": "udp", "encryption": "plaintext"}, True),
    ({"gate_family": "owdeb_full_kmod", "transport": "udp", "encryption": "plaintext"}, True),
    ({"gate_family": "tc_direct", "transport": "kernel_udp", "encryption": "plaintext"}, False),
    ({"gate_family": "userspace_tc", "transport": "udp", "encryption": "plaintext"}, False),
    ({"gate_family": "userspace", "transport": "udp", "encryption": "plaintext"}, True),
    ({"gate_family": "tix_tcp_full_kmod", "transport": "tix_tcp", "encryption": "plaintext"}, True),
    ({"gate_family": "secure_kudp", "transport": "kernel_udp", "encryption": "secure"}, True),
    ({"gate_family": "route_gso", "transport": "tix_tcp", "encryption": "plaintext"}, True),
]
for row, want in cases:
    got = module.current_runtime_path_change_irrelevant(row, parent, path)
    if got != want:
        print(f"plaintext kernel UDP heartbeat scope mismatch for {row}: got {got}, want {want}", file=sys.stderr)
        sys.exit(1)
`
	cmd := exec.Command(python, "-c", code)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("plaintext kernel UDP heartbeat scope regression failed: %v\n%s", err, output)
	}
}

func TestProductionTransportAuditScriptRequireCurrentGateTools(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	current := filepath.Join(workdir, "current.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\t3\t3600\trequire current gate tooling",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	evidencePayload := "# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note\n"
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	currentHeader := "# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version\trunner_sha256\ttransport_matrix_sha256\tevidence_generator_sha256"
	currentRowPrefix := func(productionGateSHA, verifierSHA string) string {
		return "udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\tdebian13-debian13\t6.12.94_to_6.12.94\t" + productionGateManifestSchema + "\t" + productionGateSHA + "\t" + verifierSHA + "\tdocs/trustix-performance-log.md#current-tooling\tcurrent gate tooling\t" + strings.Repeat("c", 64) + "\ttrustix-current\tcurrent-commit\t2026-06-25T00:00:00Z\tgo1.25.0"
	}
	currentPayload := func(productionGateSHA, verifierSHA, runnerSHA, matrixSHA, generatorSHA string) string {
		return strings.Join([]string{
			currentHeader,
			currentRowPrefix(productionGateSHA, verifierSHA) + "\t" + runnerSHA + "\t" + matrixSHA + "\t" + generatorSHA,
			"",
		}, "\n")
	}
	currentPayloadWithoutToolchain := func(productionGateSHA, verifierSHA string) string {
		return strings.Join([]string{
			"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version",
			currentRowPrefix(productionGateSHA, verifierSHA),
			"",
		}, "\n")
	}
	currentGateSHA := sha256File(t, "linux-cross-host-production-gate.sh")
	currentVerifierSHA := sha256File(t, "linux-cross-host-soak-verify.py")
	currentRunnerSHA := sha256File(t, "linux-cross-host-soak-runner.sh")
	currentMatrixSHA := sha256File(t, "linux-cross-host-transport-matrix.sh")
	currentGeneratorSHA := sha256File(t, "production-evidence-from-gate-summary.py")
	if err := os.WriteFile(current, []byte(currentPayload(currentGateSHA, currentVerifierSHA, currentRunnerSHA, currentMatrixSHA, currentGeneratorSHA)), 0o644); err != nil {
		t.Fatalf("write current requirements: %v", err)
	}
	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-current",
		"--require-current-gate-tools",
	)
	cmd.Dir = "."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("audit rejected current gate tool hashes: %v\n%s", err, output)
	}

	if err := os.WriteFile(current, []byte(currentPayloadWithoutToolchain(currentGateSHA, currentVerifierSHA)), 0o644); err != nil {
		t.Fatalf("write missing-toolchain current requirements: %v", err)
	}
	missingToolchainCmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-current",
		"--require-current-gate-tools",
	)
	missingToolchainCmd.Dir = "."
	output, err := missingToolchainCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted new current requirement without toolchain hashes:\n%s", output)
	}
	if !strings.Contains(string(output), "are required for new current evidence rows") {
		t.Fatalf("missing-toolchain failure did not explain toolchain requirement:\n%s", output)
	}

	if err := os.WriteFile(current, []byte(currentPayload(strings.Repeat("a", 64), strings.Repeat("b", 64), currentRunnerSHA, currentMatrixSHA, currentGeneratorSHA)), 0o644); err != nil {
		t.Fatalf("write stale current requirements: %v", err)
	}
	staleCmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-current",
		"--require-current-gate-tools",
	)
	staleCmd.Dir = "."
	output, err = staleCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted stale gate tool hashes:\n%s", output)
	}
	text := string(output)
	for _, want := range []string{
		"current evidence requirements:2",
		"production_gate_sha256 must match current or compatible",
		"verifier_sha256 must match current",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit failure missing %q:\n%s", want, output)
		}
	}

	if err := os.WriteFile(current, []byte(currentPayload(currentGateSHA, currentVerifierSHA, strings.Repeat("d", 64), currentMatrixSHA, currentGeneratorSHA)), 0o644); err != nil {
		t.Fatalf("write stale runner current requirements: %v", err)
	}
	staleRunnerCmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-current",
		"--require-current-gate-tools",
	)
	staleRunnerCmd.Dir = "."
	output, err = staleRunnerCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted stale runner hash:\n%s", output)
	}
	if !strings.Contains(string(output), "runner_sha256 must match current") {
		t.Fatalf("stale runner failure missing runner hash diagnostic:\n%s", output)
	}

	const preQueueAssertionGateSHA = "1371160cca3cceb50617f1cae8704b1755b858bcf08ca530f32b7d46245b19d3"
	if err := os.WriteFile(current, []byte(currentPayload(preQueueAssertionGateSHA, currentVerifierSHA, currentRunnerSHA, currentMatrixSHA, currentGeneratorSHA)), 0o644); err != nil {
		t.Fatalf("write pre-queue-assertion current requirements: %v", err)
	}
	preQueueAssertionCmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-current",
		"--require-current-gate-tools",
	)
	preQueueAssertionCmd.Dir = "."
	output, err = preQueueAssertionCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted a pre-queue-assertion gate for full_kmod:\n%s", output)
	}
	if !strings.Contains(string(output), "production_gate_sha256 must match current or compatible") {
		t.Fatalf("pre-queue-assertion failure missing gate hash diagnostic:\n%s", output)
	}
}

func TestProductionTransportAuditScriptRequireCurrentRejectsRequirementDrift(t *testing.T) {
	python := requirePython3(t)
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	evidence := filepath.Join(workdir, "evidence.tsv")
	current := filepath.Join(workdir, "current.tsv")
	defaultPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t0.5\t30\trequire current row",
		"",
	}, "\n")
	if err := os.WriteFile(defaults, []byte(defaultPayload), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	evidencePayload := "# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note\n"
	if err := os.WriteFile(evidence, []byte(evidencePayload), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	currentPayload := strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version",
		"tcp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\tdebian13-debian13\t6.12.69_to_6.12.69\t" + productionGateManifestSchema + "\t" + strings.Repeat("c", 64) + "\t" + strings.Repeat("d", 64) + "\tdocs/trustix-performance-log.md#unexpected\tunexpected current requirement\t" + strings.Repeat("e", 64) + "\ttrustix-current\tcurrent-commit\t2026-06-25T00:00:00Z\tgo1.25.0",
		"",
	}, "\n")
	if err := os.WriteFile(current, []byte(currentPayload), 0o644); err != nil {
		t.Fatalf("write current requirements: %v", err)
	}

	cmd := exec.Command(python, "production-transport-audit.py",
		"--defaults", slashPath(defaults),
		"--evidence", slashPath(evidence),
		"--current-requirements", slashPath(current),
		"--scope", "cross_host",
		"--require-current",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit accepted current requirement drift:\n%s", output)
	}
	if !strings.Contains(string(output), "current evidence requirements do not match audited defaults") {
		t.Fatalf("audit failure did not explain current requirement drift:\n%s", output)
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
	requirements := loadCurrentProductionEvidenceRequirements(t)
	const finalProductionArtifact = "docs/trustix-performance-log.md#2026-07-12-zaozhuang-pve-0ceffe6-final-production"
	manifestRequiredArtifacts := map[string]string{
		"tc_direct":               finalProductionArtifact,
		"full_kmod":               finalProductionArtifact,
		"tix_tcp_full_kmod":       finalProductionArtifact,
		"owdeb_tix_tcp_full_kmod": finalProductionArtifact,
		"secure_kudp":             finalProductionArtifact,
		"secure_tix_tcp_kernel":   finalProductionArtifact,
		"route_gso":               finalProductionArtifact,
		"owdeb_full_kmod":         finalProductionArtifact,
		"userspace":               finalProductionArtifact,
		"userspace_tc":            finalProductionArtifact,
	}
	manifestRequiredArtifactByDefault := map[string]string{}
	legacyPendingFamilies := map[string]bool{}
	seen := map[string]bool{}
	for _, row := range loadProductionTransportDefaults(t) {
		if row.ValidationScope != "cross_host" {
			continue
		}
		requirement, ok := currentProductionEvidenceRequirementForDefault(requirements, row)
		if !ok {
			t.Fatalf("cross-host production default lacks current evidence requirement: %+v", row)
		}
		seen[row.GateFamily] = true
		wantManifestArtifact := manifestRequiredArtifactByDefault[productionDefaultEvidenceKey(row)]
		if wantManifestArtifact == "" {
			wantManifestArtifact = manifestRequiredArtifacts[row.GateFamily]
		}
		switch {
		case wantManifestArtifact != "":
			if requirement.GateManifestSchema != productionGateManifestSchema {
				t.Fatalf("production default must require manifest-backed evidence: row=%+v requirement=%+v", row, requirement)
			}
			if requirement.Artifact != wantManifestArtifact {
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
		wantArtifact     = "docs/trustix-performance-log.md#2026-07-05-zaozhuang-pve-8c2eebc-openwrt24107-debian13-full-kmod-production"
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
		"owdeb_secure_tix_tcp_kernel:openwrt24.10.2-debian13:6.6.93_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24102-full-kmod-production-gate":                 false,
		"owdeb_secure_kudp:openwrt24.10.7-debian13:6.6.141_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24107-runtime-capability-check":                           false,
		"owdeb_route_gso:openwrt24.10.7-debian13:6.6.141_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24107-runtime-capability-check":                             false,
		"owdeb_secure_tix_tcp_kernel:openwrt24.10.7-debian13:6.6.141_to_6.12.90+deb13.1-cloud-amd64:docs/trustix-performance-log.md#openwrt-24107-runtime-capability-check":                 false,
		"owdeb_secure_kudp:openwrt25.12.4-debian13:6.12.87_to_6.12.94+deb13-amd64:docs/trustix-performance-log.md#2026-06-24-zaozhuang-pve-openwrt-25124-route-gso-runtime-check":           false,
		"owdeb_route_gso:openwrt25.12.4-debian13:6.12.87_to_6.12.94+deb13-amd64:docs/trustix-performance-log.md#2026-06-24-zaozhuang-pve-openwrt-25124-route-gso-runtime-check":             false,
		"owdeb_secure_tix_tcp_kernel:openwrt25.12.4-debian13:6.12.87_to_6.12.94+deb13-amd64:docs/trustix-performance-log.md#2026-06-24-zaozhuang-pve-openwrt-25124-route-gso-runtime-check": false,
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

func TestOpenWrtRouteGSOFamiliesRequirePassingCurrentGateBeforeDefault(t *testing.T) {
	openWrtRouteGSOFamilies := map[string]bool{
		"owdeb_secure_kudp":           true,
		"owdeb_route_gso":             true,
		"owdeb_secure_tix_tcp_kernel": true,
	}
	passingEvidence := map[string][]productionTransportEvidence{}
	for _, evidence := range loadProductionTransportEvidence(t) {
		if !openWrtRouteGSOFamilies[evidence.GateFamily] {
			continue
		}
		if evidence.GateManifestSchema != productionGateManifestSchema ||
			evidence.Result != "pass" ||
			!strings.HasPrefix(evidence.OSMatrix, "openwrt") {
			continue
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid OpenWrt route-GSO evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid OpenWrt route-GSO evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		if evidenceSeconds >= 3600 && evidenceGbps > 0 {
			passingEvidence[evidence.GateFamily] = append(passingEvidence[evidence.GateFamily], evidence)
		}
	}

	requirements := loadCurrentProductionEvidenceRequirements(t)
	for _, row := range loadProductionTransportDefaults(t) {
		if row.ValidationScope != "cross_host" || !openWrtRouteGSOFamilies[row.GateFamily] {
			continue
		}
		requirement, ok := currentProductionEvidenceRequirementForDefault(requirements, row)
		if !ok {
			t.Fatalf("OpenWrt route-GSO default lacks current evidence requirement: %+v", row)
		}
		var matchesCurrent bool
		for _, evidence := range passingEvidence[row.GateFamily] {
			if evidence.OSMatrix == requirement.OSMatrix &&
				evidence.KernelMatrix == requirement.KernelMatrix &&
				evidence.Artifact == requirement.Artifact &&
				evidence.BinarySHA256 == requirement.BinarySHA256 &&
				evidence.BuildCommit == requirement.BuildCommit {
				matchesCurrent = true
				break
			}
		}
		if !matchesCurrent {
			t.Fatalf("OpenWrt route-GSO family %s cannot be a production default until it has current 3600s passing OpenWrt evidence: row=%+v requirement=%+v passing=%+v", row.GateFamily, row, requirement, passingEvidence[row.GateFamily])
		}
	}
}

func TestOpenWrtSecureTIXTCPKernelFailClosedRowsInheritRouteTCPGate(t *testing.T) {
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
		if evidence.GateFamily != "owdeb_secure_tix_tcp_kernel" {
			continue
		}
		seen++
		if evidence.Result != "fail_closed" || evidence.MinGbps != "0" || evidence.MinSeconds != "30" {
			t.Fatalf("OpenWrt secure TIX-TCP kernel evidence must be fail-closed prerequisite evidence, got %+v", evidence)
		}
		if !strings.Contains(evidence.Note, "route-TCP kfunc") {
			t.Fatalf("OpenWrt secure TIX-TCP kernel evidence must name the missing route-TCP prerequisite: %+v", evidence)
		}
		if !routeTCPFailures[keyFor(evidence)] {
			t.Fatalf("OpenWrt secure TIX-TCP kernel fail-closed row is not tied to route-GSO route-TCP capability evidence: %+v", evidence)
		}
	}
	if seen == 0 {
		t.Fatal("missing OpenWrt secure TIX-TCP kernel fail-closed boundary rows")
	}
}

func TestCurrentDebianFullKmodEvidenceCoversProductionGate(t *testing.T) {
	const (
		wantOSMatrix     = "debian13-debian13"
		wantKernelMatrix = "6.12.90+deb13.1-cloud-amd64_to_6.12.90+deb13.1-cloud-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-07-03-zaozhuang-pve-current-dd-kmod-regate"
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
		wantKernelMatrix = "6.12.90+deb13.1-cloud-amd64_to_6.12.90+deb13.1-cloud-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-07-03-zaozhuang-pve-netdevfix-kernel-fast-regate"
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
		wantArtifact     = "docs/trustix-performance-log.md#2026-07-05-zaozhuang-pve-8c2eebc-secure-kernel-production"
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
		wantArtifact     = "docs/trustix-performance-log.md#2026-07-04-zaozhuang-pve-add2971-route-gso-txq-backoff-production"
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

func TestCurrentDebianSecureTIXTCPKernelEvidenceCoversProductionGate(t *testing.T) {
	const (
		wantOSMatrix     = "debian13-debian13"
		wantKernelMatrix = "6.12.94+deb13-cloud-amd64_to_6.12.94+deb13-cloud-amd64"
		wantArtifact     = "docs/trustix-performance-log.md#2026-07-05-zaozhuang-pve-8c2eebc-secure-kernel-production"
		minGbps          = 1.5
		minSeconds       = 3600
	)
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.GateFamily != "secure_tix_tcp_kernel" ||
			evidence.OSMatrix != wantOSMatrix ||
			evidence.KernelMatrix != wantKernelMatrix ||
			evidence.Artifact != wantArtifact {
			continue
		}
		evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid Debian secure TIX-TCP kernel evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid Debian secure TIX-TCP kernel evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
			return
		}
		t.Fatalf("current Debian secure TIX-TCP kernel evidence is below production gate: %+v", evidence)
	}
	t.Fatalf("missing current Debian secure TIX-TCP kernel production evidence for %s / %s", wantOSMatrix, wantKernelMatrix)
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

func TestProductionDefaultsDoNotPromotePlainTIXTCPUserspaceWithoutStrictEvidence(t *testing.T) {
	const (
		minGbps    = 1.0
		minSeconds = 3600
	)

	hasStrictEvidence := false
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.Transport != "tix_tcp" ||
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
			t.Fatalf("invalid plaintext tix_tcp userspace evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid plaintext tix_tcp userspace evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		if evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
			hasStrictEvidence = true
			break
		}
	}

	var sawBaseline, sawRouteGSO bool
	for _, row := range loadProductionTransportDefaults(t) {
		if row.Transport != "tix_tcp" || row.Encryption != "plaintext" {
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
			t.Fatalf("plaintext tix_tcp userspace cross-host default requires fresh strict 3600s manifest evidence: %+v", row)
		}
	}
	if !sawBaseline {
		t.Fatal("plaintext tix_tcp userspace single-host baseline default disappeared")
	}
	if !sawRouteGSO {
		t.Fatal("plaintext tix_tcp cross-host production default should stay on the selected route-GSO gate")
	}
}

func TestProductionDefaultsDoNotReuseSecureKUDPForSecureTIXTCPKernelCrypto(t *testing.T) {
	const (
		minGbps    = 1.5
		minSeconds = 3600
	)

	hasStrictDedicatedEvidence := false
	for _, evidence := range loadProductionTransportEvidence(t) {
		if evidence.GateFamily == "secure_kudp" && evidence.Transport != "kernel_udp" {
			t.Fatalf("secure_kudp evidence must describe kernel_udp, not another secure kernel crypto transport: %+v", evidence)
		}
		if evidence.Transport != "tix_tcp" ||
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
			t.Fatalf("invalid secure tix_tcp kernel evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil {
			t.Fatalf("invalid secure tix_tcp kernel evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
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
		if row.Transport != "tix_tcp" || row.Encryption != "secure" {
			continue
		}
		if row.Profile == "stable" &&
			row.Datapath == "userspace" &&
			row.CryptoPlacement == "userspace" &&
			row.ValidationScope == "cross_host" &&
			row.GateFamily == "userspace" &&
			row.MinGbps == "0.5" &&
			row.MinSeconds == "3600" {
			sawSecureUserspace = true
		}
		if row.Profile == "performance" &&
			row.CryptoPlacement == "kernel" &&
			row.ValidationScope == "cross_host" &&
			!hasStrictDedicatedEvidence {
			t.Fatalf("secure tix_tcp kernel-crypto production default requires dedicated strict 3600s manifest evidence: %+v", row)
		}
	}
	if !sawSecureUserspace {
		t.Fatal("secure tix_tcp userspace cross-host production default disappeared")
	}
}

func TestProductionTransportDefaultsCoverProtocolsAndValidationScopes(t *testing.T) {
	defaults := readProductionTransportDefaults(t)
	for _, wantCase := range []string{
		"udp:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"udp:secure:stable:userspace:userspace:cross_host:userspace:1.5:3600",
		"udp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"udp:plaintext:stable:userspace:userspace:cross_host:userspace:1.5:3600",
		"udp:plaintext:performance:kernel_module:userspace:cross_host:full_kmod:3:3600",
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
		"vxlan:secure:stable:tc_xdp:userspace:cross_host:userspace_tc:0.75:3600",
		"vxlan:plaintext:performance:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"vxlan:plaintext:performance:tc_xdp:userspace:cross_host:userspace_tc:4:3600",
		"kernel_udp:plaintext:performance:tc_xdp:userspace:single_host:tc_direct:0:30",
		"kernel_udp:plaintext:performance:tc_xdp:userspace:cross_host:tc_direct:3:3600",
		"kernel_udp:secure:performance:tc_xdp:kernel:cross_host:secure_kudp:1.5:3600",
		"tix_tcp:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"tix_tcp:secure:stable:userspace:userspace:cross_host:userspace:0.5:3600",
		"tix_tcp:secure:performance:kernel_module:kernel:cross_host:secure_tix_tcp_kernel:1.5:3600",
		"tix_tcp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"tix_tcp:plaintext:performance:kernel_module:userspace:cross_host:tix_tcp_full_kmod:4:3600",
		"tix_tcp:plaintext:performance:kernel_module:userspace:cross_host:owdeb_tix_tcp_full_kmod:4:3600",
		"tix_tcp:plaintext:performance:kernel_module:userspace:cross_host:route_gso:2.5:3600",
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
		"kernel_udp": true, "tix_tcp": true,
	}
	knownGate := map[string]bool{
		"userspace": true, "userspace_tc": true, "tc_direct": true,
		"full_kmod": true, "owdeb_full_kmod": true,
		"tix_tcp_full_kmod": true, "owdeb_tix_tcp_full_kmod": true,
		"secure_kudp": true, "secure_tix_tcp_kernel": true, "route_gso": true,
	}
	crossHostGate := map[string]bool{
		"userspace": true, "userspace_tc": true, "tc_direct": true,
		"full_kmod": true, "owdeb_full_kmod": true,
		"tix_tcp_full_kmod": true, "owdeb_tix_tcp_full_kmod": true,
		"secure_kudp": true, "secure_tix_tcp_kernel": true, "route_gso": true,
	}
	crossHostOnlyGate := map[string]bool{
		"full_kmod": true, "owdeb_full_kmod": true,
		"tix_tcp_full_kmod": true, "owdeb_tix_tcp_full_kmod": true,
		"secure_kudp": true, "secure_tix_tcp_kernel": true, "route_gso": true,
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
		case "stable", "performance":
		default:
			t.Fatalf("unknown profile %q in %+v", row.Profile, row)
		}
		switch row.Datapath {
		case "userspace", "tc_xdp", "kernel_module":
		default:
			t.Fatalf("unknown datapath %q in %+v", row.Datapath, row)
		}
		switch row.CryptoPlacement {
		case "userspace", "kernel":
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
	for _, transport := range []string{"udp", "tcp", "quic", "websocket", "http_connect", "tix_tcp"} {
		for _, encryption := range []string{"secure", "plaintext"} {
			key := transport + ":" + encryption
			if !baseline[key] {
				t.Fatalf("missing stable userspace baseline for %s", key)
			}
		}
	}
}

func TestCrossHostProductionDefaultsCoverTransportEncryptionModes(t *testing.T) {
	requirements := loadCurrentProductionEvidenceRequirements(t)
	coverage := map[string]map[string][]productionTransportDefault{}
	for _, row := range loadProductionTransportDefaults(t) {
		if row.ValidationScope != "cross_host" {
			continue
		}
		requirement, ok := currentProductionEvidenceRequirementForDefault(requirements, row)
		if !ok {
			t.Fatalf("cross-host production default lacks current evidence requirement: %+v", row)
		}
		if requirement.GateManifestSchema != productionGateManifestSchema {
			t.Fatalf("cross-host production default lacks manifest-backed current evidence requirement: %+v requirement=%+v", row, requirement)
		}
		if row.MinSeconds != "3600" {
			t.Fatalf("cross-host production default must stay on 3600s soak evidence: %+v", row)
		}
		if coverage[row.Transport] == nil {
			coverage[row.Transport] = map[string][]productionTransportDefault{}
		}
		coverage[row.Transport][row.Encryption] = append(coverage[row.Transport][row.Encryption], row)
	}
	for _, transport := range []string{
		"udp",
		"tcp",
		"quic",
		"websocket",
		"http_connect",
		"gre",
		"ipip",
		"vxlan",
		"kernel_udp",
		"tix_tcp",
	} {
		for _, encryption := range []string{"secure", "plaintext"} {
			if len(coverage[transport][encryption]) == 0 {
				t.Fatalf("missing cross-host production default for %s %s; coverage=%#v", transport, encryption, coverage[transport])
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
		"route_tcp_gso_async_worker_dequeue_batch=32",
		"route_tcp_gso_async_hash_tx_queue=0",
		"route_tcp_gso_async_txq_stopped_backoff_retries=1",
		"route_tcp_gso_async_txq_stopped_backoff_sleep_usecs=50",
		"route_tcp_gso_async_worker_min_queue_depth=0",
		"route_tcp_gso_async_worker_schedule_delay_usecs=0",
		"tix_tcp_route_gso_async_worker_item_budget=64",
		"tix_tcp_route_gso_async_worker_segment_budget=2048",
		"route_tcp_gso_async_worker_item_budget=${tix_tcp_route_gso_async_worker_item_budget}",
		"route_tcp_gso_async_worker_segment_budget=${tix_tcp_route_gso_async_worker_segment_budget}",
		"tixt_rx_coalesce_segment_gso=0",
		"tixt_rx_backlog_worker_budget=2048",
		"tixt_rx_backlog_worker_queue_limit=65536",
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
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_MIN_GBPS:-${gate_min_gbps:-0.75}",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_MIN_GBPS:-${gate_min_gbps:-0}",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS:-${gate_min_gbps:-3}",
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_MIN_GBPS:-${gate_min_gbps:-4}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS:-${gate_min_gbps:-1.5}",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_MIN_GBPS:-${gate_min_gbps:-1.5}",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS:-${gate_min_gbps:-2.5}",
		"max_decimal()",
		"min_decimal()",
		"max_integer()",
		"min_integer()",
		"userspace_min_gbps=\"$(max_decimal \"$userspace_min_gbps\" \"0.5\")\"",
		"userspace_tc_min_gbps=\"$(max_decimal \"$userspace_tc_min_gbps\" \"0.75\")\"",
		"tc_direct_min_gbps=\"$(max_decimal \"$tc_direct_min_gbps\" \"3\")\"",
		"full_kmod_min_gbps=\"$(max_decimal \"$full_kmod_min_gbps\" \"3\")\"",
		"secure_kudp_min_gbps=\"$(max_decimal \"$secure_kudp_min_gbps\" \"1.5\")\"",
		"secure_tix_tcp_kernel_min_gbps=\"$(max_decimal \"$secure_tix_tcp_kernel_min_gbps\" \"1.5\")\"",
		"route_gso_min_gbps=\"$(max_decimal \"$route_gso_min_gbps\" \"2.5\")\"",
		"TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS:-3600",
		"min_seconds=\"$(max_decimal \"$min_seconds\" \"3600\")\"",
		"seconds_slop=\"$(min_decimal \"$seconds_slop\" \"1\")\"",
		"TRUSTIX_CROSS_HOST_GATE_MIN_IPERF_INTERVALS:-600",
		"min_iperf_intervals=\"$(max_integer \"$min_iperf_intervals\" \"600\")\"",
		"TRUSTIX_CROSS_HOST_GATE_MIN_INTERVAL_GBPS_RATIO:-0.25",
		"min_interval_gbps_ratio=\"$(max_decimal \"$min_interval_gbps_ratio\" \"0.25\")\"",
		"TRUSTIX_CROSS_HOST_GATE_MIN_HOST_CPUS:-4",
		"TRUSTIX_CROSS_HOST_GATE_FORBID_HOST_NET_DRIVER:-e1000 e1000e rtl8139 8139cp 8139too pcnet32 ne2k_pci",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_MIN_POOL_SIZE:-16",
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_MIN_SESSIONS:-16",
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_SESSION_ERROR_BUDGET:-0",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_CRYPTO_FLOWS:-1",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_DIRECT_ERROR_BUDGET:-64",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_REPLAY_SEEN_RATIO_BUDGET:-0.00002",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_DROP_RATIO_BUDGET:-0.00002",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_MIN_CRYPTO_FLOWS:-1",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_SESSION_ERROR_BUDGET:-2",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_DIRECT_ERROR_BUDGET:-0",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_REPLAY_RATIO_BUDGET:-0.00002",
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
		"TRUSTIX_CROSS_HOST_DD_TIX_TCP_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_OWDEB_TIX_TCP_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_DD_SECURE_KUDP",
		"TRUSTIX_CROSS_HOST_OWDEB_SECURE_KUDP",
		"TRUSTIX_CROSS_HOST_DD_ROUTE_GSO",
		"TRUSTIX_CROSS_HOST_OWDEB_ROUTE_GSO",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_CASE_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASE_MIN_GBPS",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS",
		"validate_number TRUSTIX_CROSS_HOST_USERSPACE_MIN_GBPS \"$userspace_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_USERSPACE_TC_MIN_GBPS \"$userspace_tc_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_TC_DIRECT_MIN_GBPS \"$tc_direct_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS \"$full_kmod_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_MIN_GBPS \"$tix_tcp_full_kmod_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS \"$secure_kudp_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_MIN_GBPS \"$secure_tix_tcp_kernel_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS \"$route_gso_min_gbps\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_GATE_MIN_HOST_CPUS \"$min_host_cpus\"",
		"min_host_cpus=\"$(max_integer \"$min_host_cpus\" \"4\")\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_SESSIONS \"$full_kmod_min_sessions\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_SESSIONS \"$secure_kudp_min_sessions\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_CRYPTO_FLOWS \"$secure_kudp_min_crypto_flows\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_KUDP_DIRECT_ERROR_BUDGET \"$secure_kudp_direct_error_budget\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_REPLAY_SEEN_RATIO_BUDGET \"$secure_kudp_replay_seen_ratio_budget\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_DROP_RATIO_BUDGET \"$secure_kudp_drop_ratio_budget\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_MIN_SESSIONS \"$secure_tix_tcp_kernel_min_sessions\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_MIN_CRYPTO_FLOWS \"$secure_tix_tcp_kernel_min_crypto_flows\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_SESSION_ERROR_BUDGET \"$secure_tix_tcp_kernel_session_error_budget\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_DIRECT_ERROR_BUDGET \"$secure_tix_tcp_kernel_direct_error_budget\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_REPLAY_RATIO_BUDGET \"$secure_tix_tcp_kernel_replay_ratio_budget\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_SESSIONS \"$route_gso_min_sessions\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET \"$route_gso_session_error_budget\"",
		"validate_nonnegative_integer TRUSTIX_CROSS_HOST_COMPAT_MIN_SESSIONS \"$compat_min_sessions\"",
		"full_kmod_min_sessions=\"$(max_integer \"$full_kmod_min_sessions\" \"8\")\"",
		"tix_tcp_full_kmod_min_pool_size=\"$(max_integer \"$tix_tcp_full_kmod_min_pool_size\" \"16\")\"",
		"tix_tcp_full_kmod_min_sessions=\"$(max_integer \"$tix_tcp_full_kmod_min_sessions\" \"16\")\"",
		"tix_tcp_full_kmod_session_error_budget=\"$(min_integer \"$tix_tcp_full_kmod_session_error_budget\" \"0\")\"",
		"secure_kudp_min_sessions=\"$(max_integer \"$secure_kudp_min_sessions\" \"8\")\"",
		"secure_kudp_min_crypto_flows=\"$(max_integer \"$secure_kudp_min_crypto_flows\" \"1\")\"",
		"secure_kudp_direct_error_budget=\"$(min_integer \"$secure_kudp_direct_error_budget\" \"64\")\"",
		"secure_kudp_replay_seen_ratio_budget=\"$(min_decimal \"$secure_kudp_replay_seen_ratio_budget\" \"0.00002\")\"",
		"secure_kudp_drop_ratio_budget=\"$(min_decimal \"$secure_kudp_drop_ratio_budget\" \"0.00002\")\"",
		"secure_tix_tcp_kernel_min_sessions=\"$(max_integer \"$secure_tix_tcp_kernel_min_sessions\" \"8\")\"",
		"secure_tix_tcp_kernel_min_crypto_flows=\"$(max_integer \"$secure_tix_tcp_kernel_min_crypto_flows\" \"1\")\"",
		"secure_tix_tcp_kernel_session_error_budget=\"$(min_integer \"$secure_tix_tcp_kernel_session_error_budget\" \"2\")\"",
		"secure_tix_tcp_kernel_direct_error_budget=\"$(min_integer \"$secure_tix_tcp_kernel_direct_error_budget\" \"0\")\"",
		"secure_tix_tcp_kernel_replay_ratio_budget=\"$(min_decimal \"$secure_tix_tcp_kernel_replay_ratio_budget\" \"0.00002\")\"",
		"route_gso_min_sessions=\"$(max_integer \"$route_gso_min_sessions\" \"8\")\"",
		"route_gso_session_error_budget=\"$(min_integer \"$route_gso_session_error_budget\" \"2\")\"",
		"compat_min_sessions=\"$(max_integer \"$compat_min_sessions\" \"1\")\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_USERSPACE_CASE_MIN_GBPS \"$userspace_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_USERSPACE_TC_CASE_MIN_GBPS \"$userspace_tc_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_TC_DIRECT_CASE_MIN_GBPS \"$tc_direct_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_GBPS \"$full_kmod_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_CASE_MIN_GBPS \"$tix_tcp_full_kmod_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS \"$secure_kudp_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASE_MIN_GBPS \"$secure_tix_tcp_kernel_case_min_gbps_raw\"",
		"validate_case_min_map TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_GBPS \"$route_gso_case_min_gbps_raw\"",
		"validate_case_seconds_map TRUSTIX_CROSS_HOST_FULL_KMOD_CASE_MIN_SECONDS \"$full_kmod_case_min_seconds_raw\"",
		"validate_case_seconds_map TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_CASE_MIN_SECONDS \"$tix_tcp_full_kmod_case_min_seconds_raw\"",
		"validate_case_seconds_map TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_SECONDS \"$secure_kudp_case_min_seconds_raw\"",
		"validate_case_seconds_map TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASE_MIN_SECONDS \"$secure_tix_tcp_kernel_case_min_seconds_raw\"",
		"validate_case_seconds_map TRUSTIX_CROSS_HOST_ROUTE_GSO_CASE_MIN_SECONDS \"$route_gso_case_min_seconds_raw\"",
		"case_min_gbps()",
		"case_min_seconds()",
		"case_policy_stat_args()",
		"session_transport_for_matrix_transport()",
		"session_endpoint_suffix_for_matrix_transport()",
		"case_session_args()",
		"case_module_param_args()",
		"case_is_openwrt_debian()",
		"route_tcp_helper_capability_args()",
		"write_gate_manifest()",
		"production-gate-manifest.json",
		"trustix-cross-host-production-gate-manifest-v1",
		"TRUSTIX_GATE_MANIFEST_USERSPACE_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_USERSPACE_TC_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_TC_DIRECT_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_FULL_KMOD_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_TIX_TCP_FULL_KMOD_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_SECURE_KUDP_CASE_MIN_GBPS",
		"TRUSTIX_GATE_MANIFEST_SECURE_TIX_TCP_KERNEL_CASE_MIN_GBPS",
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
		"--require-host-state-artifacts",
		"--min-host-state-nodes 2",
		"--min-host-cpus \"$min_host_cpus\"",
		"--forbid-host-net-driver \"$driver\"",
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
		"--require-transport-policy-min session_pool_size=\"${secure_tix_tcp_kernel_min_sessions}\"",
		"--require-transport-policy-min session_pool_size=\"${route_gso_min_sessions}\"",
		"--require-transport-policy-stat session_pool_strategy=flow",
		"--require-transport-policy-stat session_pool_warmup=true",
		"--require-transport-sessions-min \"${full_kmod_min_sessions}\"",
		"--require-status-min data_path.active_sessions=\"${route_gso_min_sessions}\"",
		"--require-status-max data_path.counters.session_dial_errors=\"${route_gso_session_error_budget}\"",
		"--require-status-max data_path.counters.session_heartbeat_timeouts=0",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1",
		"run_gate_case_list tix-tcp-full-kmod \"$tix_tcp_full_kmod_min_gbps\"",
		"--require-datapath-stat tix_tcp.provider=kernel_datapath_full_plaintext",
		"--require-datapath-stat tix_tcp.fast_path=true",
		"--require-datapath-stat capture_forwarder_suppressed=true",
		"--require-transport-session-stat \"stats.extra.tix_tcp_full_plaintext_kernel_datapath=1\"",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_packets=1",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_gso_segments=1",
		"--require-module-param-any-min trustix_datapath.rx_worker_injected=1",
		"--require-module-param-max trustix_datapath.tx_plaintext_gso_errors=0",
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
		"--require-datapath-min tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_seal_calls=1",
		"--require-datapath-min tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=1",
		"--require-datapath-max tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_errors=\"${secure_tix_tcp_kernel_direct_error_budget}\"",
		"--require-datapath-min tix_tcp.provider_stats.kernel_crypto_flow_map_entries=\"${secure_tix_tcp_kernel_min_crypto_flows}\"",
		"--require-datapath-min tix_tcp.provider_stats.kernel_crypto_flow_map_updates=\"${secure_tix_tcp_kernel_min_crypto_flows}\"",
		"--require-datapath-ratio-max tix_tcp.provider_stats.kernel_crypto_frame_replay_drops/tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=\"${secure_tix_tcp_kernel_replay_ratio_budget}\"",
		"--require-datapath-ratio-max tix_tcp.provider_stats.xdp_kernel_crypto_replay_drops/tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=\"${secure_tix_tcp_kernel_replay_ratio_budget}\"",
		"--require-datapath-ratio-max tix_tcp.provider_stats.xdp_kernel_crypto_replay_commit_errors/tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=\"${secure_tix_tcp_kernel_replay_ratio_budget}\"",
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
		"--require-module-param-min trustix_datapath_helpers.enable_features=768",
		"--require-module-param-min trustix_datapath_helpers.features=768",
		"--require-module-param-min trustix_datapath_helpers.safe_features=768",
		"--require-module-param-min trustix_datapath_helpers.selftests=3",
		"--require-module-param-max trustix_datapath_helpers.unsafe_features=0",
		"--require-module-param-max trustix_datapath_helpers.selftest_failures=0",
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
		"--require-module-param-min trustix_datapath.tx_plaintext_hash_tx_queue=1",
		"--require-module-param-max trustix_datapath.tx_plaintext_stream_coalesce=0",
		"--require-module-param-min trustix_datapath.session_records=\"${full_kmod_min_sessions}\"",
		"--require-module-param-min trustix_datapath.session_wire_records=\"${full_kmod_min_sessions}\"",
		"--require-module-param-min trustix_datapath.rx_worker_single_coalesce_max_frames=32",
		"--require-module-param-node-max a.trustix_datapath.rx_worker_single_coalesce=0",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_outer_gso_segments=1",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_direct_xmit_dst_mac_cache_hits=1",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_hash_tx_queue_sets=1",
		"--require-module-param-max trustix_datapath.tx_plaintext_hash_tx_queue_fallbacks=0",
		"--require-module-param-any-min trustix_datapath.rx_worker_dst_mac_cache_hits=1",
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
		"--require-datapath-stat kernel_udp.provider_stats.tc_tix_tcp_tx_direct_route_tcp_gso_async_kfunc=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_tix_tcp_tx_direct_route_tcp_gso_async_kfunc_requested=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_tix_tcp_only=1",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_hash_tx_queue=0",
		"--require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_txq_stopped_backoff_retries=1",
		"--require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_txq_stopped_backoff_sleep_usecs=50",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_direct_builds=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_direct_frames=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_xmit_packets=1",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_full=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_xmit_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_blocked=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_virtio_blocked=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_verify_errors=0",
		"--require-lsmod-module trustix_crypto",
		"--require-lsmod-module trustix_datapath_helpers",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-production-gate.sh missing %q", want)
		}
	}
	if strings.Contains(text, "--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_frames=1") {
		t.Fatal("linux-cross-host-production-gate.sh must not require outer-GSO on guarded devices")
	}
	for _, requirement := range []string{
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_direct_builds=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_direct_frames=1",
	} {
		if got := strings.Count(text, requirement); got != 2 {
			t.Fatalf("linux-cross-host-production-gate.sh should require %q for plaintext and secure route-GSO, got %d occurrences", requirement, got)
		}
	}
	if strings.Contains(text, "TRUSTIX_CROSS_HOST_GATE_REQUIRE_BINARY_IDENTITY") {
		t.Fatalf("linux-cross-host-production-gate.sh must not allow disabling binary identity checks")
	}
	for _, unwanted := range []string{
		"TRUSTIX_CROSS_HOST_DD_FULL_KMOD_TIX_TCP",
		"dd-fullkmod-tix-tcp",
		"tx_kernel_crypto_packet_seal_errors",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-cross-host-production-gate.sh still promotes diagnostic full-kmod tix_tcp case %q", unwanted)
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
			name:   "userspace-tc",
			marker: `if [[ "$userspace_tc_case_count" -gt 0 ]]; then`,
			want: []string{
				"run_gate_case_list userspace-tc \"$userspace_tc_min_gbps\"",
				"--require-transport-policy-stat datapath=tc_xdp",
				"--require-transport-policy-stat crypto_placement=userspace",
				"--require-status-max data_path.counters.session_heartbeat_timeouts=0",
				"--forbid-lsmod-prefix trustix_",
			},
		},
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
			name:   "tix-tcp-full-kmod",
			marker: `if [[ "$tix_tcp_full_kmod_case_count" -gt 0 ]]; then`,
			want: []string{
				"run_gate_case_list tix-tcp-full-kmod \"$tix_tcp_full_kmod_min_gbps\"",
				"--require-transport-policy-stat encryption=plaintext",
				"--require-transport-policy-stat profile=performance",
				"--require-transport-policy-stat datapath=kernel_module",
				"--require-transport-policy-stat crypto_placement=userspace",
				"--require-status-max data_path.counters.session_heartbeat_timeouts=0",
				"--require-datapath-stat tix_tcp.provider=kernel_datapath_full_plaintext",
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
		{
			name:   "secure-tix-tcp-kernel",
			marker: `if [[ "$secure_tix_tcp_kernel_case_count" -gt 0 ]]; then`,
			want: []string{
				"run_gate_case_list secure-tix-tcp-kernel \"$secure_tix_tcp_kernel_min_gbps\"",
				"--require-transport-policy-stat encryption=secure",
				"--require-transport-policy-stat profile=performance",
				"--require-transport-policy-stat datapath=kernel_module",
				"--require-transport-policy-stat crypto_placement=kernel",
				"--require-status-max data_path.counters.session_dial_errors=\"${secure_tix_tcp_kernel_session_error_budget}\"",
				"--require-datapath-min tix_tcp.provider_stats.kernel_crypto_flow_map_entries=\"${secure_tix_tcp_kernel_min_crypto_flows}\"",
				"--require-datapath-max tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_errors=\"${secure_tix_tcp_kernel_direct_error_budget}\"",
				"--require-datapath-ratio-max tix_tcp.provider_stats.kernel_crypto_frame_replay_drops/tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=\"${secure_tix_tcp_kernel_replay_ratio_budget}\"",
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

	fastName := "udp-secure-stable-userspace-userspace-userspace"
	slowName := "tcp-plaintext-stable-userspace-userspace-userspace"
	secureTLSName := "tcp-secure-stable-userspace-userspace-userspace"
	userspaceTCName := "gre-plaintext-performance-tc_xdp-userspace-userspace_tc"
	fastDir := slashPath(filepath.Join(workdir, "fast"))
	slowDir := slashPath(filepath.Join(workdir, "slow"))
	secureTLSDir := slashPath(filepath.Join(workdir, "secure-tls"))
	userspaceTCDir := slashPath(filepath.Join(workdir, "userspace-tc"))
	tcDirectDir := slashPath(filepath.Join(workdir, "tc-direct"))
	fullKmodDir := slashPath(filepath.Join(workdir, "full-kmod"))
	tixTCPFullKmodDir := slashPath(filepath.Join(workdir, "tix-tcp-full-kmod"))
	secureKUDPDir := slashPath(filepath.Join(workdir, "secure-kudp"))
	secureTIXTCPKernelDir := slashPath(filepath.Join(workdir, "secure-tix-tcp-kernel"))
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
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_MIN_SESSIONS=0",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_MIN_CRYPTO_FLOWS=0",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_SESSION_ERROR_BUDGET=999",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_DIRECT_ERROR_BUDGET=999",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_REPLAY_RATIO_BUDGET=999999",
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
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_CASES=expfull="+tixTCPFullKmodDir,
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_CASE_MIN_GBPS=expfull=0",
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_CASE_MIN_SECONDS=expfull=3600",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES=secure="+secureKUDPDir,
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS=secure=0",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_SECONDS=secure=3600",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_MIN_GBPS=0",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASES=secure-exp="+secureTIXTCPKernelDir,
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASE_MIN_GBPS=secure-exp=0",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASE_MIN_SECONDS=secure-exp=3600",
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
		"min_seconds":                                "3600",
		"seconds_slop":                               "1",
		"min_iperf_intervals":                        "600",
		"min_interval_gbps_ratio":                    "0.25",
		"full_kmod_min_sessions":                     "8",
		"tix_tcp_full_kmod_min_gbps":                 "4",
		"tix_tcp_full_kmod_min_pool_size":            "16",
		"tix_tcp_full_kmod_min_sessions":             "16",
		"tix_tcp_full_kmod_session_error_budget":     "0",
		"secure_kudp_min_sessions":                   "8",
		"secure_kudp_min_crypto_flows":               "1",
		"secure_kudp_direct_error_budget":            "64",
		"secure_kudp_replay_seen_ratio_budget":       "0.00002",
		"secure_kudp_drop_ratio_budget":              "0.00002",
		"secure_tix_tcp_kernel_min_gbps":             "1.5",
		"secure_tix_tcp_kernel_min_sessions":         "8",
		"secure_tix_tcp_kernel_min_crypto_flows":     "1",
		"secure_tix_tcp_kernel_session_error_budget": "2",
		"secure_tix_tcp_kernel_direct_error_budget":  "0",
		"secure_tix_tcp_kernel_replay_ratio_budget":  "0.00002",
		"route_gso_min_sessions":                     "8",
		"route_gso_session_error_budget":             "2",
		"compat_min_sessions":                        "1",
	} {
		if manifest.Thresholds[key] != want {
			t.Fatalf("manifest threshold %s = %q, want %q\n%s", key, manifest.Thresholds[key], want, manifestPayload)
		}
	}
	for key, wantSubstring := range map[string]string{
		"userspace":             secureTLSName + "=" + secureTLSDir,
		"userspace_tc":          userspaceTCName + "=" + userspaceTCDir,
		"tc_direct":             "tc=" + tcDirectDir,
		"full_kmod":             "full=" + fullKmodDir,
		"tix_tcp_full_kmod":     "expfull=" + tixTCPFullKmodDir,
		"secure_kudp":           "secure=" + secureKUDPDir,
		"secure_tix_tcp_kernel": "secure-exp=" + secureTIXTCPKernelDir,
		"route_gso":             "route=" + routeGSODir,
	} {
		if !strings.Contains(manifest.Cases[key], wantSubstring) {
			t.Fatalf("manifest cases[%s] missing %q:\n%s", key, wantSubstring, manifestPayload)
		}
	}
	for key, wantSubstring := range map[string]string{
		"userspace":             fastName + "=1.5",
		"userspace_tc":          userspaceTCName + "=0",
		"tc_direct":             "tc=0",
		"full_kmod":             "full=0",
		"tix_tcp_full_kmod":     "expfull=0",
		"secure_kudp":           "secure=0",
		"secure_tix_tcp_kernel": "secure-exp=0",
		"route_gso":             "route=0",
	} {
		if !strings.Contains(manifest.CaseMinGbps[key], wantSubstring) {
			t.Fatalf("manifest case_min_gbps[%s] missing %q:\n%s", key, wantSubstring, manifestPayload)
		}
	}
	for key, wantSubstring := range map[string]string{
		"userspace":             fastName + "=900",
		"userspace_tc":          userspaceTCName + "=900",
		"tc_direct":             "tc=3600",
		"full_kmod":             "full=3600",
		"tix_tcp_full_kmod":     "expfull=3600",
		"secure_kudp":           "secure=3600",
		"secure_tix_tcp_kernel": "secure-exp=3600",
		"route_gso":             "route=3600",
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
		userspaceTCName: "0.75",
		"tc":            "3",
		"full":          "3",
		"expfull":       "4",
		"secure":        "1.5",
		"secure-exp":    "1.5",
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
	requireRouteTCPHelperArgs := func(caseName string) {
		t.Helper()
		requireArgPair(caseName, "--require-module-param-min", "trustix_datapath_helpers.enable_features=768")
		requireArgPair(caseName, "--require-module-param-min", "trustix_datapath_helpers.features=768")
		requireArgPair(caseName, "--require-module-param-min", "trustix_datapath_helpers.safe_features=768")
		requireArgPair(caseName, "--require-module-param-min", "trustix_datapath_helpers.selftests=3")
		requireArgPair(caseName, "--require-module-param-max", "trustix_datapath_helpers.unsafe_features=0")
		requireArgPair(caseName, "--require-module-param-max", "trustix_datapath_helpers.selftest_failures=0")
	}
	for _, name := range []string{fastName, slowName, userspaceTCName, "tc", "full", "expfull", "secure", "secure-exp", "route"} {
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
	requireArgPair("expfull", "--require-transport-policy-min", "session_pool_size=16")
	requireEndpointArgs("expfull", "tix_tcp", "performance", "kernel_module", "plaintext")
	requireArgPair("expfull", "--require-transport-sessions-min", "16")
	requireArgPair("expfull", "--require-transport-session-stat", "transport=tix_tcp")
	requireArg("expfull", "--require-transport-session-endpoint-suffix=-tix-tcp")
	requireArgPair("expfull", "--require-transport-session-stat", "stats.encryption=plaintext")
	requireArgPair("expfull", "--require-transport-session-stat", "stats.extra.tix_tcp_full_plaintext_kernel_datapath=1")
	requireArgPair("expfull", "--require-transport-session-any-min", "stats.packets_sent=1")
	requireArgPair("expfull", "--require-status-min", "data_path.active_sessions=16")
	requireArgPair("expfull", "--require-status-max", "data_path.counters.session_dial_errors=0")
	requireArgPair("expfull", "--require-status-max", "data_path.counters.session_resets_sent=0")
	requireArgPair("expfull", "--require-status-max", "data_path.counters.session_resets_received=0")
	requireArgPair("expfull", "--require-status-max", "data_path.counters.stale_sessions_dropped=0")
	requireArgPair("expfull", "--require-datapath-stat", "tix_tcp.provider=kernel_datapath_full_plaintext")
	requireArgPair("expfull", "--require-datapath-stat", "tix_tcp.fast_path=true")
	requireArgPair("expfull", "--require-datapath-stat", "capture_forwarder_suppressed=true")
	requireArgPair("expfull", "--require-datapath-min", "tix_tcp.active_flows=16")
	requireArgPair("expfull", "--require-module-param-any-min", "trustix_datapath.tx_plaintext_packets=1")
	requireArgPair("expfull", "--require-module-param-any-min", "trustix_datapath.tx_plaintext_gso_segments=1")
	requireArgPair("expfull", "--require-module-param-any-min", "trustix_datapath.rx_worker_injected=1")
	requireArgPair("expfull", "--require-module-param-max", "trustix_datapath.tx_plaintext_gso_errors=0")
	requireArgPair("expfull", "--require-lsmod-module", "trustix_datapath")
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
	requireRouteTCPHelperArgs("secure")
	requireArgPair("secure", "--require-lsmod-module", "trustix_crypto")
	requireArgPair("secure", "--require-lsmod-module", "trustix_datapath_helpers")
	requireArgPair("secure-exp", "--require-transport-policy-min", "session_pool_size=8")
	requireEndpointArgs("secure-exp", "tix_tcp", "performance", "kernel_module", "secure")
	requireSecureEndpointPlacement("secure-exp", "kernel")
	requireArgPair("secure-exp", "--require-transport-sessions-min", "8")
	requireArgPair("secure-exp", "--require-transport-session-stat", "transport=tix_tcp")
	requireArg("secure-exp", "--require-transport-session-endpoint-suffix=-tix-tcp")
	requireArgPair("secure-exp", "--require-transport-session-stat", "stats.encryption=secure")
	requireArgPair("secure-exp", "--require-transport-session-stat", "stats.crypto_placement=kernel")
	requireArgPair("secure-exp", "--require-status-min", "data_path.active_sessions=8")
	requireArgPair("secure-exp", "--require-status-max", "data_path.counters.session_dial_errors=2")
	requireArgPair("secure-exp", "--require-datapath-stat", "tix_tcp.fast_path=true")
	requireArgPair("secure-exp", "--require-datapath-stat", "tix_tcp.kernel_crypto=true")
	requireArgPair("secure-exp", "--require-datapath-stat", "tix_tcp.requested_crypto=kernel")
	requireArgPair("secure-exp", "--require-datapath-stat", "tix_tcp.effective_crypto=kernel")
	requireArgPair("secure-exp", "--require-datapath-min", "tix_tcp.provider_stats.kernel_crypto_flow_map_entries=1")
	requireArgPair("secure-exp", "--require-datapath-min", "tix_tcp.provider_stats.kernel_crypto_flow_map_updates=1")
	requireArgPair("secure-exp", "--require-datapath-min", "tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_seal_calls=1")
	requireArgPair("secure-exp", "--require-datapath-min", "tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=1")
	requireArgPair("secure-exp", "--require-datapath-max", "tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_errors=0")
	requireArgPair("secure-exp", "--require-datapath-ratio-max", "tix_tcp.provider_stats.kernel_crypto_frame_replay_drops/tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=0.00002")
	requireArgPair("secure-exp", "--require-datapath-ratio-max", "tix_tcp.provider_stats.xdp_kernel_crypto_replay_drops/tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=0.00002")
	requireArgPair("secure-exp", "--require-datapath-ratio-max", "tix_tcp.provider_stats.xdp_kernel_crypto_replay_commit_errors/tix_tcp.provider_stats.kernel_crypto_module_direct_kfunc_open_calls=0.00002")
	requireArgPair("secure-exp", "--require-module-param-max", "trustix_crypto.direct_kfunc_errors=0")
	requireRouteTCPHelperArgs("secure-exp")
	requireArgPair("secure-exp", "--require-lsmod-module", "trustix_crypto")
	requireArgPair("secure-exp", "--require-lsmod-module", "trustix_datapath_helpers")
	requireArgPair("route", "--require-transport-policy-min", "session_pool_size=8")
	requireEndpointArgs("route", "tix_tcp", "performance", "kernel_module", "plaintext")
	requireArgPair("route", "--require-transport-sessions-min", "8")
	requireArgPair("route", "--require-transport-session-stat", "transport=tix_tcp")
	requireArg("route", "--require-transport-session-endpoint-suffix=-tix-tcp")
	requireArgPair("route", "--require-transport-session-stat", "stats.encryption=plaintext")
	requireArgPair("route", "--require-status-min", "data_path.active_sessions=8")
	requireArgPair("route", "--require-status-max", "data_path.counters.session_dial_errors=2")
	requireRouteTCPHelperArgs("route")
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
		"tix_tcp\tsecure\tperformance\tkernel_module\tkernel\tcross_host\tsecure_tix_tcp_kernel\t1.5\t3600\tselected secure TIX-TCP kernel gate",
		"tix_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\troute_gso\t2.5\t3600\tselected route-GSO gate",
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
		"  printf 'SECURE_TIX_TCP_KERNEL_CASE_MIN_GBPS=%s\\n' \"$TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASE_MIN_GBPS\"",
		"  printf 'SECURE_TIX_TCP_KERNEL_CASE_MIN_SECONDS=%s\\n' \"$TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASE_MIN_SECONDS\"",
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
		"udp-secure-stable-userspace-userspace-userspace=1.5",
		"tcp-secure-stable-userspace-userspace-userspace=0.75",
		"udp-secure-stable-userspace-userspace-userspace=30",
		"tcp-secure-stable-userspace-userspace-userspace=30",
		"gre-plaintext-performance-tc_xdp-userspace-userspace_tc=4",
		"gre-plaintext-performance-tc_xdp-userspace-userspace_tc=30",
		"tix_tcp-secure-performance-kernel_module-kernel-secure_tix_tcp_kernel=1.5",
		"tix_tcp-secure-performance-kernel_module-kernel-secure_tix_tcp_kernel=3600",
		"tix_tcp-plaintext-performance-kernel_module-userspace-route_gso=2.5",
		"tix_tcp-plaintext-performance-kernel_module-userspace-route_gso=3600",
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
		`{"schema":"trustix-cross-host-production-gate-manifest-v1","production_gate":{"path":"production-gate.sh","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":123},"verifier":{"path":"verifier.py","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":456},"cases":{"userspace":"${case_token}"},"case_min_gbps":{"userspace":"udp-secure-stable-userspace-userspace-userspace=1.5"},"case_min_seconds":{"userspace":"udp-secure-stable-userspace-userspace-userspace=3600"}}`,
		"JSON",
		"cat > \"$TRUSTIX_CROSS_HOST_GATE_SUMMARY_DIR/userspace-udp-secure.jsonl\" <<JSON",
		`{"case":"udp-secure-stable-userspace-userspace-userspace","path":"${case_path}","status":"pass","min_gbps_required":1.5,"min_seconds_required":3600,"seconds_slop":0,"min_sent_gbps":1.9,"min_received_gbps":1.8,"min_required_received_gbps":1.7,"min_seconds":3600.1,"min_iperf_intervals_required":600,"min_iperf_interval_gbps_ratio_required":0.25,"iperf_json_count":2,"iperf_direction_count":2,"iperf_pair_directions":["a-to-b","b-to-a"],"iperf":[{"direction":"forward","sent_gbps":1.9,"received_gbps":1.8,"seconds":3600.1,"intervals":600,"interval_min_gbps":1.0,"sent_required":true,"received_required":true},{"direction":"forward","sent_gbps":1.8,"received_gbps":1.7,"seconds":3600.1,"intervals":600,"interval_min_gbps":1.0,"sent_required":true,"received_required":true}],"result_markers":["pass"],"binary_identities":[{"source":"collect/a/binary-identity.json","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},{"source":"collect/b/binary-identity.json","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"build_identities":[{"source":"collect/a/status.json","version":"trustix-test","commit":"0123456789ab","built_at":"2026-06-25T00:00:00Z","go_version":"go1.25.0","goos":"linux","goarch":"amd64","strong":true},{"source":"collect/b/status.json","version":"trustix-test","commit":"0123456789ab","built_at":"2026-06-25T00:00:00Z","go_version":"go1.25.0","goos":"linux","goarch":"amd64","strong":true}],"lsmod_artifacts":[{"source":"collect/a/lsmod.txt","node":"a","modules":[]},{"source":"collect/b/lsmod.txt","node":"b","modules":[]}],"lsmod_nodes":["a","b"],"lan_state_artifacts":[{"source":"collect/a/lan-state.txt","node":"a","interface":"tix-lan-a","tx_queue_len":1000},{"source":"collect/b/lan-state.txt","node":"b","interface":"tix-lan-b","tx_queue_len":1000}],"lan_state_nodes":["a","b"],"run_timing":[{"source":"run-timing.json","iperf_mode":"forward","iperf_directions":"both","iperf_seconds_requested":3600,"start_epoch":1000,"end_epoch":4600.1,"elapsed_seconds":3600.1}],"uname_artifacts":[{"node":"a","phase":"before","kernel_release":"6.12.90+deb13.1-amd64"},{"node":"a","phase":"after","kernel_release":"6.12.90+deb13.1-amd64"},{"node":"b","phase":"before","kernel_release":"6.12.90+deb13.1-amd64"},{"node":"b","phase":"after","kernel_release":"6.12.90+deb13.1-amd64"}],"os_release_artifacts":[{"node":"a","phase":"before","identity":"debian:13"},{"node":"a","phase":"after","identity":"debian:13"},{"node":"b","phase":"before","identity":"debian:13"},{"node":"b","phase":"after","identity":"debian:13"}],"boot_ids":[{"node":"a","phase":"before","boot_id":"boot-a"},{"node":"a","phase":"after","boot_id":"boot-a"},{"node":"b","phase":"before","boot_id":"boot-b"},{"node":"b","phase":"after","boot_id":"boot-b"}],"errors":[],"log_findings":[],"kernel_log_artifacts":["collect/a/kernel.log","collect/b/kernel.log"],"kernel_log_nodes":["a","b"],"kernel_log_rejected_artifacts":[],"pstore_artifacts":["collect/a/pstore.txt","collect/b/pstore.txt"],"pstore_nodes":["a","b"],"pstore_rejected_artifacts":[]}`,
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
	if len(fields) != 25 {
		t.Fatalf("expected 25 evidence fields, got %d:\n%s", len(fields), payload)
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
		17: strings.Repeat("c", 64),
		18: "trustix-test",
		19: "0123456789ab",
		20: "2026-06-25T00:00:00Z",
		21: "go1.25.0",
		22: sha256File(t, runner),
		23: sha256File(t, "linux-cross-host-transport-matrix.sh"),
		24: sha256File(t, "production-evidence-from-gate-summary.py"),
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
		"gate_class=\"$(gate_family_class \"$gate_family\")\"",
		"local base=\"${token}-${encryption}-${profile}-${datapath}-${placement}-${gate_class}\"",
		"full_kmod|dd_full_kmod) printf 'dd-fullkmod\\n'",
		"owdeb_full_kmod) printf 'owdeb-fullkmod\\n'",
		"tix_tcp_full_kmod|dd_tix_tcp_full_kmod) printf 'tix-tcp-full-kmod\\n'",
		"owdeb_tix_tcp_full_kmod) printf 'owdeb-tix-tcp-full-kmod\\n'",
		"secure_kudp|dd_secure_kudp) printf 'secure-kudp\\n'",
		"owdeb_secure_kudp) printf 'owdeb-secure-kudp\\n'",
		"secure_tix_tcp_kernel|dd_secure_tix_tcp_kernel|owdeb_secure_tix_tcp_kernel) printf 'secure-tix-tcp-kernel\\n'",
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
		"append_case_token tix_tcp_full_kmod_case_min_gbps",
		"append_case_token secure_kudp_case_min_gbps",
		"append_case_token secure_tix_tcp_kernel_case_min_gbps",
		"append_case_token route_gso_case_min_gbps",
		"append_case_token full_kmod_case_min_seconds",
		"append_case_token tix_tcp_full_kmod_case_min_seconds",
		"append_case_token secure_kudp_case_min_seconds",
		"append_case_token secure_tix_tcp_kernel_case_min_seconds",
		"append_case_token route_gso_case_min_seconds",
		"full_kmod|dd_full_kmod|owdeb_full_kmod) printf 'full_kmod\\n'",
		"tix_tcp_full_kmod|dd_tix_tcp_full_kmod|owdeb_tix_tcp_full_kmod) printf 'tix_tcp_full_kmod\\n'",
		"secure_kudp|dd_secure_kudp|owdeb_secure_kudp) printf 'secure_kudp\\n'",
		"secure_tix_tcp_kernel|dd_secure_tix_tcp_kernel|owdeb_secure_tix_tcp_kernel) printf 'secure_tix_tcp_kernel\\n'",
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
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_CASES=${tix_tcp_full_kmod_cases}",
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_CASE_MIN_GBPS=${tix_tcp_full_kmod_case_min_gbps}",
		"TRUSTIX_CROSS_HOST_TIX_TCP_FULL_KMOD_CASE_MIN_SECONDS=${tix_tcp_full_kmod_case_min_seconds}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES=${secure_kudp_cases}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_GBPS=${secure_kudp_case_min_gbps}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASE_MIN_SECONDS=${secure_kudp_case_min_seconds}",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASES=${secure_tix_tcp_kernel_cases}",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASE_MIN_GBPS=${secure_tix_tcp_kernel_case_min_gbps}",
		"TRUSTIX_CROSS_HOST_SECURE_TIX_TCP_KERNEL_CASE_MIN_SECONDS=${secure_tix_tcp_kernel_case_min_seconds}",
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
		"tix_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\troute_gso\t2.5\t30\tselected route-GSO gate",
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
		"udp-secure-stable-userspace-userspace-userspace":                 "data_path.counters.session_dial_errors=0",
		"tix_tcp-plaintext-performance-kernel_module-userspace-route_gso": "data_path.counters.session_dial_errors=2",
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
			row:  "tix_tcp\tsecure\tperformance\ttc_xdp\tkernel\tcross_host\tsecure_kudp\t1.5\t3600\tsecure kernel TCP must not reuse secure-kUDP gate",
			want: "gate_family=secure_kudp requires transport=kernel_udp; got transport=tix_tcp",
		},
		{
			name: "route_gso_wrong_transport",
			row:  "udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\troute_gso\t2.5\t3600\tUDP full-kmod must not reuse route-GSO gate",
			want: "gate_family=route_gso requires transport=tix_tcp; got transport=udp",
		},
		{
			name: "secure_tix_tcp_kernel_wrong_datapath",
			row:  "tix_tcp\tsecure\tperformance\ttc_xdp\tkernel\tcross_host\tsecure_tix_tcp_kernel\t1.5\t3600\tsecure TIX-TCP kernel crypto must use kernel-module datapath",
			want: "gate_family=secure_tix_tcp_kernel requires datapath=kernel_module; got datapath=tc_xdp",
		},
		{
			name: "full_kmod_wrong_crypto",
			row:  "udp\tsecure\tperformance\tkernel_module\tuserspace\tcross_host\tfull_kmod\t3\t3600\tfull-kmod production gate is plaintext-only",
			want: "gate_family=full_kmod requires encryption=plaintext; got encryption=secure",
		},
		{
			name: "tix_tcp_full_kmod_wrong_transport",
			row:  "udp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\ttix_tcp_full_kmod\t3\t3600\tTIX-TCP full-kmod must not reuse UDP full-kmod gate",
			want: "gate_family=tix_tcp_full_kmod requires transport=tix_tcp; got transport=udp",
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
	case "tix_tcp_full_kmod", "dd_tix_tcp_full_kmod":
		return "tix-tcp-full-kmod"
	case "owdeb_tix_tcp_full_kmod":
		return "owdeb-tix-tcp-full-kmod"
	case "secure_kudp", "dd_secure_kudp":
		return "secure-kudp"
	case "owdeb_secure_kudp":
		return "owdeb-secure-kudp"
	case "secure_tix_tcp_kernel", "dd_secure_tix_tcp_kernel", "owdeb_secure_tix_tcp_kernel":
		return "secure-tix-tcp-kernel"
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

func productionDefaultEndpointTransport(row productionTransportDefault) string {
	if row.Transport == "kernel_udp" {
		return "udp"
	}
	return row.Transport
}

func productionDefaultNeedsKernelTransport(row productionTransportDefault) bool {
	switch row.Transport {
	case "gre", "ipip", "vxlan":
		return true
	}
	switch row.GateFamily {
	case "full_kmod", "dd_full_kmod", "owdeb_full_kmod",
		"tix_tcp_full_kmod", "dd_tix_tcp_full_kmod", "owdeb_tix_tcp_full_kmod",
		"secure_kudp", "dd_secure_kudp", "owdeb_secure_kudp",
		"secure_tix_tcp_kernel", "dd_secure_tix_tcp_kernel", "owdeb_secure_tix_tcp_kernel",
		"route_gso", "dd_route_gso", "owdeb_route_gso",
		"tc_direct":
		return true
	default:
		return false
	}
}

func productionDefaultCapabilityProfile(row productionTransportDefault) string {
	switch row.GateFamily {
	case "full_kmod", "dd_full_kmod", "owdeb_full_kmod",
		"tix_tcp_full_kmod", "dd_tix_tcp_full_kmod", "owdeb_tix_tcp_full_kmod":
		return "full_plaintext"
	case "userspace", "userspace_tc", "tc_direct":
		return "disabled"
	default:
		return "performance"
	}
}

func productionDefaultModuleSnippets(row productionTransportDefault) []string {
	base := []string{"capability_profile: " + productionDefaultCapabilityProfile(row)}
	switch row.GateFamily {
	case "full_kmod", "dd_full_kmod", "owdeb_full_kmod",
		"tix_tcp_full_kmod", "dd_tix_tcp_full_kmod", "owdeb_tix_tcp_full_kmod":
		return append(base,
			"trustix_crypto:\n    mode: disabled",
			"trustix_datapath:\n    mode: required",
			"trustix_datapath_helpers:\n    mode: disabled",
		)
	case "secure_kudp", "dd_secure_kudp", "owdeb_secure_kudp",
		"secure_tix_tcp_kernel", "dd_secure_tix_tcp_kernel", "owdeb_secure_tix_tcp_kernel":
		return append(base,
			"trustix_crypto:\n    mode: required",
			"trustix_datapath:\n    mode: disabled",
			"trustix_datapath_helpers:\n    mode: required",
		)
	case "route_gso", "dd_route_gso", "owdeb_route_gso":
		return append(base,
			"trustix_crypto:\n    mode: disabled",
			"trustix_datapath:\n    mode: disabled",
			"trustix_datapath_helpers:\n    mode: required",
		)
	default:
		return append(base,
			"trustix_crypto:\n    mode: disabled",
			"trustix_datapath:\n    mode: disabled",
			"trustix_datapath_helpers:\n    mode: disabled",
		)
	}
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
		productionGateFamilyClass(row.GateFamily),
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
		if row.GateFamily == "owdeb_secure_tix_tcp_kernel" {
			t.Fatalf("OpenWrt-Debian secure TIX-TCP kernel path was promoted without a passing OpenWrt route-GSO/kfunc gate:\n%s", payload)
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
		"tix_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\towdeb_route_gso\t2.5\t900\texplicit OpenWrt-Debian route-GSO validation input",
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
		row.Case != "tix_tcp-plaintext-performance-kernel_module-userspace-route_gso-owdeb" {
		t.Fatalf("unexpected owdeb route-GSO dry-run row: %+v\n%s", row, payload)
	}
}

func TestCrossHostTransportMatrixDisambiguatesTIXTCPFullKmodAndRouteGSO(t *testing.T) {
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
		"tix_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\ttix_tcp_full_kmod\t4\t30\texplicit TIX-TCP full-kmod validation input",
		"tix_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\troute_gso\t2.5\t30\texplicit route-GSO validation input",
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
		t.Fatalf("dry-run explicit TIX-TCP matrix failed: %v\n%s", err, output)
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
			t.Fatalf("decode summary row %q: %v", line, err)
		}
		got[row.GateFamily] = row
	}
	expFull := got["tix_tcp_full_kmod"]
	routeGSO := got["route_gso"]
	if expFull.Case != "tix_tcp-plaintext-performance-kernel_module-userspace-tix_tcp_full_kmod" {
		t.Fatalf("unexpected tix_tcp_full_kmod case name: %+v\n%s", expFull, payload)
	}
	if routeGSO.Case != "tix_tcp-plaintext-performance-kernel_module-userspace-route_gso" {
		t.Fatalf("unexpected route_gso case name: %+v\n%s", routeGSO, payload)
	}
	if expFull.Case == routeGSO.Case {
		t.Fatalf("tix_tcp_full_kmod and route_gso share a case directory:\n%s", payload)
	}
}

func TestCrossHostTransportMatrixCanRepresentTIXTCPFullKmodWhenExplicitlyValidated(t *testing.T) {
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
		"tix_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\ttix_tcp_full_kmod\t3\t900\texplicit TIX-TCP full-kmod validation input",
		"tix_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\towdeb_tix_tcp_full_kmod\t3\t900\texplicit OpenWrt-Debian TIX-TCP full-kmod validation input",
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
		t.Fatalf("dry-run explicit TIX-TCP full-kmod matrix failed: %v\n%s", err, output)
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
			t.Fatalf("decode summary row %q: %v", line, err)
		}
		got[row.GateFamily] = row
	}
	tests := map[string]string{
		"tix_tcp_full_kmod":       "tix-tcp-full-kmod",
		"owdeb_tix_tcp_full_kmod": "owdeb-tix-tcp-full-kmod",
	}
	wantCases := map[string]string{
		"tix_tcp_full_kmod":       "tix_tcp-plaintext-performance-kernel_module-userspace-tix_tcp_full_kmod",
		"owdeb_tix_tcp_full_kmod": "tix_tcp-plaintext-performance-kernel_module-userspace-tix_tcp_full_kmod-owdeb",
	}
	for family, runner := range tests {
		row, ok := got[family]
		if !ok {
			t.Fatalf("summary missing %s:\n%s", family, payload)
		}
		if row.Transport != "tix_tcp" ||
			row.RunnerCase != runner ||
			row.Datapath != "kernel_module" ||
			row.CryptoPlacement != "userspace" {
			t.Fatalf("unexpected %s dry-run row: %+v\n%s", family, row, payload)
		}
		if row.Case != wantCases[family] {
			t.Fatalf("unexpected %s case name: got %q want %q\n%s", family, row.Case, wantCases[family], payload)
		}
	}
}

func TestProductionDefaultsDoNotPromoteOpenWrtRouteGSOWithoutRuntimeEvidence(t *testing.T) {
	rows := loadProductionTransportDefaults(t)
	for _, row := range rows {
		switch row.GateFamily {
		case "owdeb_secure_kudp", "owdeb_secure_tix_tcp_kernel", "owdeb_route_gso":
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
		"dry_run_config=\"${TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG:-0}\"",
		"data_a_port=\"${TRUSTIX_CROSS_HOST_DATA_A_PORT:-}\"",
		"data_b_port=\"${TRUSTIX_CROSS_HOST_DATA_B_PORT:-}\"",
		"default_data_port",
		"node_value \"$node\" 13000 13001",
		"TRUSTIX_CROSS_HOST_IPERF_SECONDS:-3600",
		"preserve_on_failure=\"${TRUSTIX_CROSS_HOST_PRESERVE_ON_FAILURE:-0}\"",
		"iperf_parallel_explicit=\"${TRUSTIX_CROSS_HOST_IPERF_PARALLEL+x}\"",
		"health_port=\"${TRUSTIX_CROSS_HOST_HEALTH_PORT:-}\"",
		"TRUSTIX_CROSS_HOST_IPERF_MODE:-forward",
		"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS:-both",
		"TRUSTIX_CROSS_HOST_MIXED_MIN_GBPS:-0",
		"TRUSTIX_CROSS_HOST_MIXED_UDP_MIN_GBPS:-$mixed_min_gbps",
		"TRUSTIX_CROSS_HOST_MIXED_TIX_TCP_MIN_GBPS:-$mixed_min_gbps",
		"daemon_ready_sleep=\"${TRUSTIX_CROSS_HOST_READY_SLEEP:-1}\"",
		"iperf_parallel=\"${TRUSTIX_CROSS_HOST_IPERF_PARALLEL:-8}\"",
		"iptunnel_iperf_parallel=\"${TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL:-4}\"",
		"transport_snapshot_delay=\"${TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY:-5}\"",
		"session_pool_size_explicit=\"${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE+x}\"",
		"session_pool_size=\"${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE:-$iperf_parallel}\"",
		"session_pool_heartbeat_interval=\"${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_INTERVAL:-10s}\"",
		"session_pool_heartbeat_timeout=\"${TRUSTIX_CROSS_HOST_SESSION_POOL_HEARTBEAT_TIMEOUT:-10s}\"",
		"capture_forwarder_workers=\"${TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_WORKERS:-auto}\"",
		"capture_forwarder_buffer=\"${TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BUFFER:-65536}\"",
		"TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_WORKERS must be auto or a positive integer",
		"TRUSTIX_CROSS_HOST_CAPTURE_FORWARDER_BATCH must be <= 4096",
		"printf 'TRUSTIX_CAPTURE_FORWARDER_WORKERS=%s\\n' \"$capture_forwarder_workers\"",
		"printf 'TRUSTIX_CAPTURE_FORWARDER_BUFFER=%s\\n' \"$capture_forwarder_buffer\"",
		"session_pool:",
		"size: ${session_pool_size}",
		"strategy: ${session_pool_strategy}",
		"warmup: ${session_pool_warmup}",
		"heartbeat:",
		"mode: ${session_pool_heartbeat_mode}",
		"interval: ${session_pool_heartbeat_interval}",
		"timeout: ${session_pool_heartbeat_timeout}",
		"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS must be both, a2b, or b2a",
		"TRUSTIX_CROSS_HOST_HEALTH_PORT must differ from TRUSTIX_CROSS_HOST_IPERF_PORT",
		"TRUSTIX_CROSS_HOST_IPTUNNEL_IPERF_PARALLEL must be >= 1",
		"case \"$iperf_mode\" in bidir|forward|reverse)",
		"apply_case_runtime_defaults",
		"tix-tcp-full-kmod|tix_tcp_full_kmod|tix-tcp-full-kmod|tix_tcp_full_kmod|dd-tix-tcp-full-kmod|dd_tix_tcp_full_kmod|owdeb-tix-tcp-full-kmod|owdeb_tix_tcp_full_kmod)",
		"iperf_parallel=16",
		"truthy \"$dry_run_config\"",
		"acquire_pair_lock || die \"another soak runner owns this VM pair\"",
		"release_pair_lock",
		"trustix-cross-host-pair-${pair_key}.lock",
		"write_config a \"$workdir/config-a.yaml\"",
		"write_config b \"$workdir/config-b.yaml\"",
		"if [ -n \\\"\\$secondary_host_addr\\\" ]; then",
		"addr add \\\"\\$secondary_host_addr\\\" dev",
		"daemon_env >\"$workdir/daemon-env.txt\"",
		"dry_run_config",
		"TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE must be >= 1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY must be >= 0",
		"TRUSTIX_CROSS_HOST_SESSION_POOL_STRATEGY must be flow, five_tuple, 5tuple, packet, or round_robin",
		"ssh -n \"${ssh_opts[@]}\" \"$dest\" \"bash -c $(remote_quote \"$script\")\"",
		"iperf_artifact_suffix",
		"assert_iperf_min_gbps",
		"mixed-throughput-gates.jsonl",
		"route_a_if=\"$(detect_underlay_if a \"$underlay_b_ip\" | tail -n 1 || true)\"",
		"configured underlay interface ${underlay_a_if} does not match route to peer",
		"using route interface",
		"dd-fullkmod|owdeb-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod",
		"tix-tcp-full-kmod|tix_tcp_full_kmod|tix-tcp-full-kmod|tix_tcp_full_kmod|dd-tix-tcp-full-kmod|dd_tix_tcp_full_kmod|owdeb-tix-tcp-full-kmod|owdeb_tix_tcp_full_kmod",
		"dd-secure-kudp|owdeb-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel",
		"dd-routegso|owdeb-routegso|route-gso|tix-tcp-route-gso|tix_tcp_route_gso",
		"ow-tc-direct|tc-direct) printf 'udp\\n'",
		"tix-tcp-tc-direct|tix_tcp_tc_direct) printf 'tix_tcp\\n'",
		"ow-tc-direct|tc-direct|tix-tcp-tc-direct|tix_tcp_tc_direct",
		"userspace-*-secure|userspace-*-plaintext|crosshost-userspace-*-secure|crosshost-userspace-*-plaintext",
		"tc-*-secure|tc-*-plaintext|crosshost-tc-*-secure|crosshost-tc-*-plaintext",
		"supported_case_transport",
		"case_transport_profile",
		"case_fast_path",
		"case_encryption",
		"case_crypto_placement",
		"case_transport_datapath",
		"case_kernel_transport_mode",
		"case_is_iptunnel_transport",
		"userspace) printf '\\n' ;;",
		"if case_uses_tc_direct_fast_path; then",
		"*) printf 'require_kernel\\n' ;;",
		"case_uses_tc_direct_fast_path",
		"case_tc_requested_but_falls_back_to_userspace",
		"has no safe TC direct fast path with this configuration; using userspace datapath",
		"route_gso|secure_tix_tcp_kernel)",
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
		"modprobe veth",
		"collect_boot_id()",
		"boot-id-${phase}.txt",
		"collect_boot_id a before",
		"collect_boot_id b before",
		"collect_boot_id a after",
		"collect_boot_id b after",
		"collect_host_state()",
		"${prefix}-host-state.txt",
		"cpu_count=\\$(nproc",
		"net_driver[%s]=%s",
		"collect_host_state a",
		"collect_host_state b",
		"TRUSTIX_TIX_TCP_RAW_FALLBACK=1",
		"case_has_endpoint_transport tix_tcp",
		"rx_worker_tix_tcp=1",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_TIX_TCP=%s",
		"TRUSTIX_TIX_TCP_ALLOW_MIXED_TCP_FAST_PATH=1",
		"require explicit tix_tcp_full_kmod gate evidence before treating this mix as production",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER_EXPERIMENTS=1",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_RX_WORKER_EXPERIMENTS=1",
		"TRUSTIX_CROSS_HOST_OPENWRT_RX_SINGLE_COALESCE",
		"TRUSTIX_KERNEL_DATAPATH_OPENWRT_RX_SINGLE_COALESCE=%s",
		"daemon_env_exports",
		"env ${env_exports} $(remote_quote \"$trustixd\") -config",
		"prepare-cleanup.log",
		"yaml_single_quote",
		"endpoint_security_yaml \"    \" \"$encryption\"",
		"crypto_placement: ${crypto_placement}",
		"kernel_mode=\"$(case_kernel_transport_mode)\"",
		"if [[ -n \"$kernel_mode\" ]]; then",
		"  kernel_transport:",
		"    mode: ${kernel_mode}",
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
		"TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=1",
		"TRUSTIX_TIX_TCP_ROUTE_GSO=0",
		"TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=0",
		"plaintext_tc_direct_daemon_env",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT=1",
		"TRUSTIX_KERNEL_UDP_TC_ONLY=1",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY=1",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1",
		"unload_on_exit: true",
		"-cleanup-dataplane",
		"rmmod trustix_datapath",
		"rmmod trustix_datapath_helpers",
		"printf 'pass\\n' >\"$workdir/${case_name}.result\"",
		"collect_binary_identity a",
		"version_output=\\$(",
		"collect_kernel_logs a",
		"accept_iperf_server_summary_artifact()",
		"server-control-error-${label}.raw.json",
		"iperf3-server-${label}.accepted-control-error.txt",
		"accepted_server_summary=1",
		"reason=client_missing_server_results_only",
		"client missed server results; accepting server-side summary artifact",
		"if command -v journalctl >/dev/null 2>&1; then",
		"tmp=\\\"\\${dir}/.\\${prefix}-kernel.log.tmp\\\"",
		"since=$(remote_quote \"$since\")",
		"journal_since=\\\"\\$since\\\"",
		"journalctl -k -b --since \\\"\\$journal_since\\\" --no-pager -o short-iso >\\\"\\$tmp\\\"",
		"if command -v dmesg >/dev/null 2>&1; then",
		"tmp=\\\"\\${dir}/.\\${prefix}-dmesg.log.tmp\\\"",
		"mark_kernel_log_start",
		".kernel-log-start-uptime",
		"dmesg_since=\\\"\\$since\\\"",
		"dmesg --since \\\"\\$dmesg_since\\\" >\\\"\\$tmp\\\"",
		"dmesg 2>/dev/null | awk -v start=\\\"\\$baseline\\\"",
		"no dmesg entries since uptime",
		"elif dmesg -T >\\\"\\$tmp\\\"",
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
		"route_gso|secure_kudp|secure_tix_tcp_kernel)",
		"run_tcp_health_checks",
		"run_tcp_health_direction",
		"proc_tcp_listening /proc/net/tcp",
		"proc_tcp_listening /proc/net/tcp6",
		"listener wait failed for tcp port",
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

func TestCrossHostSoakRunnerDryRunPinsKernelTransportConfig(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}

	for _, row := range loadProductionTransportDefaults(t) {
		if row.ValidationScope != "cross_host" {
			continue
		}
		row := row
		t.Run(productionDefaultEvidenceKey(row), func(t *testing.T) {
			caseName := productionDefaultRunnerCase(row)
			endpointTransport := productionDefaultEndpointTransport(row)
			workdir := filepath.Join(t.TempDir(), strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-").Replace(caseName))
			env := append(os.Environ(),
				"TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG=1",
				"TRUSTIX_CROSS_HOST_CASE="+caseName,
				"TRUSTIX_CROSS_HOST_TRANSPORT="+endpointTransport,
				"TRUSTIX_CROSS_HOST_ENCRYPTION="+row.Encryption,
				"TRUSTIX_CROSS_HOST_PROFILE="+row.Profile,
				"TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH="+row.Datapath,
				"TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT="+row.CryptoPlacement,
				"TRUSTIX_CROSS_HOST_WORKDIR="+workdir,
				"TRUSTIX_CROSS_HOST_A_UNDERLAY_IP=198.51.100.10",
				"TRUSTIX_CROSS_HOST_B_UNDERLAY_IP=198.51.100.11",
				"TRUSTIX_CROSS_HOST_A_UNDERLAY_IF=eth0",
				"TRUSTIX_CROSS_HOST_B_UNDERLAY_IF=eth0",
			)
			cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
			cmd.Dir = "."
			cmd.Env = env
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("dry-run config failed: %v\n%s", err, output)
			}
			payload, err := os.ReadFile(filepath.Join(workdir, "config-a.yaml"))
			if err != nil {
				t.Fatalf("read dry-run config: %v", err)
			}
			text := string(payload)
			want := []string{
				"transport: " + endpointTransport,
				"profile: " + row.Profile,
				"datapath: " + row.Datapath,
				"encryption: " + row.Encryption,
				"crypto_placement: " + row.CryptoPlacement,
			}
			want = append(want, productionDefaultModuleSnippets(row)...)
			if productionDefaultNeedsKernelTransport(row) {
				want = append(want, "kernel_transport:\n    mode: require_kernel")
			}
			for _, want := range want {
				if !strings.Contains(text, want) {
					t.Fatalf("dry-run config missing %q:\n%s", want, text)
				}
			}
			if !productionDefaultNeedsKernelTransport(row) && strings.Contains(text, "kernel_transport:") {
				t.Fatalf("dry-run config contains unwanted kernel_transport:\n%s", text)
			}
		})
	}
}

func TestCrossHostSoakRunnerDryRunPinsPlaintextTCDirectTransport(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}

	tests := []struct {
		name      string
		caseName  string
		transport string
		want      []string
		forbid    []string
	}{
		{
			name:      "kernel-udp",
			caseName:  "tc-direct",
			transport: "udp",
			want: []string{
				"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT=1",
				"TRUSTIX_KERNEL_UDP_TC_ONLY=1",
				"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY=1",
			},
			forbid: []string{
				"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY=1",
				"TRUSTIX_TIX_TCP_TC_TX_DIRECT=1",
			},
		},
		{
			name:      "tix-tcp",
			caseName:  "tix-tcp-tc-direct",
			transport: "tix_tcp",
			want: []string{
				"TRUSTIX_TIX_TCP_TC_TX_DIRECT=1",
				"TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY=1",
				"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY=1",
			},
			forbid: []string{
				"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY=1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workdir := filepath.Join(t.TempDir(), tt.name)
			cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
			cmd.Dir = "."
			cmd.Env = append(os.Environ(),
				"TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG=1",
				"TRUSTIX_CROSS_HOST_CASE="+tt.caseName,
				"TRUSTIX_CROSS_HOST_TRANSPORT="+tt.transport,
				"TRUSTIX_CROSS_HOST_ENCRYPTION=plaintext",
				"TRUSTIX_CROSS_HOST_PROFILE=performance",
				"TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH=tc_xdp",
				"TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT=userspace",
				"TRUSTIX_CROSS_HOST_WORKDIR="+workdir,
				"TRUSTIX_CROSS_HOST_A_UNDERLAY_IP=198.51.100.10",
				"TRUSTIX_CROSS_HOST_B_UNDERLAY_IP=198.51.100.11",
				"TRUSTIX_CROSS_HOST_A_UNDERLAY_IF=eth0",
				"TRUSTIX_CROSS_HOST_B_UNDERLAY_IF=eth0",
			)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("dry-run config failed: %v\n%s", err, output)
			}
			payload, err := os.ReadFile(filepath.Join(workdir, "daemon-env.txt"))
			if err != nil {
				t.Fatalf("read dry-run daemon environment: %v", err)
			}
			text := string(payload)
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Fatalf("dry-run daemon environment missing %q:\n%s", want, text)
				}
			}
			for _, forbidden := range tt.forbid {
				if strings.Contains(text, forbidden) {
					t.Fatalf("dry-run daemon environment contains forbidden %q:\n%s", forbidden, text)
				}
			}
		})
	}
}

func TestCrossHostSoakRunnerRejectsConcurrentVMPairUse(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}

	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"trustixd", "trustixctl", "trustix-ca"} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	baseEnv := append(os.Environ(),
		"TRUSTIX_CROSS_HOST_A=local",
		"TRUSTIX_CROSS_HOST_B=local",
		"TRUSTIX_CROSS_HOST_A_UNDERLAY_IP=198.51.100.10",
		"TRUSTIX_CROSS_HOST_B_UNDERLAY_IP=198.51.100.11",
		"TRUSTIX_CROSS_HOST_A_UNDERLAY_IF=eth0",
		"TRUSTIX_CROSS_HOST_B_UNDERLAY_IF=eth0",
		"TRUSTIX_CROSS_HOST_BIN_DIR="+binDir,
		"TRUSTIX_CROSS_HOST_PAIR_LOCK_ROOT="+filepath.Join(root, "locks"),
		"TRUSTIX_CROSS_HOST_PAIR_LOCK_HOLD_SECONDS=30",
	)
	first := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	first.Dir = "."
	first.Env = append(baseEnv, "TRUSTIX_CROSS_HOST_WORKDIR="+filepath.Join(root, "first"))
	firstOutputPath := filepath.Join(root, "first.log")
	firstOutput, err := os.Create(firstOutputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer firstOutput.Close()
	first.Stdout = firstOutput
	first.Stderr = firstOutput
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if first.Process != nil {
			_ = first.Process.Kill()
		}
	})

	lockRoot := filepath.Join(root, "locks")
	deadline := time.Now().Add(3 * time.Second)
	lockReady := false
	for time.Now().Before(deadline) {
		entries, readErr := os.ReadDir(lockRoot)
		if readErr == nil && len(entries) == 1 && entries[0].IsDir() {
			lockReady = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !lockReady {
		_ = firstOutput.Sync()
		payload, _ := os.ReadFile(firstOutputPath)
		t.Fatalf("first runner did not acquire lock:\n%s", payload)
	}

	second := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	second.Dir = "."
	second.Env = append(baseEnv, "TRUSTIX_CROSS_HOST_WORKDIR="+filepath.Join(root, "second"))
	output, err := second.CombinedOutput()
	if err == nil {
		t.Fatalf("second runner unexpectedly acquired the same VM pair lock:\n%s", output)
	}
	if !strings.Contains(string(output), "another soak runner owns this VM pair") {
		t.Fatalf("second runner failure did not identify VM pair contention:\n%s", output)
	}

	if err := first.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err == nil {
		t.Fatal("killed first runner unexpectedly exited successfully")
	}
}

func TestCrossHostSoakRunnerCleanupTrapReturnsCleanly(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}

	scriptPath, err := filepath.Abs("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	code := fmt.Sprintf(`
set -Eeuo pipefail
source %q
collect_all() { :; }
stop_daemon() { :; }
cleanup_node() { :; }
workdir=$(mktemp -d)
pair_lock_dir="$workdir/pair.lock"
mkdir "$pair_lock_dir"
printf '%%s\n' "$$" >"$pair_lock_dir/owner.pid"
pair_lock_acquired=1
keep_local=1
preserve_on_failure=0
cleanup_all
test "$pair_lock_acquired" = 0
test ! -e "$pair_lock_dir"
`, scriptPath)
	cmd := exec.Command(bash, "-c", code)
	cmd.Env = append(os.Environ(), "TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cleanup trap returned a shell parse/runtime error: %v\n%s", err, output)
	}
}
