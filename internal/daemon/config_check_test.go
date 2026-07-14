package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCheckConfigValidatesWithoutCreatingRuntimeState(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(
		pkiSet,
		"ix-a",
		"127.0.0.1:17001",
		"https://127.0.0.1:19443",
		"10.0.0.0/24",
	)
	payload, err := yaml.Marshal(desired)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "ix-a.yaml")
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	dataDir := filepath.Join(dir, "runtime-must-not-exist")

	result, err := CheckConfig(Config{
		ConfigPath:    configPath,
		DataDir:       dataDir,
		APIAddr:       "127.0.0.1:18787",
		PeerAPIAddr:   "127.0.0.1:19443",
		DataplaneMode: "auto",
	})
	if err != nil {
		t.Fatalf("check config: %v", err)
	}
	if result.DomainID != "lab.local" || result.IXID != "ix-a" {
		t.Fatalf("check result = %#v", result)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("offline config check created data dir %q: %v", dataDir, err)
	}
}

func TestCheckConfigRejectsLegacyTransportBeforeRuntimeChanges(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "legacy.yaml")
	dataDir := filepath.Join(dir, "runtime-must-not-exist")
	payload := []byte(`
domain:
  id: lab.local
ix:
  id: ix-a
endpoints:
  - name: legacy
    transport: experimental_tcp
    listen: 127.0.0.1:17443
`)
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := CheckConfig(Config{
		ConfigPath:    configPath,
		DataDir:       dataDir,
		APIAddr:       "127.0.0.1:18787",
		PeerAPIAddr:   "127.0.0.1:19443",
		DataplaneMode: "auto",
	})
	if err == nil || !strings.Contains(err.Error(), `unsupported transport "experimental_tcp"`) {
		t.Fatalf("legacy config error = %v", err)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("rejected config check created data dir %q: %v", dataDir, err)
	}
}

func TestCheckConfigRejectsUnsupportedRuntimeInputs(t *testing.T) {
	_, err := CheckConfig(Config{
		ConfigPath:    "unused.yaml",
		APIAddr:       "not-an-address",
		DataplaneMode: "auto",
	})
	if err == nil || !strings.Contains(err.Error(), "management api listen address") {
		t.Fatalf("invalid api error = %v", err)
	}
	_, err = CheckConfig(Config{
		ConfigPath:    "unused.yaml",
		APIAddr:       "127.0.0.1:http",
		DataplaneMode: "auto",
	})
	if err == nil || !strings.Contains(err.Error(), "numeric port") {
		t.Fatalf("non-numeric api port error = %v", err)
	}
	_, err = CheckConfig(Config{
		ConfigPath:    "unused.yaml",
		APIAddr:       " 127.0.0.1:8787",
		DataplaneMode: "auto",
	})
	if err == nil || !strings.Contains(err.Error(), "surrounding whitespace") {
		t.Fatalf("api whitespace error = %v", err)
	}

	_, err = CheckConfig(Config{
		ConfigPath:    "unused.yaml",
		APIAddr:       "127.0.0.1:8787",
		DataplaneMode: "invalid",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported dataplane mode") {
		t.Fatalf("invalid dataplane error = %v", err)
	}
}
