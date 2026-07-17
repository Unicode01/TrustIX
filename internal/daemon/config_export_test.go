package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
)

func TestConfigExportArchiveOmitsPrivateKeysByDefault(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.Endpoints = append(desired.Endpoints, config.EndpointConfig{
		Name:      "ix-a-tix-tcp",
		Mode:      config.EndpointModePassive,
		Listen:    "127.0.0.1:7443",
		Transport: "tix_tcp",
		Enabled:   true,
	})
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	daemon.logPath = "memory"

	response, err := daemon.exportConfigArchive(configExportRequest{})
	if err != nil {
		t.Fatalf("export config archive: %v", err)
	}
	entries := readConfigExportArchive(t, response.payload)
	manifest := decodeConfigExportManifest(t, entries["manifest.json"])
	if manifest.PrivateKeysIncluded {
		t.Fatal("manifest marks private keys included for default export")
	}
	if manifest.PrivateKeysOmitted == 0 {
		t.Fatal("manifest should report omitted private keys")
	}
	if _, ok := entries["desired.json"]; !ok {
		t.Fatal("archive missing desired.json")
	}
	legacyTransport := []byte(`"transport": "experimental` + `_tcp"`)
	if !bytes.Contains(entries["desired.json"], []byte(`"transport": "tix_tcp"`)) ||
		bytes.Contains(entries["desired.json"], legacyTransport) {
		t.Fatalf("exported desired config did not use the canonical TIX-TCP name:\n%s", entries["desired.json"])
	}
	if len(entries["config.log"]) == 0 {
		t.Fatal("archive missing config.log payload")
	}
	manifestHead := manifest.ConfigHead
	if manifestHead.Seq < 2 {
		t.Fatalf("export head seq = %d, want synthetic desired baseline included", manifestHead.Seq)
	}
	for path, payload := range entries {
		if strings.Contains(path, "private_key") || bytes.Contains(payload, []byte("PRIVATE KEY")) {
			t.Fatalf("default export leaked private key material in %s", path)
		}
	}
	if !configExportManifestHasRole(manifest, "ix.certificate") {
		t.Fatal("manifest missing IX certificate file")
	}
}

func TestConfigRestoreArchiveRestoresRuntimeAndConfigLog(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, initial)
	daemon.logPath = "memory"
	exported, err := daemon.exportConfigArchive(configExportRequest{IncludePrivateKeys: true})
	if err != nil {
		t.Fatalf("export backup archive: %v", err)
	}

	next := configApplyDesired(pkiSet, "10.0.2.0/24")
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply next changed=%t err=%v", changed, err)
	}
	assertRuntimeRoute(t, daemon, "10.0.2.0/24")

	response, err := daemon.restoreConfigArchive(context.Background(), exported.payload)
	if err != nil {
		t.Fatalf("restore config archive: %v", err)
	}
	if !response.Restored || response.Head.Seq != exported.manifest.ConfigHead.Seq || response.Head.Hash != exported.manifest.ConfigHead.Hash {
		t.Fatalf("restore response = %#v, want exported head %#v", response, exported.manifest.ConfigHead)
	}
	assertRuntimeRoute(t, daemon, "10.0.1.0/24")
	assertNoRuntimeRoute(t, daemon, "10.0.2.0/24")
	head, err := daemon.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != exported.manifest.ConfigHead.Seq || head.Hash != exported.manifest.ConfigHead.Hash {
		t.Fatalf("store head after restore = %#v, want %#v", head, exported.manifest.ConfigHead)
	}
}

func TestConfigRestoreArchiveRollsBackLogAndRuntimeAfterPostCommitFailure(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, initial)
	daemon.logPath = "memory"
	exported, err := daemon.exportConfigArchive(configExportRequest{IncludePrivateKeys: true})
	if err != nil {
		t.Fatalf("export backup archive: %v", err)
	}

	next := configApplyDesired(pkiSet, "10.0.2.0/24")
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply next changed=%t err=%v", changed, err)
	}
	beforeHead := daemon.head
	daemon.dataplane = &failNthSnapshotManager{inner: dataplane.NewNoopManager(), failAt: 2}

	if _, err := daemon.restoreConfigArchive(context.Background(), exported.payload); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("restore post-commit failure err = %v, want rolled-back error", err)
	}
	storeHead, err := daemon.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	if storeHead != beforeHead || daemon.head != beforeHead {
		t.Fatalf("restore failure changed head: store=%+v runtime=%+v before=%+v", storeHead, daemon.head, beforeHead)
	}
	if !desiredConfigsEqual(daemon.desired, next) {
		t.Fatal("restore failure did not restore previous desired config")
	}
	assertRuntimeRoute(t, daemon, "10.0.2.0/24")
	assertNoRuntimeRoute(t, daemon, "10.0.1.0/24")
}

type failNthSnapshotManager struct {
	inner  dataplane.Manager
	calls  int
	failAt int
}

func (manager *failNthSnapshotManager) Load(ctx context.Context) error {
	return manager.inner.Load(ctx)
}

func (manager *failNthSnapshotManager) Attach(ctx context.Context, spec dataplane.AttachSpec) error {
	return manager.inner.Attach(ctx, spec)
}

func (manager *failNthSnapshotManager) ApplySnapshot(ctx context.Context, snapshot dataplane.Snapshot) error {
	manager.calls++
	if manager.calls == manager.failAt {
		return fmt.Errorf("injected snapshot failure")
	}
	return manager.inner.ApplySnapshot(ctx, snapshot)
}

func (manager *failNthSnapshotManager) Stats(ctx context.Context) (dataplane.Stats, error) {
	return manager.inner.Stats(ctx)
}

func (manager *failNthSnapshotManager) Detach(ctx context.Context) error {
	return manager.inner.Detach(ctx)
}

func TestConfigValidateArchiveVerifiesRecoveryWithoutMutation(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, initial)
	daemon.logPath = "memory"
	exported, err := daemon.exportConfigArchive(configExportRequest{IncludePrivateKeys: true})
	if err != nil {
		t.Fatalf("export backup archive: %v", err)
	}

	next := configApplyDesired(pkiSet, "10.0.2.0/24")
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply next changed=%t err=%v", changed, err)
	}
	headBefore, err := daemon.store.Head()
	if err != nil {
		t.Fatal(err)
	}

	response, err := daemon.validateConfigArchive(exported.payload)
	if err != nil {
		t.Fatalf("validate config archive: %v", err)
	}
	if !response.Valid || !response.Restorable || !response.RecoveryComplete || !response.PrivateKeysIncluded || response.PrivateKeyFiles == 0 {
		t.Fatalf("validation response = %#v", response)
	}
	if response.Head != exported.manifest.ConfigHead {
		t.Fatalf("validated head = %#v, want %#v", response.Head, exported.manifest.ConfigHead)
	}
	headAfter, err := daemon.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	if headAfter != headBefore {
		t.Fatalf("validation mutated config log head: before=%#v after=%#v", headBefore, headAfter)
	}
	assertRuntimeRoute(t, daemon, "10.0.2.0/24")
	assertNoRuntimeRoute(t, daemon, "10.0.1.0/24")
}

func TestConfigValidateArchiveReportsIncompleteRecoveryWithoutPrivateKeys(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	exported, err := daemon.exportConfigArchive(configExportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := daemon.validateConfigArchive(exported.payload)
	if err != nil {
		t.Fatalf("validate config archive: %v", err)
	}
	if !response.Valid || !response.Restorable || response.RecoveryComplete || response.PrivateKeysIncluded || response.PrivateKeyFiles != 0 {
		t.Fatalf("validation response = %#v", response)
	}
}

func TestConfigRestoreArchiveRejectsUnauthorizedTargetPath(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	exported, err := daemon.exportConfigArchive(configExportRequest{IncludePrivateKeys: true})
	if err != nil {
		t.Fatalf("export backup archive: %v", err)
	}
	entries := readConfigExportArchive(t, exported.payload)
	manifest := decodeConfigExportManifest(t, entries["manifest.json"])
	if len(manifest.Files) == 0 {
		t.Fatal("export manifest has no files")
	}
	manifest.Files[0].SourcePath = filepath.Join(t.TempDir(), "not-configured.key")
	entries["manifest.json"] = mustJSON(t, manifest)
	tampered := writeTestRestoreArchive(t, entries)

	if _, err := daemon.restoreConfigArchive(context.Background(), tampered); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("restore tampered target err = %v, want not allowed", err)
	}
}

func TestConfigRestoreArchiveRejectsTrailingJSONEntryContent(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	exported, err := daemon.exportConfigArchive(configExportRequest{})
	if err != nil {
		t.Fatalf("export archive: %v", err)
	}
	entries := readConfigExportArchive(t, exported.payload)
	entries["manifest.json"] = append(entries["manifest.json"], []byte("\n{}")...)
	tampered := writeTestRestoreArchive(t, entries)

	if _, err := parseConfigRestoreArchive(tampered); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("parse trailing JSON archive err = %v, want trailing JSON", err)
	}
}

func TestConfigRestoreArchiveRejectsUnreferencedFile(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	exported, err := daemon.exportConfigArchive(configExportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	entries := readConfigExportArchive(t, exported.payload)
	entries["unreferenced-private.key"] = []byte("PRIVATE KEY")
	tampered := writeTestRestoreArchive(t, entries)
	if _, err := parseConfigRestoreArchive(tampered); err == nil || !strings.Contains(err.Error(), "unreferenced file") {
		t.Fatalf("parse unreferenced file error = %v", err)
	}
}

func TestConfigRestoreArchiveRejectsDesiredOutsideSignedSnapshot(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	exported, err := daemon.exportConfigArchive(configExportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	entries := readConfigExportArchive(t, exported.payload)
	var desiredEntry config.Desired
	if err := json.Unmarshal(entries["desired.json"], &desiredEntry); err != nil {
		t.Fatal(err)
	}
	desiredEntry.Routes = nil
	entries["desired.json"] = mustJSON(t, desiredEntry)
	tampered := writeTestRestoreArchive(t, entries)
	if _, err := parseConfigRestoreArchive(tampered); err == nil || !strings.Contains(err.Error(), "does not match latest desired") {
		t.Fatalf("parse mismatched desired error = %v", err)
	}
}

func TestConfigRestoreArchiveRejectsTooManyEntries(t *testing.T) {
	var payload bytes.Buffer
	gzipWriter := gzip.NewWriter(&payload)
	tarWriter := tar.NewWriter(gzipWriter)
	for i := 0; i <= maxConfigRestoreArchiveEntries; i++ {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name:     fmt.Sprintf("dirs/%03d", i),
			Typeflag: tar.TypeDir,
			Mode:     0o700,
			ModTime:  time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := parseConfigRestoreArchive(payload.Bytes()); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("parse oversized-entry archive err = %v, want entry limit", err)
	}
}

func TestConfigRestoreArchiveRejectsSymlinkTarget(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	exported, err := daemon.exportConfigArchive(configExportRequest{IncludePrivateKeys: true})
	if err != nil {
		t.Fatalf("export backup archive: %v", err)
	}

	target := pkiSet.ixKeys["ix-a"]
	linkTarget := filepath.Join(filepath.Dir(target), "linked.key")
	if err := os.WriteFile(linkTarget, []byte("linked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkTarget, target); err != nil {
		t.Skipf("symlink creation unavailable on this host: %v", err)
	}

	if _, err := daemon.restoreConfigArchive(context.Background(), exported.payload); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("restore symlink target err = %v, want not a regular file", err)
	}
}

func TestConfigRestoreArchiveFilesRollBackEarlierWrites(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	configPath := writeConfigExportSourceFile(t, desired)
	daemon.cfg.ConfigPath = configPath
	originalConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	certPath := desired.IX.CertPath
	if err := os.Remove(certPath); err != nil {
		t.Fatalf("remove certificate fixture: %v", err)
	}
	if err := os.Mkdir(certPath, 0o700); err != nil {
		t.Fatalf("replace certificate fixture with directory: %v", err)
	}
	configPayload := []byte(`{"changed":true}`)
	certPayload := []byte("replacement certificate")
	archive := parsedConfigRestoreArchive{
		Manifest: configExportManifest{Files: []configExportFileManifest{
			{
				Roles:       []string{"config.source"},
				SourcePath:  configPath,
				ArchivePath: "files/config.json",
				SizeBytes:   int64(len(configPayload)),
				SHA256:      sha256Bytes(configPayload),
			},
			{
				Roles:       []string{"ix.certificate"},
				SourcePath:  certPath,
				ArchivePath: "files/ix.crt",
				SizeBytes:   int64(len(certPayload)),
				SHA256:      sha256Bytes(certPayload),
			},
		}},
		Entries: map[string][]byte{
			"files/config.json": configPayload,
			"files/ix.crt":      certPayload,
		},
	}

	if _, changes, _, _, err := daemon.restoreConfigArchiveFiles(archive, desired); err == nil {
		t.Fatal("restore files succeeded with a directory certificate target")
	} else if len(changes) != 0 {
		t.Fatalf("restore returned unrolled changes: %#v", changes)
	}
	restoredConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredConfig, originalConfig) {
		t.Fatalf("config file was not rolled back\n got: %s\nwant: %s", restoredConfig, originalConfig)
	}
}

func TestConfigRestoreFileModeChangeIsRolledBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	target := filepath.Join(t.TempDir(), "certificate.pem")
	payload := []byte("same certificate")
	if err := os.WriteFile(target, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	backup, changed, err := writeConfigRestoreFile(target, payload, false)
	if err != nil {
		t.Fatalf("restore mode-only file change: %v", err)
	}
	if !changed || backup == "" {
		t.Fatalf("mode-only restore changed=%t backup=%q, want transactional change", changed, backup)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("restored mode = %o, want 0644", info.Mode().Perm())
	}
	if err := rollbackConfigRestoreFiles([]configRestoreFileChange{{targetPath: target, backupPath: backup}}); err != nil {
		t.Fatalf("rollback mode-only file change: %v", err)
	}
	info, err = os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("rolled-back mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestConfigRestoreArchiveAPIRequiresAdminProofWhenEnabled(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.APIAdminAuth = true
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	exported, err := daemon.exportConfigArchive(configExportRequest{})
	if err != nil {
		t.Fatalf("export archive: %v", err)
	}

	unsigned := httptest.NewRequest(http.MethodPost, "/v1/config/restore-archive", bytes.NewReader(exported.payload))
	unsigned.Header.Set("Content-Type", "application/gzip")
	unsignedRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(unsignedRecorder, unsigned)
	if unsignedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned restore status = %d, want %d; body=%s", unsignedRecorder.Code, http.StatusUnauthorized, unsignedRecorder.Body.String())
	}

	signed := httptest.NewRequest(http.MethodPost, "/v1/config/restore-archive", bytes.NewReader(exported.payload))
	signed.Header.Set("Content-Type", "application/gzip")
	signAdminTestRequest(t, signed, exported.payload, pkiSet.adminCert, pkiSet.adminKey)
	signedRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(signedRecorder, signed)
	if signedRecorder.Code != http.StatusOK {
		t.Fatalf("signed restore status = %d, want %d; body=%s", signedRecorder.Code, http.StatusOK, signedRecorder.Body.String())
	}
}

func TestConfigValidateArchiveAPIRequiresAdminProofWhenEnabled(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.APIAdminAuth = true
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	exported, err := daemon.exportConfigArchive(configExportRequest{IncludePrivateKeys: true})
	if err != nil {
		t.Fatalf("export archive: %v", err)
	}

	unsigned := httptest.NewRequest(http.MethodPost, "/v1/config/validate-archive", bytes.NewReader(exported.payload))
	unsigned.Header.Set("Content-Type", "application/gzip")
	unsignedRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(unsignedRecorder, unsigned)
	if unsignedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned validate status = %d, want %d; body=%s", unsignedRecorder.Code, http.StatusUnauthorized, unsignedRecorder.Body.String())
	}

	signed := httptest.NewRequest(http.MethodPost, "/v1/config/validate-archive", bytes.NewReader(exported.payload))
	signed.Header.Set("Content-Type", "application/gzip")
	signAdminTestRequest(t, signed, exported.payload, pkiSet.adminCert, pkiSet.adminKey)
	signedRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(signedRecorder, signed)
	if signedRecorder.Code != http.StatusOK {
		t.Fatalf("signed validate status = %d, want %d; body=%s", signedRecorder.Code, http.StatusOK, signedRecorder.Body.String())
	}
	var response configValidateArchiveResponse
	if err := json.Unmarshal(signedRecorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode validation response: %v", err)
	}
	if !response.Valid || !response.RecoveryComplete {
		t.Fatalf("validation response = %#v", response)
	}
}

func TestConfigBackupArchiveIncludesPrivateKeysWhenRequested(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.ConfigPath = writeConfigExportSourceFile(t, desired)
	daemon.logPath = "memory"

	response, err := daemon.exportConfigArchive(configExportRequest{IncludePrivateKeys: true})
	if err != nil {
		t.Fatalf("export config backup archive: %v", err)
	}
	entries := readConfigExportArchive(t, response.payload)
	manifest := decodeConfigExportManifest(t, entries["manifest.json"])
	if !manifest.PrivateKeysIncluded || manifest.PrivateKeysOmitted != 0 {
		t.Fatalf("private key manifest flags = included:%t omitted:%d, want included and none omitted", manifest.PrivateKeysIncluded, manifest.PrivateKeysOmitted)
	}
	keyPayload, err := os.ReadFile(pkiSet.ixKeys["ix-a"])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range manifest.Files {
		if !entry.PrivateKey {
			continue
		}
		if bytes.Equal(entries[entry.ArchivePath], keyPayload) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("backup archive did not include local IX private key")
	}
}

func TestConfigExportAPIRequiresAdminProofWhenEnabled(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	daemon.cfg.APIAdminAuth = true
	body := []byte(`{}`)

	unsigned := httptest.NewRequest(http.MethodPost, "/v1/config/export", bytes.NewReader(body))
	unsigned.Header.Set("Content-Type", "application/json")
	unsignedRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(unsignedRecorder, unsigned)
	if unsignedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status = %d, want %d; body=%s", unsignedRecorder.Code, http.StatusUnauthorized, unsignedRecorder.Body.String())
	}

	signed := httptest.NewRequest(http.MethodPost, "/v1/config/export", bytes.NewReader(body))
	signed.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, signed, body, pkiSet.adminCert, pkiSet.adminKey)
	signedRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(signedRecorder, signed)
	if signedRecorder.Code != http.StatusOK {
		t.Fatalf("signed status = %d, want %d; body=%s", signedRecorder.Code, http.StatusOK, signedRecorder.Body.String())
	}
	if contentType := signedRecorder.Header().Get("Content-Type"); contentType != "application/gzip" {
		t.Fatalf("content-type = %q, want application/gzip", contentType)
	}
	if cacheControl := signedRecorder.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("cache-control = %q, want no-store", cacheControl)
	}
	if got := signedRecorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("x-content-type-options = %q, want nosniff", got)
	}
}

func writeConfigExportSourceFile(t *testing.T, desired any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trustix.json")
	payload, err := json.MarshalIndent(desired, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readConfigExportArchive(t *testing.T, payload []byte) map[string][]byte {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	entries := make(map[string][]byte)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar header: %v", err)
		}
		content, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatalf("read tar file %q: %v", header.Name, err)
		}
		entries[header.Name] = content
	}
	return entries
}

func writeTestRestoreArchive(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var payload bytes.Buffer
	gzipWriter := gzip.NewWriter(&payload)
	tarWriter := tar.NewWriter(gzipWriter)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := entries[name]
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), ModTime: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return payload.Bytes()
}

func decodeConfigExportManifest(t *testing.T, payload []byte) configExportManifest {
	t.Helper()
	if len(payload) == 0 {
		t.Fatal("manifest payload is empty")
	}
	var manifest configExportManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return manifest
}

func configExportManifestHasRole(manifest configExportManifest, role string) bool {
	for _, file := range manifest.Files {
		for _, candidate := range file.Roles {
			if candidate == role {
				return true
			}
		}
	}
	return false
}
