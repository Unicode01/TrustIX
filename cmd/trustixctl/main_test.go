package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trustix.local/trustix/internal/backupcrypto"
)

func TestEncryptedBackupNeverWritesPlainArchive(t *testing.T) {
	archive := []byte("test gzip archive with PRIVATE KEY material")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/config/export" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="trustix-lab-ix-a-20260715T000000Z.tar.gz"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	dir := t.TempDir()
	publicPath := filepath.Join(dir, "backup.pub")
	identityPath := filepath.Join(dir, "backup.key")
	if err := backupcrypto.WriteKeyPair(publicPath, identityPath); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "backup.tixbak")
	client := apiClient{baseURL: server.URL}
	if err := client.postAndSaveEncryptedBackup("/v1/config/export", []byte(`{"include_private_keys":true}`), publicPath, outPath); err != nil {
		t.Fatalf("encrypted backup: %v", err)
	}
	encrypted, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !backupcrypto.IsEncrypted(encrypted) || bytes.Contains(encrypted, archive) || bytes.Contains(encrypted, []byte("PRIVATE KEY")) {
		t.Fatal("backup output exposed plaintext archive material")
	}
	opened, err := readBackupArchive(outPath, identityPath)
	if err != nil {
		t.Fatalf("read encrypted backup: %v", err)
	}
	if !bytes.Equal(opened, archive) {
		t.Fatalf("opened archive = %q", opened)
	}
}

func TestReadBackupArchiveRejectsWrongIdentityAndTampering(t *testing.T) {
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "backup.pub")
	identityPath := filepath.Join(dir, "backup.key")
	wrongPublicPath := filepath.Join(dir, "wrong.pub")
	wrongIdentityPath := filepath.Join(dir, "wrong.key")
	if err := backupcrypto.WriteKeyPair(publicPath, identityPath); err != nil {
		t.Fatal(err)
	}
	if err := backupcrypto.WriteKeyPair(wrongPublicPath, wrongIdentityPath); err != nil {
		t.Fatal(err)
	}
	public, err := backupcrypto.ReadPublicKeyFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := backupcrypto.Seal([]byte("archive"), public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "backup.tixbak")
	if err := os.WriteFile(path, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackupArchive(path, wrongIdentityPath); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("wrong identity error = %v", err)
	}
	encrypted[len(encrypted)-1] ^= 0xff
	if err := os.WriteFile(path, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackupArchive(path, identityPath); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestPostAndReadRejectsOversizeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.CopyN(w, zeroStream{}, 17)
	}))
	defer server.Close()
	client := apiClient{baseURL: server.URL}
	if _, _, err := client.postAndRead("/v1/config/export", nil, "application/json", 16); err == nil || !strings.Contains(err.Error(), "exceeds 16 bytes") {
		t.Fatalf("oversize response error = %v", err)
	}
}

type zeroStream struct{}

func (zeroStream) Read(payload []byte) (int, error) {
	for i := range payload {
		payload[i] = 0
	}
	return len(payload), nil
}
