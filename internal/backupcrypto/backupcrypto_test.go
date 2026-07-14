package backupcrypto

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	public, identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	payload := []byte("private TrustIX backup payload")
	envelope, err := Seal(payload, public)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !IsEncrypted(envelope) || bytes.Contains(envelope, payload) {
		t.Fatal("sealed backup did not use the encrypted envelope")
	}
	opened, err := Open(envelope, identity)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, payload) {
		t.Fatalf("opened payload = %q", opened)
	}
}

func TestOpenRejectsWrongIdentityAndTampering(t *testing.T) {
	public, identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, wrongIdentity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal([]byte("payload"), public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(envelope, wrongIdentity); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("wrong identity error = %v", err)
	}
	envelope[len(envelope)-1] ^= 0xff
	if _, err := Open(envelope, identity); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
}

func TestWriteAndReadKeyPair(t *testing.T) {
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "backup.pub")
	identityPath := filepath.Join(dir, "backup.key")
	if err := WriteKeyPair(publicPath, identityPath); err != nil {
		t.Fatalf("write key pair: %v", err)
	}
	public, err := ReadPublicKeyFile(publicPath)
	if err != nil {
		t.Fatalf("read public: %v", err)
	}
	identity, err := ReadIdentityFile(identityPath)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	envelope, err := Seal([]byte("payload"), public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(envelope, identity); err != nil {
		t.Fatalf("open with persisted identity: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(identityPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("identity mode = %04o", got)
		}
	}
	if err := WriteKeyPair(publicPath, identityPath); err == nil {
		t.Fatal("existing key outputs were overwritten")
	}
}

func TestReadIdentityRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission semantics")
	}
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "backup.pub")
	identityPath := filepath.Join(dir, "backup.key")
	if err := WriteKeyPair(publicPath, identityPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(identityPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadIdentityFile(identityPath); err == nil || !strings.Contains(err.Error(), "require 0600") {
		t.Fatalf("loose permission error = %v", err)
	}
}
