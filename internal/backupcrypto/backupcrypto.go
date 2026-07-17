package backupcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	publicKeyPrefix = "TRUSTIX-BACKUP-PUBLIC-KEY-V1:"
	identityPrefix  = "TRUSTIX-BACKUP-IDENTITY-V1:"
)

var envelopeMagic = []byte("TRUSTIX-ENCRYPTED-BACKUP-V1\n")

type PublicKey [curve25519.ScalarSize]byte
type Identity [curve25519.ScalarSize]byte

func GenerateKeyPair() (PublicKey, Identity, error) {
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return PublicKey{}, Identity{}, fmt.Errorf("generate backup key pair: %w", err)
	}
	return PublicKey(*public), Identity(*private), nil
}

func WriteKeyPair(publicPath, identityPath string) (err error) {
	publicPath = filepath.Clean(strings.TrimSpace(publicPath))
	identityPath = filepath.Clean(strings.TrimSpace(identityPath))
	if publicPath == "." || identityPath == "." {
		return fmt.Errorf("public and identity output paths are required")
	}
	if samePath(publicPath, identityPath) {
		return fmt.Errorf("public and identity output paths must be different")
	}
	public, identity, err := GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := writeKeyFile(identityPath, MarshalIdentity(identity), 0o600); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if removeErr := os.Remove(identityPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("remove backup identity %q after public key failure: %w", identityPath, removeErr))
			} else if syncErr := syncKeyDirectory(filepath.Dir(identityPath)); syncErr != nil {
				err = errors.Join(err, fmt.Errorf("sync backup identity directory after cleanup: %w", syncErr))
			}
		}
	}()
	if err = writeKeyFile(publicPath, MarshalPublicKey(public), 0o644); err != nil {
		return err
	}
	return nil
}

func MarshalPublicKey(key PublicKey) []byte {
	return []byte(publicKeyPrefix + base64.RawURLEncoding.EncodeToString(key[:]) + "\n")
}

func MarshalIdentity(identity Identity) []byte {
	return []byte(identityPrefix + base64.RawURLEncoding.EncodeToString(identity[:]) + "\n")
}

func ParsePublicKey(payload []byte) (PublicKey, error) {
	decoded, err := parseKey(payload, publicKeyPrefix)
	if err != nil {
		return PublicKey{}, fmt.Errorf("parse backup public key: %w", err)
	}
	return PublicKey(decoded), nil
}

func ParseIdentity(payload []byte) (Identity, error) {
	decoded, err := parseKey(payload, identityPrefix)
	if err != nil {
		return Identity{}, fmt.Errorf("parse backup identity: %w", err)
	}
	return Identity(decoded), nil
}

func ReadPublicKeyFile(path string) (PublicKey, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return PublicKey{}, fmt.Errorf("read backup public key %q: %w", path, err)
	}
	return ParsePublicKey(payload)
}

func ReadIdentityFile(path string) (Identity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Identity{}, fmt.Errorf("stat backup identity %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return Identity{}, fmt.Errorf("backup identity %q is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Identity{}, fmt.Errorf("backup identity %q permissions %04o expose private key material; require 0600", path, info.Mode().Perm())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, fmt.Errorf("read backup identity %q: %w", path, err)
	}
	return ParseIdentity(payload)
}

func Seal(payload []byte, recipient PublicKey) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("backup payload is empty")
	}
	sealed, err := box.SealAnonymous(nil, payload, (*[curve25519.ScalarSize]byte)(&recipient), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("encrypt backup: %w", err)
	}
	envelope := make([]byte, 0, len(envelopeMagic)+len(sealed))
	envelope = append(envelope, envelopeMagic...)
	envelope = append(envelope, sealed...)
	return envelope, nil
}

func Open(envelope []byte, identity Identity) ([]byte, error) {
	if !IsEncrypted(envelope) {
		return nil, fmt.Errorf("file is not a TrustIX encrypted backup")
	}
	publicBytes, err := curve25519.X25519(identity[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive backup public key: %w", err)
	}
	var public PublicKey
	copy(public[:], publicBytes)
	plaintext, ok := box.OpenAnonymous(nil, envelope[len(envelopeMagic):], (*[curve25519.ScalarSize]byte)(&public), (*[curve25519.ScalarSize]byte)(&identity))
	if !ok {
		return nil, fmt.Errorf("decrypt backup: identity does not match or backup authentication failed")
	}
	return plaintext, nil
}

func IsEncrypted(payload []byte) bool {
	return bytes.HasPrefix(payload, envelopeMagic)
}

func parseKey(payload []byte, prefix string) ([curve25519.ScalarSize]byte, error) {
	var result [curve25519.ScalarSize]byte
	value := strings.TrimSpace(string(payload))
	if !strings.HasPrefix(value, prefix) {
		return result, fmt.Errorf("unsupported key format")
	}
	encoded := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return result, fmt.Errorf("decode key: %w", err)
	}
	if len(decoded) != len(result) {
		return result, fmt.Errorf("key is %d bytes, want %d", len(decoded), len(result))
	}
	copy(result[:], decoded)
	return result, nil
}

func writeKeyFile(path string, payload []byte, mode os.FileMode) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("key output %q already exists", path)
		}
		return fmt.Errorf("create key output %q: %w", path, err)
	}
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close key output %q: %w", path, closeErr))
			}
		}
		if err != nil {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("remove failed key output %q: %w", path, removeErr))
			} else if syncErr := syncKeyDirectory(filepath.Dir(path)); syncErr != nil {
				err = errors.Join(err, fmt.Errorf("sync key output directory after cleanup: %w", syncErr))
			}
		}
	}()
	if _, err = file.Write(payload); err != nil {
		return fmt.Errorf("write key output %q: %w", path, err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync key output %q: %w", path, err)
	}
	if err = file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close key output %q: %w", path, err)
	}
	closed = true
	if err = syncKeyDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync key output directory %q: %w", filepath.Dir(path), err)
	}
	return nil
}

func samePath(a, b string) bool {
	aAbs, aErr := filepath.Abs(a)
	bAbs, bErr := filepath.Abs(b)
	if aErr == nil && bErr == nil {
		return aAbs == bAbs || runtime.GOOS == "windows" && strings.EqualFold(aAbs, bAbs)
	}
	return a == b
}
