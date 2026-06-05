// Package pki contains TrustIX's first X.509 implementation. It keeps the
// certificate profile intentionally small: roles and TrustIX metadata are stored
// in private extensions, while standard CA constraints and signatures are
// handled by crypto/x509.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Role string

const (
	RoleRootCA             Role = "root_ca"
	RoleDomainCA           Role = "domain_ca"
	RoleDomainConfigCA     Role = "domain_config_ca"
	RoleAdmin              Role = "admin"
	RoleIX                 Role = "ix"
	RoleDevice             Role = "device"
	RoleRouteAuthorization Role = "route_authorization"
)

var (
	oidRole     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidDomain   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}
	oidIX       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}
	oidPrefixes = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}
	oidDevice   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}
	oidLANID    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}
)

type Bundle struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	CertPEM []byte
	KeyPEM  []byte
}

type IssueRequest struct {
	CommonName  string
	Role        Role
	Domain      string
	IX          string
	Device      string
	LANID       string
	Prefixes    []string
	DNSNames    []string
	IPAddresses []net.IP
	IsCA        bool
	NotAfter    time.Time
}

type Metadata struct {
	Role     Role     `json:"role"`
	Domain   string   `json:"domain,omitempty"`
	IX       string   `json:"ix,omitempty"`
	Device   string   `json:"device,omitempty"`
	LANID    string   `json:"lan_id,omitempty"`
	Prefixes []string `json:"prefixes,omitempty"`
}

func NewRoot(commonName string, years int) (Bundle, error) {
	if strings.TrimSpace(commonName) == "" {
		commonName = "TrustIX Root CA"
	}
	return newSelfSignedCA(IssueRequest{
		CommonName: commonName,
		Role:       RoleRootCA,
		IsCA:       true,
		NotAfter:   time.Now().AddDate(yearsOrDefault(years, 10), 0, 0),
	})
}

func Issue(parent Bundle, req IssueRequest) (Bundle, error) {
	if parent.Cert == nil || parent.Key == nil {
		return Bundle{}, fmt.Errorf("parent certificate and key are required")
	}
	if strings.TrimSpace(req.CommonName) == "" {
		return Bundle{}, fmt.Errorf("common name is required")
	}
	if req.Role == "" {
		return Bundle{}, fmt.Errorf("role is required")
	}
	if req.NotAfter.IsZero() {
		req.NotAfter = time.Now().AddDate(2, 0, 0)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, fmt.Errorf("generate private key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Bundle{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         req.CommonName,
			Organization:       []string{"TrustIX"},
			OrganizationalUnit: []string{string(req.Role)},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              req.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       metadataExtensions(req),
	}
	if req.Domain != "" {
		template.DNSNames = append(template.DNSNames, req.Domain)
	}
	template.DNSNames = append(template.DNSNames, normalizedDNSNames(req.DNSNames)...)
	template.IPAddresses = append(template.IPAddresses, normalizedIPAddresses(req.IPAddresses)...)
	if req.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if req.Role == RoleIX {
			template.MaxPathLen = 0
			template.MaxPathLenZero = true
		} else {
			template.MaxPathLen = 1
		}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, key.Public(), parent.Key)
	if err != nil {
		return Bundle{}, fmt.Errorf("create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return Bundle{}, fmt.Errorf("parse generated certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Bundle{}, fmt.Errorf("marshal private key: %w", err)
	}
	return Bundle{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func normalizedDNSNames(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizedIPAddresses(values []net.IP) []net.IP {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		normalized := value.To16()
		if normalized == nil {
			continue
		}
		if v4 := value.To4(); v4 != nil {
			normalized = v4
		}
		key := normalized.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, append(net.IP(nil), normalized...))
	}
	return out
}

func LoadBundle(certPath, keyPath string) (Bundle, error) {
	cert, certPEM, err := LoadCertificate(certPath)
	if err != nil {
		return Bundle{}, err
	}
	key, keyPEM, err := LoadPrivateKey(keyPath)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func LoadCertificate(path string) (*x509.Certificate, []byte, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read certificate %q: %w", path, err)
	}
	cert, err := ParseCertificatePEM(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %q: %w", "decode certificate", path, err)
	}
	return cert, payload, nil
}

func ParseCertificatePEM(payload []byte) (*x509.Certificate, error) {
	certs, err := ParseCertificatesPEM(payload)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func ParseCertificatesPEM(payload []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := payload
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("missing CERTIFICATE PEM block")
	}
	return certs, nil
}

func LoadPrivateKey(path string) (crypto.Signer, []byte, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key %q: %w", path, err)
	}
	block, _ := pem.Decode(payload)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("decode private key %q: missing PRIVATE KEY PEM block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key %q: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key %q is not a signer", path)
	}
	return signer, payload, nil
}

func WriteBundle(outDir, baseName string, bundle Bundle, writeKey bool) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create certificate directory %q: %w", outDir, err)
	}
	certPath := filepath.Join(outDir, baseName+".crt")
	if strings.HasSuffix(baseName, "-ca") || baseName == "root-ca" || baseName == "domain-ca" || baseName == "config-ca" {
		certPath = filepath.Join(outDir, baseName+".pem")
	}
	if err := os.WriteFile(certPath, bundle.CertPEM, 0o644); err != nil {
		return fmt.Errorf("write certificate %q: %w", certPath, err)
	}
	if writeKey {
		keyPath := filepath.Join(outDir, baseName+".key")
		if err := os.WriteFile(keyPath, bundle.KeyPEM, 0o600); err != nil {
			return fmt.Errorf("write private key %q: %w", keyPath, err)
		}
	}
	return nil
}

func Sign(signer crypto.Signer, payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign payload: %w", err)
	}
	return signature, nil
}

func Verify(cert *x509.Certificate, payload, signature []byte) error {
	digest := sha256.Sum256(payload)
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], signature) {
			return fmt.Errorf("signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
	return nil
}

func VerifyChain(cert *x509.Certificate, roots []*x509.Certificate, intermediates []*x509.Certificate) error {
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("verify certificate chain: %w", err)
	}
	return nil
}

func CertificateFingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func NormalizeCertificateFingerprintSHA256(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimPrefix(value, "sha256:")
	value = strings.ReplaceAll(value, ":", "")
	if value == "" {
		return "", fmt.Errorf("fingerprint is required")
	}
	if len(value) != sha256.Size*2 {
		return "", fmt.Errorf("fingerprint %q is not a SHA256 hex digest", raw)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("fingerprint %q is not valid hex: %w", raw, err)
	}
	return value, nil
}

func ParseMetadata(cert *x509.Certificate) Metadata {
	var meta Metadata
	for _, ext := range cert.Extensions {
		var value string
		if _, err := asn1.Unmarshal(ext.Value, &value); err != nil {
			continue
		}
		switch {
		case ext.Id.Equal(oidRole):
			meta.Role = Role(value)
		case ext.Id.Equal(oidDomain):
			meta.Domain = value
		case ext.Id.Equal(oidIX):
			meta.IX = value
		case ext.Id.Equal(oidDevice):
			meta.Device = value
		case ext.Id.Equal(oidLANID):
			meta.LANID = value
		case ext.Id.Equal(oidPrefixes):
			if value != "" {
				meta.Prefixes = strings.Split(value, ",")
			}
		}
	}
	return meta
}

func newSelfSignedCA(req IssueRequest) (Bundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, fmt.Errorf("generate private key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Bundle{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         req.CommonName,
			Organization:       []string{"TrustIX"},
			OrganizationalUnit: []string{string(req.Role)},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              req.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		ExtraExtensions:       metadataExtensions(req),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return Bundle{}, fmt.Errorf("create root certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return Bundle{}, fmt.Errorf("parse generated root certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Bundle{}, fmt.Errorf("marshal private key: %w", err)
	}
	return Bundle{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func metadataExtensions(req IssueRequest) []pkix.Extension {
	extensions := make([]pkix.Extension, 0, 6)
	add := func(oid asn1.ObjectIdentifier, value string) {
		if value == "" {
			return
		}
		encoded, err := asn1.Marshal(value)
		if err != nil {
			return
		}
		extensions = append(extensions, pkix.Extension{Id: oid, Value: encoded})
	}
	add(oidRole, string(req.Role))
	add(oidDomain, req.Domain)
	add(oidIX, req.IX)
	add(oidDevice, req.Device)
	add(oidLANID, strings.TrimSpace(req.LANID))
	add(oidPrefixes, strings.Join(req.Prefixes, ","))
	return extensions
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func yearsOrDefault(years, fallback int) int {
	if years <= 0 {
		return fallback
	}
	return years
}
