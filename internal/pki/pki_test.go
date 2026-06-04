package pki

import (
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestIssueIXCertificateMetadataAndSignature(t *testing.T) {
	root, err := NewRoot("TrustIX Root CA", 1)
	if err != nil {
		t.Fatalf("new root: %v", err)
	}
	domain, err := Issue(root, IssueRequest{
		CommonName: "TrustIX Domain CA lab.local",
		Role:       RoleDomainCA,
		Domain:     "lab.local",
		IsCA:       true,
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue domain: %v", err)
	}
	ix, err := Issue(domain, IssueRequest{
		CommonName:  "TrustIX IX ix-a",
		Role:        RoleIX,
		Domain:      "lab.local",
		IX:          "ix-a",
		DNSNames:    []string{"ix-a.example.com"},
		IPAddresses: []net.IP{net.ParseIP("203.0.113.10")},
		NotAfter:    time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue ix: %v", err)
	}

	meta := ParseMetadata(ix.Cert)
	if meta.Role != RoleIX || meta.Domain != "lab.local" || meta.IX != "ix-a" {
		t.Fatalf("metadata = %+v", meta)
	}
	if len(ix.Cert.DNSNames) != 2 || ix.Cert.DNSNames[0] != "lab.local" || ix.Cert.DNSNames[1] != "ix-a.example.com" {
		t.Fatalf("DNS SANs = %#v", ix.Cert.DNSNames)
	}
	if len(ix.Cert.IPAddresses) != 1 || !ix.Cert.IPAddresses[0].Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("IP SANs = %#v", ix.Cert.IPAddresses)
	}

	payload := []byte("config event")
	signature, err := Sign(ix.Key, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(ix.Cert, payload, signature); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestIssueDeviceCertificateFromIXCA(t *testing.T) {
	root, err := NewRoot("TrustIX Root CA", 1)
	if err != nil {
		t.Fatalf("new root: %v", err)
	}
	domain, err := Issue(root, IssueRequest{
		CommonName: "TrustIX Domain CA lab.local",
		Role:       RoleDomainCA,
		Domain:     "lab.local",
		IsCA:       true,
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue domain: %v", err)
	}
	ix, err := Issue(domain, IssueRequest{
		CommonName: "TrustIX IX ix-a",
		Role:       RoleIX,
		Domain:     "lab.local",
		IX:         "ix-a",
		IsCA:       true,
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue ix: %v", err)
	}
	if !ix.Cert.IsCA || ix.Cert.MaxPathLen != 0 || !ix.Cert.MaxPathLenZero {
		t.Fatalf("ix CA constraints IsCA=%t MaxPathLen=%d MaxPathLenZero=%t", ix.Cert.IsCA, ix.Cert.MaxPathLen, ix.Cert.MaxPathLenZero)
	}
	device, err := Issue(ix, IssueRequest{
		CommonName: "TrustIX Device laptop-1",
		Role:       RoleDevice,
		Domain:     "lab.local",
		IX:         "ix-a",
		Device:     "laptop-1",
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue device: %v", err)
	}
	meta := ParseMetadata(device.Cert)
	if meta.Role != RoleDevice || meta.Domain != "lab.local" || meta.IX != "ix-a" || meta.Device != "laptop-1" {
		t.Fatalf("metadata = %+v", meta)
	}
	if err := VerifyChain(device.Cert, []*x509.Certificate{root.Cert}, []*x509.Certificate{domain.Cert, ix.Cert}); err != nil {
		t.Fatalf("verify device chain: %v", err)
	}
}
