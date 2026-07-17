package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trustix.local/trustix/internal/buildinfo"
	"trustix.local/trustix/internal/pki"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "version":
		if err := buildinfo.WriteText(os.Stdout, buildinfo.Snapshot()); err != nil {
			fmt.Fprintf(os.Stderr, "trustix-ca: %v\n", err)
			os.Exit(1)
		}
		return
	case "quickstart":
		err = quickstart(os.Args[2:])
	case "root":
		err = root(os.Args[2:])
	case "domain":
		err = domain(os.Args[2:])
	case "admin":
		err = admin(os.Args[2:])
	case "ix":
		err = ix(os.Args[2:])
	case "device":
		err = device(os.Args[2:])
	case "route":
		err = route(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustix-ca: %v\n", err)
		os.Exit(1)
	}
}

func quickstart(args []string) error {
	fs := flag.NewFlagSet("quickstart", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	domainID := fs.String("domain", "lab.local", "domain id")
	adminID := fs.String("admin", "admin-1", "admin id")
	ixList := fs.String("ix", "ix-a,ix-b", "comma-separated IX ids")
	dnsList := fs.String("dns", "", "comma-separated DNS SANs to add to every IX certificate")
	ipList := fs.String("ip", "", "comma-separated IP SANs to add to every IX certificate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dnsNames := splitCSV(*dnsList)
	ipAddresses, err := parseIPList(*ipList)
	if err != nil {
		return err
	}

	root, err := pki.NewRoot("TrustIX Root CA", 10)
	if err != nil {
		return err
	}
	if err := pki.WriteBundle(*out, "root-ca", root, true); err != nil {
		return err
	}

	domainCA, err := pki.Issue(root, pki.IssueRequest{
		CommonName: "TrustIX Domain CA " + *domainID,
		Role:       pki.RoleDomainCA,
		Domain:     *domainID,
		IsCA:       true,
		NotAfter:   time.Now().AddDate(5, 0, 0),
	})
	if err != nil {
		return err
	}
	if err := pki.WriteBundle(*out, "domain-ca", domainCA, true); err != nil {
		return err
	}

	configCA, err := pki.Issue(domainCA, pki.IssueRequest{
		CommonName: "TrustIX Config CA " + *domainID,
		Role:       pki.RoleDomainConfigCA,
		Domain:     *domainID,
		IsCA:       true,
		NotAfter:   time.Now().AddDate(3, 0, 0),
	})
	if err != nil {
		return err
	}
	if err := pki.WriteBundle(*out, "config-ca", configCA, true); err != nil {
		return err
	}

	adminCert, err := pki.Issue(configCA, pki.IssueRequest{
		CommonName: "TrustIX Admin " + *adminID,
		Role:       pki.RoleAdmin,
		Domain:     *domainID,
		NotAfter:   time.Now().AddDate(2, 0, 0),
	})
	if err != nil {
		return err
	}
	if err := pki.WriteBundle(*out, *adminID, adminCert, true); err != nil {
		return err
	}

	for _, ixID := range splitCSV(*ixList) {
		ixCert, err := pki.Issue(domainCA, pki.IssueRequest{
			CommonName:  "TrustIX IX " + ixID,
			Role:        pki.RoleIX,
			Domain:      *domainID,
			IX:          ixID,
			IsCA:        true,
			DNSNames:    dnsNames,
			IPAddresses: ipAddresses,
			NotAfter:    time.Now().AddDate(1, 0, 0),
		})
		if err != nil {
			return err
		}
		if err := pki.WriteBundle(*out, ixID, ixCert, true); err != nil {
			return err
		}
		prefix := quickstartPrefix(ixID)
		if prefix != "" {
			routeCert, err := pki.Issue(configCA, pki.IssueRequest{
				CommonName: "TrustIX Route Authorization " + ixID,
				Role:       pki.RoleRouteAuthorization,
				Domain:     *domainID,
				IX:         ixID,
				Prefixes:   []string{prefix},
				NotAfter:   time.Now().AddDate(1, 0, 0),
			})
			if err != nil {
				return err
			}
			if err := pki.WriteBundle(*out, ixID+"-route", routeCert, false); err != nil {
				return err
			}
		}
	}

	fmt.Printf("wrote quickstart certificates to %s\n", *out)
	return nil
}

func root(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return fmt.Errorf("usage: trustix-ca root init [-out certs] [-name 'TrustIX Root CA']")
	}
	fs := flag.NewFlagSet("root init", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	name := fs.String("name", "TrustIX Root CA", "root common name")
	years := fs.Int("years", 10, "validity in years")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	root, err := pki.NewRoot(*name, *years)
	if err != nil {
		return err
	}
	if err := pki.WriteBundle(*out, "root-ca", root, true); err != nil {
		return err
	}
	fmt.Printf("wrote root CA to %s\n", *out)
	return nil
}

func domain(args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return fmt.Errorf("usage: trustix-ca domain issue -domain lab.local [-out certs]")
	}
	fs := flag.NewFlagSet("domain issue", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	domainID := fs.String("domain", "", "domain id")
	rootCert := fs.String("root-cert", "", "root CA certificate")
	rootKey := fs.String("root-key", "", "root CA key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *domainID == "" {
		return fmt.Errorf("domain is required")
	}
	if *rootCert == "" {
		*rootCert = filepath.Join(*out, "root-ca.pem")
	}
	if *rootKey == "" {
		*rootKey = filepath.Join(*out, "root-ca.key")
	}
	rootBundle, err := pki.LoadBundle(*rootCert, *rootKey)
	if err != nil {
		return err
	}
	domainCA, err := pki.Issue(rootBundle, pki.IssueRequest{
		CommonName: "TrustIX Domain CA " + *domainID,
		Role:       pki.RoleDomainCA,
		Domain:     *domainID,
		IsCA:       true,
		NotAfter:   time.Now().AddDate(5, 0, 0),
	})
	if err != nil {
		return err
	}
	if err := pki.WriteBundle(*out, "domain-ca", domainCA, true); err != nil {
		return err
	}
	fmt.Printf("wrote domain CA to %s\n", *out)
	return nil
}

func admin(args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return fmt.Errorf("usage: trustix-ca admin issue -domain lab.local -admin admin-1 [-out certs]")
	}
	fs := flag.NewFlagSet("admin issue", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	domainID := fs.String("domain", "", "domain id")
	adminID := fs.String("admin", "admin-1", "admin id")
	caCert := fs.String("ca-cert", "", "config CA certificate")
	caKey := fs.String("ca-key", "", "config CA key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *domainID == "" {
		return fmt.Errorf("domain is required")
	}
	if *caCert == "" {
		*caCert = filepath.Join(*out, "config-ca.pem")
	}
	if *caKey == "" {
		*caKey = filepath.Join(*out, "config-ca.key")
	}
	caBundle, err := pki.LoadBundle(*caCert, *caKey)
	if err != nil {
		return err
	}
	cert, err := pki.Issue(caBundle, pki.IssueRequest{
		CommonName: "TrustIX Admin " + *adminID,
		Role:       pki.RoleAdmin,
		Domain:     *domainID,
		NotAfter:   time.Now().AddDate(2, 0, 0),
	})
	if err != nil {
		return err
	}
	if err := pki.WriteBundle(*out, *adminID, cert, true); err != nil {
		return err
	}
	fmt.Printf("wrote admin certificate to %s\n", *out)
	return nil
}

func ix(args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return fmt.Errorf("usage: trustix-ca ix issue -domain lab.local -ix ix-a [-out certs]")
	}
	fs := flag.NewFlagSet("ix issue", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	domainID := fs.String("domain", "", "domain id")
	ixID := fs.String("ix", "", "IX id")
	dnsList := fs.String("dns", "", "comma-separated DNS SANs")
	ipList := fs.String("ip", "", "comma-separated IP SANs")
	caCert := fs.String("ca-cert", "", "domain CA certificate")
	caKey := fs.String("ca-key", "", "domain CA key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *domainID == "" || *ixID == "" {
		return fmt.Errorf("domain and ix are required")
	}
	if *caCert == "" {
		*caCert = filepath.Join(*out, "domain-ca.pem")
	}
	if *caKey == "" {
		*caKey = filepath.Join(*out, "domain-ca.key")
	}
	ipAddresses, err := parseIPList(*ipList)
	if err != nil {
		return err
	}
	caBundle, err := pki.LoadBundle(*caCert, *caKey)
	if err != nil {
		return err
	}
	cert, err := pki.Issue(caBundle, pki.IssueRequest{
		CommonName:  "TrustIX IX " + *ixID,
		Role:        pki.RoleIX,
		Domain:      *domainID,
		IX:          *ixID,
		IsCA:        true,
		DNSNames:    splitCSV(*dnsList),
		IPAddresses: ipAddresses,
		NotAfter:    time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		return err
	}
	if err := pki.WriteBundle(*out, *ixID, cert, true); err != nil {
		return err
	}
	fmt.Printf("wrote IX certificate to %s\n", *out)
	return nil
}

func device(args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return fmt.Errorf("usage: trustix-ca device issue -domain lab.local -ix ix-a -device laptop-1 [-out certs]")
	}
	fs := flag.NewFlagSet("device issue", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	domainID := fs.String("domain", "", "domain id")
	ixID := fs.String("ix", "", "issuing IX id")
	deviceID := fs.String("device", "", "device id")
	dnsList := fs.String("dns", "", "comma-separated DNS SANs")
	ipList := fs.String("ip", "", "comma-separated IP SANs")
	ixCert := fs.String("ix-cert", "", "IX certificate")
	ixKey := fs.String("ix-key", "", "IX key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *domainID == "" || *ixID == "" || *deviceID == "" {
		return fmt.Errorf("domain, ix, and device are required")
	}
	if *ixCert == "" {
		*ixCert = filepath.Join(*out, *ixID+".crt")
	}
	if *ixKey == "" {
		*ixKey = filepath.Join(*out, *ixID+".key")
	}
	ipAddresses, err := parseIPList(*ipList)
	if err != nil {
		return err
	}
	ixBundle, err := pki.LoadBundle(*ixCert, *ixKey)
	if err != nil {
		return err
	}
	ixMeta := pki.ParseMetadata(ixBundle.Cert)
	if ixMeta.Role != pki.RoleIX {
		return fmt.Errorf("issuer certificate role is %q, want %q", ixMeta.Role, pki.RoleIX)
	}
	if ixMeta.Domain != *domainID {
		return fmt.Errorf("issuer certificate domain is %q, want %q", ixMeta.Domain, *domainID)
	}
	if ixMeta.IX != *ixID {
		return fmt.Errorf("issuer certificate ix is %q, want %q", ixMeta.IX, *ixID)
	}
	if !ixBundle.Cert.IsCA {
		return fmt.Errorf("issuer IX certificate is not a CA; reissue it with trustix-ca ix issue from this version")
	}
	cert, err := pki.Issue(ixBundle, pki.IssueRequest{
		CommonName:  "TrustIX Device " + *deviceID,
		Role:        pki.RoleDevice,
		Domain:      *domainID,
		IX:          *ixID,
		Device:      *deviceID,
		DNSNames:    splitCSV(*dnsList),
		IPAddresses: ipAddresses,
		NotAfter:    time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		return err
	}
	cert.CertPEM = append(append([]byte(nil), cert.CertPEM...), ixBundle.CertPEM...)
	base := *ixID + "-" + *deviceID
	if err := pki.WriteBundle(*out, base, cert, true); err != nil {
		return err
	}
	fmt.Printf("wrote device certificate to %s\n", *out)
	return nil
}

func route(args []string) error {
	if len(args) == 0 || args[0] != "authorize" {
		return fmt.Errorf("usage: trustix-ca route authorize -domain lab.local -ix ix-a -prefix 10.0.0.0/24 [-out certs]")
	}
	fs := flag.NewFlagSet("route authorize", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	domainID := fs.String("domain", "", "domain id")
	ixID := fs.String("ix", "", "IX id")
	prefixes := fs.String("prefix", "", "comma-separated authorized prefixes")
	caCert := fs.String("ca-cert", "", "config CA certificate")
	caKey := fs.String("ca-key", "", "config CA key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *domainID == "" || *ixID == "" || *prefixes == "" {
		return fmt.Errorf("domain, ix, and prefix are required")
	}
	if *caCert == "" {
		*caCert = filepath.Join(*out, "config-ca.pem")
	}
	if *caKey == "" {
		*caKey = filepath.Join(*out, "config-ca.key")
	}
	caBundle, err := pki.LoadBundle(*caCert, *caKey)
	if err != nil {
		return err
	}
	cert, err := pki.Issue(caBundle, pki.IssueRequest{
		CommonName: "TrustIX Route Authorization " + *ixID,
		Role:       pki.RoleRouteAuthorization,
		Domain:     *domainID,
		IX:         *ixID,
		Prefixes:   splitCSV(*prefixes),
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		return err
	}
	base := *ixID + "-route"
	if err := pki.WriteBundle(*out, base, cert, true); err != nil {
		return err
	}
	fmt.Printf("wrote route authorization certificate to %s\n", *out)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	certPath := fs.String("cert", "", "certificate to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certPath == "" {
		return fmt.Errorf("cert is required")
	}
	cert, _, err := pki.LoadCertificate(*certPath)
	if err != nil {
		return err
	}
	meta := pki.ParseMetadata(cert)
	fmt.Printf("subject=%s\nrole=%s\ndomain=%s\nix=%s\ndevice=%s\nprefixes=%s\ndns_names=%s\nip_addresses=%s\nfingerprint_sha256=%s\nnot_after=%s\n",
		cert.Subject.String(),
		meta.Role,
		meta.Domain,
		meta.IX,
		meta.Device,
		strings.Join(meta.Prefixes, ","),
		strings.Join(cert.DNSNames, ","),
		joinIPs(cert.IPAddresses),
		pki.CertificateFingerprintSHA256(cert),
		cert.NotAfter.Format(time.RFC3339),
	)
	return nil
}

func parseIPList(raw string) ([]net.IP, error) {
	parts := splitCSV(raw)
	out := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP SAN %q", part)
		}
		out = append(out, ip)
	}
	return out, nil
}

func joinIPs(values []net.IP) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, value.String())
	}
	return strings.Join(parts, ",")
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func quickstartPrefix(ixID string) string {
	switch ixID {
	case "ix-a":
		return "10.0.0.0/24"
	case "ix-b":
		return "10.0.1.0/24"
	default:
		return ""
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  trustix-ca quickstart [-out certs] [-domain lab.local] [-ix ix-a,ix-b] [-dns name] [-ip 203.0.113.10]
  trustix-ca root init [-out certs]
  trustix-ca domain issue -domain lab.local [-out certs]
  trustix-ca admin issue -domain lab.local -admin admin-1 [-out certs]
  trustix-ca ix issue -domain lab.local -ix ix-a [-out certs] [-dns name] [-ip 203.0.113.10]
  trustix-ca device issue -domain lab.local -ix ix-a -device laptop-1 [-out certs] [-dns name] [-ip 10.0.0.200]
  trustix-ca route authorize -domain lab.local -ix ix-a -prefix 10.0.0.0/24 [-out certs]
  trustix-ca verify -cert certs/ix-a.crt
  trustix-ca version`)
}
