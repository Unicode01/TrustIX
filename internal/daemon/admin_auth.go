package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trustix.local/trustix/internal/adminauth"
	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
)

const adminRequestMaxSkew = 5 * time.Minute

type managementAuthOptions struct {
	RequireWriteAuth bool
	RequireReadAuth  bool
}

type adminRequestProof struct {
	cert       *x509.Certificate
	method     string
	requestURI string
	bodySHA256 string
	timestamp  time.Time
	signature  []byte
}

type adminProofContextKey struct{}

func (daemon *Daemon) managementAuthMiddleware(next http.Handler, options managementAuthOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := rejectCrossSiteManagementMutation(r); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		writeAuth := adminAuthRequiredForRequest(r)
		readAuth := adminReadAuthRequiredForRequest(r)
		required := options.RequireWriteAuth && writeAuth || options.RequireReadAuth && readAuth
		if !required && !hasAdminAuthHeaders(r) {
			next.ServeHTTP(w, r)
			return
		}
		body, err := readLimitedBody(r.Body, maxConfigEventsBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		proofs, err := daemon.verifyAdminRequests(r, body)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		if required {
			adminProofs := adminProofsFromRequestProofs(proofs)
			if err := daemon.verifyAdminProofPolicy(adminProofs, daemon.desired.Trust); err != nil {
				writeError(w, http.StatusUnauthorized, err)
				return
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), adminProofContextKey{}, proofs))
		next.ServeHTTP(w, r)
	})
}

func rejectCrossSiteManagementMutation(r *http.Request) error {
	if !adminAuthRequiredForRequest(r) {
		return nil
	}
	site := strings.TrimSpace(strings.ToLower(r.Header.Get("Sec-Fetch-Site")))
	if site == "cross-site" || site == "same-site" {
		return fmt.Errorf("cross-site management mutation is not allowed")
	}
	for _, header := range []string{"Origin", "Referer"} {
		raw := strings.TrimSpace(r.Header.Get(header))
		if raw == "" {
			continue
		}
		if !requestSourceMatchesOrigin(raw, r) {
			return fmt.Errorf("cross-site management mutation is not allowed")
		}
	}
	return nil
}

func requestSourceMatchesOrigin(rawSource string, r *http.Request) bool {
	source, err := url.Parse(rawSource)
	if err != nil || source.Host == "" {
		return false
	}
	return strings.EqualFold(source.Scheme, requestScheme(r)) &&
		normalizeHostPort(source.Host) == normalizeHostPort(r.Host)
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func normalizeHostPort(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if strings.HasSuffix(host, ":443") {
		return strings.TrimSuffix(host, ":443")
	}
	if strings.HasSuffix(host, ":80") {
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

func hasAdminAuthHeaders(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get(adminauth.HeaderCert)) != "" ||
		strings.TrimSpace(r.Header.Get(adminauth.HeaderSignature)) != "" ||
		strings.TrimSpace(r.Header.Get(adminauth.HeaderTimestamp)) != ""
}

func adminAuthRequiredForRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/config/validate":
		return false
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/config/"):
		return true
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/trust"):
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/device-access/issue":
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/device-access/revoke":
		return true
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/endpoint-grants"):
		return true
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/admissions"):
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/control/advertisements":
		return true
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/control/members/"):
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/control/config/events":
		return true
	default:
		return false
	}
}

func adminReadAuthRequiredForRequest(r *http.Request) bool {
	if adminAuthRequiredForRequest(r) {
		return false
	}
	return r.Method != http.MethodOptions
}

func (daemon *Daemon) verifyAdminRequest(r *http.Request, body []byte) (adminRequestProof, error) {
	proofs, err := daemon.verifyAdminRequests(r, body)
	if err != nil {
		return adminRequestProof{}, err
	}
	if len(proofs) == 0 {
		return adminRequestProof{}, fmt.Errorf("admin signed request headers are required")
	}
	return proofs[0], nil
}

func (daemon *Daemon) verifyAdminRequests(r *http.Request, body []byte) ([]adminRequestProof, error) {
	return daemon.verifyAdminRequestsForRequestURI(r, body, r.URL.RequestURI())
}

func (daemon *Daemon) verifyAdminRequestsForRequestURI(r *http.Request, body []byte, requestURI string) ([]adminRequestProof, error) {
	rawCerts := adminHeaderValues(r.Header, adminauth.HeaderCert)
	rawSignatures := adminHeaderValues(r.Header, adminauth.HeaderSignature)
	timestamps := adminHeaderValues(r.Header, adminauth.HeaderTimestamp)
	if len(rawCerts) == 0 || len(rawSignatures) == 0 || len(timestamps) == 0 {
		return nil, fmt.Errorf("admin signed request headers are required")
	}
	if len(rawCerts) != len(rawSignatures) || len(rawCerts) != len(timestamps) {
		return nil, fmt.Errorf("admin signed request header counts differ: cert=%d signature=%d timestamp=%d", len(rawCerts), len(rawSignatures), len(timestamps))
	}
	proofs := make([]adminRequestProof, 0, len(rawCerts))
	for i := range rawCerts {
		proof, err := daemon.verifyAdminRequestHeaders(r, body, requestURI, rawCerts[i], rawSignatures[i], timestamps[i])
		if err != nil {
			return nil, fmt.Errorf("admin proof %d: %w", i, err)
		}
		proofs = append(proofs, proof)
	}
	return proofs, nil
}

func adminHeaderValues(header http.Header, name string) []string {
	values := make([]string, 0)
	for _, raw := range header.Values(name) {
		for _, value := range strings.Split(raw, ",") {
			value = strings.TrimSpace(value)
			if value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

func (daemon *Daemon) verifyAdminRequestHeaders(r *http.Request, body []byte, requestURI string, rawCert, rawSignature, timestamp string) (adminRequestProof, error) {
	if rawCert == "" || rawSignature == "" || timestamp == "" {
		return adminRequestProof{}, fmt.Errorf("admin signed request headers are required")
	}
	requestTime, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return adminRequestProof{}, fmt.Errorf("admin request timestamp is invalid")
	}
	now := time.Now().UTC()
	if requestTime.Before(now.Add(-adminRequestMaxSkew)) || requestTime.After(now.Add(adminRequestMaxSkew)) {
		return adminRequestProof{}, fmt.Errorf("admin request timestamp is outside the allowed window")
	}
	certDER, err := base64.StdEncoding.DecodeString(rawCert)
	if err != nil {
		return adminRequestProof{}, fmt.Errorf("decode admin certificate: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(rawSignature)
	if err != nil {
		return adminRequestProof{}, fmt.Errorf("decode admin signature: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return adminRequestProof{}, fmt.Errorf("parse admin certificate: %w", err)
	}
	if err := daemon.verifyAdminCertificate(cert); err != nil {
		return adminRequestProof{}, err
	}
	signingBytes := adminauth.SigningBytes(r.Method, requestURI, timestamp, body)
	if len(signature) == 0 {
		return adminRequestProof{}, fmt.Errorf("admin signature is empty")
	}
	if err := pki.Verify(cert, signingBytes, signature); err != nil {
		return adminRequestProof{}, fmt.Errorf("verify admin signature: %w", err)
	}
	bodyHash := sha256.Sum256(body)
	return adminRequestProof{
		cert:       cert,
		method:     strings.ToUpper(r.Method),
		requestURI: requestURI,
		bodySHA256: hex.EncodeToString(bodyHash[:]),
		timestamp:  requestTime.UTC(),
		signature:  signature,
	}, nil
}

func (daemon *Daemon) verifyAdminCertificate(cert *x509.Certificate) error {
	return daemon.verifyAdminCertificateWithTrust(cert, daemon.desired.Trust)
}

func (daemon *Daemon) verifyAdminCertificateWithTrust(cert *x509.Certificate, trust config.TrustConfig) error {
	if err := verifyCertificateNotRevokedByTrust(trust, cert, "admin certificate"); err != nil {
		return err
	}
	meta := pki.ParseMetadata(cert)
	if meta.Role != pki.RoleAdmin {
		return fmt.Errorf("admin certificate role is %q, want %q", meta.Role, pki.RoleAdmin)
	}
	if meta.Domain != string(daemon.desired.Domain.ID) {
		return fmt.Errorf("admin certificate domain is %q, want %q", meta.Domain, daemon.desired.Domain.ID)
	}
	roots, err := daemon.trustRootCertificatesWithTrust(trust)
	if err != nil {
		return err
	}
	if err := pki.VerifyChain(cert, roots, nil); err != nil {
		return fmt.Errorf("verify admin certificate chain: %w", err)
	}
	return nil
}

func adminProofsFromContext(ctx context.Context) []configlog.AdminProof {
	if proofs, ok := ctx.Value(adminProofContextKey{}).([]adminRequestProof); ok {
		return adminProofsFromRequestProofs(proofs)
	}
	proof, ok := ctx.Value(adminProofContextKey{}).(adminRequestProof)
	if !ok || proof.cert == nil {
		return nil
	}
	return adminProofsFromRequestProofs([]adminRequestProof{proof})
}

func adminProofsFromRequestProofs(proofs []adminRequestProof) []configlog.AdminProof {
	if len(proofs) == 0 {
		return nil
	}
	out := make([]configlog.AdminProof, 0, len(proofs))
	for _, proof := range proofs {
		if proof.cert == nil {
			continue
		}
		out = append(out, configlog.AdminProof{
			SignerID:    signerIDForAdminCert(proof.cert),
			Certificate: proof.cert.Raw,
			Method:      proof.method,
			RequestURI:  proof.requestURI,
			BodySHA256:  proof.bodySHA256,
			Timestamp:   proof.timestamp,
			Signature:   append([]byte(nil), proof.signature...),
		})
	}
	return out
}

func adminProofsNotRevokedByTrust(proofs []configlog.AdminProof, trust config.TrustConfig) []configlog.AdminProof {
	if len(proofs) == 0 {
		return nil
	}
	filtered := make([]configlog.AdminProof, 0, len(proofs))
	for _, proof := range proofs {
		cert, err := x509.ParseCertificate(proof.Certificate)
		if err != nil {
			continue
		}
		if err := verifyCertificateNotRevokedByTrust(trust, cert, "admin proof certificate"); err != nil {
			continue
		}
		filtered = append(filtered, proof)
	}
	return filtered
}

func signerIDForAdminCert(cert *x509.Certificate) core.SignerID {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return core.SignerID("admin:" + hex.EncodeToString(sum[:]))
}

func (daemon *Daemon) verifyAdminProofPolicy(proofs []configlog.AdminProof, trust config.TrustConfig) error {
	threshold := config.EffectiveAdminThreshold(trust)
	if threshold <= 0 {
		threshold = 1
	}
	if len(proofs) == 0 {
		return fmt.Errorf("domain trust changes require %d Admin proof(s)", threshold)
	}
	allowed := make(map[string]struct{}, len(trust.AdminPolicy.AllowedFingerprints))
	for _, raw := range trust.AdminPolicy.AllowedFingerprints {
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(raw)
		if err != nil {
			return err
		}
		allowed[fingerprint] = struct{}{}
	}
	unique := make(map[string]struct{}, len(proofs))
	for _, proof := range proofs {
		cert, err := x509.ParseCertificate(proof.Certificate)
		if err != nil {
			return fmt.Errorf("parse admin proof certificate: %w", err)
		}
		fingerprint := pki.CertificateFingerprintSHA256(cert)
		if len(allowed) > 0 {
			if _, ok := allowed[fingerprint]; !ok {
				continue
			}
		}
		if err := daemon.verifyAdminCertificateWithTrust(cert, trust); err != nil {
			return err
		}
		unique[fingerprint] = struct{}{}
	}
	if len(unique) < threshold {
		return fmt.Errorf("admin policy requires %d distinct Admin proof(s), got %d", threshold, len(unique))
	}
	return nil
}

func (daemon *Daemon) apiSecurityDoctorCheck() doctorCheck {
	if daemon.cfg.APIAdminAuth {
		if daemon.managementPrimaryAPIReadAuthRequired() {
			return doctorCheck{Name: "api_security", Status: "ok", Detail: "admin signed reads and writes required on the non-loopback primary management API; protected mutations include config apply/rejoin/restore-backup, trust, admission, and control changes"}
		}
		return doctorCheck{Name: "api_security", Status: "ok", Detail: "admin signed writes required; primary management API reads are loopback-only"}
	}
	if apiAddrIsLoopback(daemon.cfg.APIAddr) {
		return doctorCheck{Name: "api_security", Status: "ok", Detail: "management API is loopback-only; high-risk mutation endpoints include config restore-backup, config apply/rejoin, trust, admissions, and control writes"}
	}
	return doctorCheck{Name: "api_security", Status: "warn", Detail: "management API writes are unauthenticated on a non-loopback listener; high-risk mutations include config restore-backup, config apply/rejoin, trust, admissions, and control writes"}
}

func (daemon *Daemon) managementHostAPIDoctorCheck() doctorCheck {
	hostAPI := daemon.desired.Management.HostAPI
	if !hostAPI.Enabled {
		return doctorCheck{Name: "management_host_api", Status: "ok", Detail: "host management API is disabled"}
	}
	listen, err := daemon.managementHostAPIListenAddress()
	if err != nil {
		return doctorCheck{Name: "management_host_api", Status: "degraded", Detail: err.Error()}
	}
	if !daemon.managementHostAPIWriteAuthRequired() {
		return doctorCheck{Name: "management_host_api", Status: "degraded", Detail: fmt.Sprintf("host management API %s://%s allows unauthenticated writes", daemon.managementAPIScheme(listen), listen)}
	}
	if !daemon.managementHostAPIReadAuthRequired() {
		return doctorCheck{Name: "management_host_api", Status: "warn", Detail: fmt.Sprintf("host management API %s://%s requires signed writes; reads are unauthenticated", daemon.managementAPIScheme(listen), listen)}
	}
	return doctorCheck{Name: "management_host_api", Status: "ok", Detail: fmt.Sprintf("host management API %s://%s requires Admin signed reads and writes", daemon.managementAPIScheme(listen), listen)}
}

func apiAddrIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
