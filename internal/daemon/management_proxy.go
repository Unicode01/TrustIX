package daemon

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"trustix.local/trustix/internal/core"
)

const (
	managementProxyTargetIXHeader  = "X-TrustIX-Management-Target-IX"
	managementProxyTargetURIHeader = "X-TrustIX-Management-Target-URI"
	managementProxyOriginalURI     = "X-TrustIX-Management-Original-URI"
)

func (daemon *Daemon) handleManagementIXProxy(w http.ResponseWriter, r *http.Request) {
	targetIX := core.IXID(r.PathValue("ix_id"))
	if err := targetIX.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	targetURI, err := managementProxyTargetURIFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	body, err := readLimitedBody(r.Body, maxConfigEventsBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := r.Body.Close(); err != nil {
		daemon.recordBackgroundError("management_proxy_request_body_close", err)
	} else {
		daemon.clearBackgroundError("management_proxy_request_body_close")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	proofs, err := daemon.verifyAdminRequests(r, body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if err := daemon.verifyAdminProofPolicy(adminProofsFromRequestProofs(proofs), daemon.desired.Trust); err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if targetIX == daemon.desired.IX.ID {
		daemon.serveLocalManagementTarget(w, r, targetURI, body, proofs)
		return
	}
	if err := daemon.proxyManagementToIX(w, r, targetIX, targetURI, body); err != nil {
		writeError(w, http.StatusBadGateway, err)
	}
}

func (daemon *Daemon) handleControlManagementProxy(w http.ResponseWriter, r *http.Request) {
	targetIX := core.IXID(strings.TrimSpace(r.Header.Get(managementProxyTargetIXHeader)))
	if targetIX != daemon.desired.IX.ID {
		writeError(w, http.StatusBadRequest, fmt.Errorf("management proxy target ix %q does not match local ix %q", targetIX, daemon.desired.IX.ID))
		return
	}
	targetURI := strings.TrimSpace(r.Header.Get(managementProxyTargetURIHeader))
	if err := validateManagementProxyTargetURI(targetURI); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	originalURI := strings.TrimSpace(r.Header.Get(managementProxyOriginalURI))
	if originalURI == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("management proxy original URI is required"))
		return
	}
	body, err := readLimitedBody(r.Body, maxConfigEventsBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := r.Body.Close(); err != nil {
		daemon.recordBackgroundError("management_proxy_request_body_close", err)
	} else {
		daemon.clearBackgroundError("management_proxy_request_body_close")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	proofs, err := daemon.verifyAdminRequestsForRequestURI(r, body, originalURI)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if err := daemon.verifyAdminProofPolicy(adminProofsFromRequestProofs(proofs), daemon.desired.Trust); err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	daemon.serveLocalManagementTarget(w, r, targetURI, body, proofs)
}

func managementProxyTargetURIFromRequest(r *http.Request) (string, error) {
	targetPath := "/" + strings.TrimLeft(r.PathValue("path"), "/")
	if targetPath == "/" {
		return "", fmt.Errorf("management proxy target path is required")
	}
	targetURI := targetPath
	if r.URL.RawQuery != "" {
		targetURI += "?" + r.URL.RawQuery
	}
	if err := validateManagementProxyTargetURI(targetURI); err != nil {
		return "", err
	}
	return targetURI, nil
}

func validateManagementProxyTargetURI(targetURI string) error {
	parsed, err := url.ParseRequestURI(targetURI)
	if err != nil {
		return fmt.Errorf("management proxy target URI %q is invalid: %w", targetURI, err)
	}
	if parsed.IsAbs() || parsed.Host != "" {
		return fmt.Errorf("management proxy target URI must be relative")
	}
	if !strings.HasPrefix(parsed.Path, "/v1/") {
		return fmt.Errorf("management proxy target URI %q must target /v1", targetURI)
	}
	if strings.HasPrefix(parsed.Path, "/v1/management/") {
		return fmt.Errorf("management proxy target URI %q may not target management proxy endpoints", targetURI)
	}
	return nil
}

func (daemon *Daemon) serveLocalManagementTarget(w http.ResponseWriter, r *http.Request, targetURI string, body []byte, proofs []adminRequestProof) {
	parsed, err := url.ParseRequestURI(targetURI)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx := context.WithValue(r.Context(), adminProofContextKey{}, proofs)
	sub := r.Clone(ctx)
	sub.URL = parsed
	sub.RequestURI = targetURI
	sub.Body = io.NopCloser(bytes.NewReader(body))
	sub.Header = cloneManagementRequestHeader(r.Header)
	daemon.managementMux().ServeHTTP(w, sub)
}

func (daemon *Daemon) proxyManagementToIX(w http.ResponseWriter, r *http.Request, targetIX core.IXID, targetURI string, body []byte) error {
	target, err := daemon.managementControlTarget(targetIX)
	if err != nil {
		return err
	}
	client, err := daemon.controlClient(target)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(target.ControlAPI)
	if err != nil {
		return fmt.Errorf("parse control_api for %q: %w", targetIX, err)
	}
	requestURL := parsed.ResolveReference(&url.URL{Path: "/v1/control/management"})
	req, err := http.NewRequestWithContext(r.Context(), r.Method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header = cloneManagementRequestHeader(r.Header)
	req.Header.Set(managementProxyTargetIXHeader, string(targetIX))
	req.Header.Set(managementProxyTargetURIHeader, targetURI)
	req.Header.Set(managementProxyOriginalURI, r.URL.RequestURI())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("proxy management request to %q: %w", targetIX, err)
	}
	defer drainAndCloseResponse(resp)
	copyProxyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("copy management proxy response: %w", err)
	}
	return nil
}

func (daemon *Daemon) managementControlTarget(ixID core.IXID) (controlTarget, error) {
	peer, ok := daemon.peerConfig(ixID)
	if !ok {
		return controlTarget{}, fmt.Errorf("management proxy target IX %q is not a configured or learned peer", ixID)
	}
	if strings.TrimSpace(peer.ControlAPI) == "" {
		return controlTarget{}, fmt.Errorf("management proxy target IX %q has no control_api", ixID)
	}
	return controlTarget{
		ID:         peer.ID,
		Domain:     peer.Domain,
		ControlAPI: peer.ControlAPI,
	}, nil
}

func cloneManagementRequestHeader(header http.Header) http.Header {
	out := make(http.Header, len(header))
	for key, values := range header {
		if hopByHopHeader(key) || strings.HasPrefix(strings.ToLower(key), "x-trustix-management-") {
			continue
		}
		for _, value := range values {
			out.Add(key, value)
		}
	}
	return out
}

func copyProxyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		if hopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func hopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func (daemon *Daemon) managementProxyRouteForVIP(addr netip.Addr) (core.IXID, bool) {
	if !addr.Is4() {
		return "", false
	}
	if daemon.managementHostAPIAddr() == addr {
		return daemon.desired.IX.ID, true
	}
	daemon.membershipMu.RLock()
	defer daemon.membershipMu.RUnlock()
	for ixID, record := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		if managementVIPFromAdvertisement(record.Advertisement) == addr {
			return ixID, true
		}
	}
	return "", false
}

func (daemon *Daemon) managementHostAPIAddr() netip.Addr {
	addr, _, ok := daemon.managementHostAPIAdvertisedHostPort()
	if !ok {
		return netip.Addr{}
	}
	return addr
}

func managementVIPFromAdvertisement(ad advertisementResponse) netip.Addr {
	if ad.Management == nil || ad.Management.HostAPI == nil {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(ad.Management.HostAPI.IP)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
