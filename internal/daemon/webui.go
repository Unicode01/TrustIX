package daemon

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"

	"trustix.local/trustix/internal/webui"
)

type webUIStatus struct {
	Enabled   bool     `json:"enabled"`
	Active    bool     `json:"active"`
	Mode      string   `json:"mode,omitempty"`
	ExposedOn []string `json:"exposed_on,omitempty"`
	CustomDir string   `json:"custom_dir,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type webUIBootstrap struct {
	APIBase              string `json:"api_base"`
	AssetBase            string `json:"asset_base"`
	RequireAdminProof    bool   `json:"require_admin_proof"`
	AdminReadAuthEnabled bool   `json:"admin_read_auth_enabled"`
}

func (daemon *Daemon) managementWebUIEnabled() bool {
	return daemon.desired.Management.WebUI.Enabled
}

func (daemon *Daemon) managementWebUIStatus() webUIStatus {
	webUI := daemon.desired.Management.WebUI
	status := webUIStatus{
		Enabled:   webUI.Enabled,
		Mode:      "follows_api",
		CustomDir: strings.TrimSpace(webUI.CustomDir),
	}
	if !webUI.Enabled {
		return status
	}

	status.Active = true
	status.ExposedOn = appendUniqueString(status.ExposedOn, daemon.cfg.APIAddr)
	if daemon.managementHostAPIEnabled() {
		listen, err := daemon.managementHostAPIListenAddress()
		if err != nil {
			status.Error = err.Error()
		} else {
			status.ExposedOn = appendUniqueString(status.ExposedOn, listen)
		}
	}
	for _, target := range daemon.managementVIPTargets() {
		status.ExposedOn = appendUniqueString(status.ExposedOn, target.listenAddress())
	}
	sort.Strings(status.ExposedOn)
	return status
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func (daemon *Daemon) serveWebUIIfRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		daemon.serveWebUIIndex(w, r)
		return true
	}
	if assetName, ok := webUIAssetName(r.URL.Path); ok {
		daemon.serveWebUIAsset(w, r, assetName)
		return true
	}
	return false
}

func webUIAssetName(requestPath string) (string, bool) {
	if requestPath == "/favicon.svg" {
		return "favicon.svg", true
	}
	if !strings.HasPrefix(requestPath, "/assets/") {
		return "", false
	}
	name := strings.TrimPrefix(requestPath, "/assets/")
	if strings.TrimSpace(name) == "" {
		return "", true
	}
	return name, true
}

func (daemon *Daemon) serveWebUIIndex(w http.ResponseWriter, r *http.Request) {
	if !webUIReadMethodAllowed(w, r) {
		return
	}
	nonce, err := newWebUIScriptNonce()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	payload, err := daemon.webUIAssets().RenderIndex(daemon.webUIIndexData(nonce))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	setWebUISecurityHeaders(w, nonce)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(payload)
	}
}

func (daemon *Daemon) serveWebUIAsset(w http.ResponseWriter, r *http.Request, assetName string) {
	if !webUIReadMethodAllowed(w, r) {
		return
	}
	setWebUISecurityHeaders(w, "")
	if err := daemon.webUIAssets().Serve(w, assetName); err != nil {
		http.NotFound(w, r)
	}
}

func webUIReadMethodAllowed(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s is not allowed", r.Method))
	return false
}

func (daemon *Daemon) webUIAssets() *webui.Assets {
	return webui.New(daemon.desired.Management.WebUI.CustomDir)
}

func (daemon *Daemon) webUIIndexData(scriptNonce string) webui.IndexData {
	bootstrap := webUIBootstrap{
		APIBase:              "/v1",
		AssetBase:            "/assets",
		RequireAdminProof:    daemon.webUIRequiresAdminProof(),
		AdminReadAuthEnabled: daemon.webUIRequiresAdminProof(),
	}
	payload, err := json.Marshal(bootstrap)
	if err != nil {
		payload = []byte("{}")
	}
	return webui.IndexData{
		Title:         "TrustIX",
		BootstrapJSON: template.JS(payload),
		ScriptNonce:   scriptNonce,
	}
}

func newWebUIScriptNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate webui csp nonce: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(raw[:]), nil
}

func setWebUISecurityHeaders(w http.ResponseWriter, scriptNonce string) {
	header := w.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	header.Set("Content-Security-Policy", webUIContentSecurityPolicy(scriptNonce))
}

func webUIContentSecurityPolicy(scriptNonce string) string {
	scriptSrc := "script-src 'self'"
	if scriptNonce != "" {
		scriptSrc += " 'nonce-" + scriptNonce + "'"
	}
	return strings.Join([]string{
		"default-src 'self'",
		"base-uri 'none'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"form-action 'none'",
		"img-src 'self' data:",
		"style-src 'self'",
		scriptSrc,
		"connect-src 'self'",
	}, "; ")
}

func (daemon *Daemon) managementWebUIDoctorCheck() doctorCheck {
	webUI := daemon.desired.Management.WebUI
	if !webUI.Enabled {
		return doctorCheck{Name: "management_web_ui", Status: "ok", Detail: "web ui is disabled"}
	}
	status := "ok"
	details := []string{"web ui follows management API listeners"}
	if daemon.cfg.APIAdminAuth {
		if daemon.managementPrimaryAPIReadAuthRequired() {
			details = append(details, "primary listener requires signed reads and writes")
		} else {
			details = append(details, "primary listener requires signed writes")
		}
	} else if apiAddrIsLoopback(daemon.cfg.APIAddr) {
		details = append(details, "primary listener is loopback-only without signed writes")
	} else {
		status = worstDoctorStatus(status, "warn")
		details = append(details, "primary listener exposes unauthenticated writes on a non-loopback address")
	}
	if !daemon.managementTLSEnabledForListen(daemon.cfg.APIAddr) && !apiAddrIsLoopback(daemon.cfg.APIAddr) {
		status = worstDoctorStatus(status, "degraded")
		details = append(details, "primary listener exposes WebUI without HTTPS")
	}
	hostAPI := daemon.desired.Management.HostAPI
	if hostAPI.Enabled {
		listen, err := daemon.managementHostAPIListenAddress()
		if err != nil {
			status = worstDoctorStatus(status, "degraded")
			details = append(details, err.Error())
		} else {
			if !daemon.managementHostAPIWriteAuthRequired() {
				status = worstDoctorStatus(status, "degraded")
				details = append(details, fmt.Sprintf("host listener %s allows unauthenticated writes", listen))
			} else {
				details = append(details, fmt.Sprintf("host listener %s requires signed writes", listen))
			}
			if !daemon.managementHostAPIReadAuthRequired() {
				status = worstDoctorStatus(status, "warn")
				details = append(details, fmt.Sprintf("host listener %s allows unauthenticated reads", listen))
			}
			if !daemon.managementTLSEnabledForListen(listen) && !apiAddrIsLoopback(listen) {
				status = worstDoctorStatus(status, "degraded")
				details = append(details, fmt.Sprintf("host listener %s exposes WebUI without HTTPS", listen))
			}
		}
	}
	if customDir := strings.TrimSpace(webUI.CustomDir); customDir != "" {
		details = append(details, "custom_dir="+customDir)
	}
	return doctorCheck{Name: "management_web_ui", Status: status, Detail: strings.Join(details, "; ")}
}

func (daemon *Daemon) webUIRequiresAdminProof() bool {
	return daemon.managementPrimaryAPIReadAuthRequired() || daemon.managementHostAPIReadAuthRequired()
}

func worstDoctorStatus(current, candidate string) string {
	if doctorStatusRank(candidate) > doctorStatusRank(current) {
		return candidate
	}
	return current
}

func doctorStatusRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "degraded", "bad", "error":
		return 3
	case "warn":
		return 2
	case "ok":
		return 1
	default:
		return 0
	}
}
