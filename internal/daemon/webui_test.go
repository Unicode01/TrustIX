package daemon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
)

func TestManagementHandlerServesLocalWebUI(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "127.0.0.1:8787"},
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Management: config.ManagementConfig{
				WebUI: config.WebUIConfig{Enabled: true},
			},
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("content-type = %q, want text/html", contentType)
	}
	if !strings.Contains(recorder.Body.String(), "window.TRUSTIX_WEBUI") {
		t.Fatalf("index response does not include webui bootstrap")
	}
	if !strings.Contains(recorder.Body.String(), "<title>TrustIX - ix-a</title>") {
		t.Fatalf("index response does not include IX title: %s", recorder.Body.String())
	}
	if csp := recorder.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "script-src 'self' 'nonce-") {
		t.Fatalf("content-security-policy = %q, want frame protection and script nonce", csp)
	}
	if recorder.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("x-frame-options = %q, want DENY", recorder.Header().Get("X-Frame-Options"))
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("x-content-type-options = %q, want nosniff", recorder.Header().Get("X-Content-Type-Options"))
	}
	if !strings.Contains(recorder.Body.String(), `<script nonce="`) {
		t.Fatalf("index response does not include csp nonce")
	}
}

func TestManagementHandlerDoesNotServeDisabledWebUI(t *testing.T) {
	daemon := &Daemon{cfg: Config{APIAddr: "127.0.0.1:8787"}}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestManagementHandlerWebUIFollowsRuntimeConfig(t *testing.T) {
	daemon := &Daemon{cfg: Config{APIAddr: "127.0.0.1:8787"}}
	handler := daemon.handler()
	daemon.desired.Management.WebUI = config.WebUIConfig{Enabled: true}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestManagementHandlerServesEmbeddedWebUIAsset(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "127.0.0.1:8787"},
		desired: config.Desired{
			Management: config.ManagementConfig{
				WebUI: config.WebUIConfig{Enabled: true},
			},
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/assets/i18n/en.json", nil)
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("content-type = %q, want application/json", contentType)
	}
	if !strings.Contains(recorder.Body.String(), "TrustIX") {
		t.Fatalf("asset response does not look like the embedded locale")
	}
	if csp := recorder.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("asset content-security-policy = %q, want same-origin default", csp)
	}
}

func TestManagementHandlerServesWebUIAssetIndexAliases(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "127.0.0.1:8787"},
		desired: config.Desired{
			Management: config.ManagementConfig{
				WebUI: config.WebUIConfig{Enabled: true},
			},
		},
	}
	for _, path := range []string{"/assets", "/assets/", "/assets/index.html"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			recorder := httptest.NewRecorder()

			daemon.handler().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
			}
			body := recorder.Body.String()
			if !strings.Contains(body, "window.TRUSTIX_WEBUI") {
				t.Fatalf("index response does not include webui bootstrap")
			}
			if strings.Contains(body, "{{.BootstrapJSON}}") || strings.Contains(body, "{{.ScriptNonce}}") {
				t.Fatalf("index alias returned an unrendered template: %s", body)
			}
		})
	}
}

func TestHostAPIHandlerServesWebUIWhenEnabled(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "127.0.0.1:8787"},
		desired: config.Desired{
			LAN: config.LANConfig{Gateway: "10.0.0.1/24"},
			Management: config.ManagementConfig{
				HostAPI: config.HostManagementAPIConfig{Enabled: true, AllowUnauthenticatedReads: true},
				WebUI:   config.WebUIConfig{Enabled: true},
			},
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()

	daemon.hostAPIHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestManagementWebUIStatusFollowsAPIListeners(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "127.0.0.1:8787"},
		desired: config.Desired{
			LAN: config.LANConfig{Gateway: "10.0.0.1/24"},
			Management: config.ManagementConfig{
				HostAPI: config.HostManagementAPIConfig{Enabled: true},
				WebUI:   config.WebUIConfig{Enabled: true},
			},
		},
	}

	status := daemon.managementWebUIStatus()

	if !status.Enabled || !status.Active || status.Mode != "follows_api" || len(status.ExposedOn) != 2 {
		t.Fatalf("web ui status = %#v", status)
	}
	if status.ExposedOn[0] != "10.0.0.1:8787" || status.ExposedOn[1] != "127.0.0.1:8787" {
		t.Fatalf("web ui exposed_on = %#v", status.ExposedOn)
	}
}

func TestManagementWebUIDoctorDisabled(t *testing.T) {
	daemon := &Daemon{cfg: Config{APIAddr: "127.0.0.1:8787"}}

	check := daemon.managementWebUIDoctorCheck()

	if check.Name != "management_web_ui" || check.Status != "ok" || !strings.Contains(check.Detail, "disabled") {
		t.Fatalf("web ui doctor = %#v, want disabled ok", check)
	}
}

func TestManagementWebUIDoctorWarnsForNetworkPrimaryWithoutWriteAuth(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "0.0.0.0:8787"},
		desired: config.Desired{
			Management: config.ManagementConfig{
				WebUI: config.WebUIConfig{Enabled: true},
			},
		},
	}

	check := daemon.managementWebUIDoctorCheck()

	if check.Status != "warn" || !strings.Contains(check.Detail, "non-loopback") {
		t.Fatalf("web ui doctor = %#v, want non-loopback warning", check)
	}
}

func TestManagementWebUIDoctorDegradedForHostUnauthenticatedWrites(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "127.0.0.1:8787"},
		desired: config.Desired{
			LAN: config.LANConfig{Gateway: "10.0.0.1/24"},
			Management: config.ManagementConfig{
				HostAPI: config.HostManagementAPIConfig{Enabled: true, AllowUnauthenticatedWrites: true},
				WebUI:   config.WebUIConfig{Enabled: true},
			},
		},
	}

	check := daemon.managementWebUIDoctorCheck()

	if check.Status != "degraded" || !strings.Contains(check.Detail, "unauthenticated writes") {
		t.Fatalf("web ui doctor = %#v, want host unauthenticated writes degraded", check)
	}
}

func TestManagementWebUIDoctorWarnsForCustomDir(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "127.0.0.1:8787", APIAdminAuth: true},
		desired: config.Desired{
			Management: config.ManagementConfig{
				WebUI: config.WebUIConfig{Enabled: true, CustomDir: "/opt/trustix-webui"},
			},
		},
	}

	check := daemon.managementWebUIDoctorCheck()

	if check.Status != "warn" || !strings.Contains(check.Detail, "custom_dir=/opt/trustix-webui") || !strings.Contains(check.Detail, "Admin proof") {
		t.Fatalf("web ui doctor = %#v, want custom_dir Admin proof warning", check)
	}
}
