package webui

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderEmbeddedIndex(t *testing.T) {
	assets := New("")

	payload, err := assets.RenderIndex(IndexData{
		Title:         "TrustIX",
		BootstrapJSON: template.JS(`{"api_base":"/v1"}`),
	})
	if err != nil {
		t.Fatalf("render embedded index: %v", err)
	}
	body := string(payload)
	if !strings.Contains(body, "<title>TrustIX</title>") {
		t.Fatalf("index title was not rendered: %s", body)
	}
	if !strings.Contains(body, `"api_base":"/v1"`) {
		t.Fatalf("index bootstrap was not rendered: %s", body)
	}
}

func TestReadEmbeddedLocale(t *testing.T) {
	payload, source, err := New("").Read("i18n/en.json")
	if err != nil {
		t.Fatalf("read embedded locale: %v", err)
	}
	if source != "embedded" {
		t.Fatalf("source = %q, want embedded", source)
	}
	if !strings.Contains(string(payload), "TrustIX") {
		t.Fatalf("locale payload = %s", payload)
	}
}

func TestCustomDirOverridesEmbeddedIndex(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(`<title>{{.Title}} custom</title>`), 0o600); err != nil {
		t.Fatalf("write custom index: %v", err)
	}
	assets := New(dir)

	payload, err := assets.RenderIndex(IndexData{Title: "TrustIX"})
	if err != nil {
		t.Fatalf("render custom index: %v", err)
	}
	if string(payload) != "<title>TrustIX custom</title>" {
		t.Fatalf("custom index = %s", payload)
	}
}

func TestCustomIndexWithoutTrustIXTemplateIsServedRaw(t *testing.T) {
	dir := t.TempDir()
	raw := `<div id="app">{{ frontend_template }}</div>`
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(raw), 0o600); err != nil {
		t.Fatalf("write custom index: %v", err)
	}
	assets := New(dir)

	payload, err := assets.RenderIndex(IndexData{Title: "TrustIX"})
	if err != nil {
		t.Fatalf("render custom index: %v", err)
	}
	if string(payload) != raw {
		t.Fatalf("custom index = %s, want raw %s", payload, raw)
	}
}
