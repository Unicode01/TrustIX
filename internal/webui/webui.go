package webui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

//go:embed assets/* assets/i18n/*
var embeddedAssets embed.FS

type IndexData struct {
	Title         string
	BootstrapJSON template.JS
	ScriptNonce   string
}

type Assets struct {
	customDir string
}

func New(customDir string) *Assets {
	return &Assets{customDir: strings.TrimSpace(customDir)}
}

func (assets *Assets) RenderIndex(data IndexData) ([]byte, error) {
	payload, source, err := assets.Read("index.html")
	if err != nil {
		return nil, err
	}
	if source == "custom" && !customIndexUsesTrustIXTemplate(payload) {
		return payload, nil
	}
	tmpl, err := template.New("trustix-webui").Parse(string(payload))
	if err != nil {
		return nil, fmt.Errorf("parse webui index template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render webui index template: %w", err)
	}
	return buf.Bytes(), nil
}

func customIndexUsesTrustIXTemplate(payload []byte) bool {
	body := string(payload)
	return strings.Contains(body, "{{.Title") ||
		strings.Contains(body, "{{ .Title") ||
		strings.Contains(body, "{{.BootstrapJSON") ||
		strings.Contains(body, "{{ .BootstrapJSON")
}

func (assets *Assets) Read(name string) ([]byte, string, error) {
	cleaned, err := cleanAssetName(name)
	if err != nil {
		return nil, "", err
	}
	if assets.customDir != "" {
		customPath := filepath.Join(assets.customDir, filepath.FromSlash(cleaned))
		if payload, err := os.ReadFile(customPath); err == nil {
			return payload, "custom", nil
		} else if !os.IsNotExist(err) {
			return nil, "", fmt.Errorf("read custom webui asset %q: %w", cleaned, err)
		}
	}
	payload, err := embeddedAssets.ReadFile("assets/" + cleaned)
	if err != nil {
		return nil, "", fmt.Errorf("read embedded webui asset %q: %w", cleaned, err)
	}
	return payload, "embedded", nil
}

func (assets *Assets) Serve(w http.ResponseWriter, name string) error {
	payload, source, err := assets.Read(name)
	if err != nil {
		return err
	}
	contentType := contentTypeForAsset(name)
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if source == "custom" {
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write webui asset %q: %w", name, err)
	}
	return nil
}

func cleanAssetName(name string) (string, error) {
	name = strings.TrimSpace(strings.TrimPrefix(name, "/"))
	if name == "" {
		return "", fmt.Errorf("asset path is required")
	}
	cleaned := path.Clean(name)
	if cleaned == "." || strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("asset path %q is invalid", name)
	}
	return cleaned, nil
}

func contentTypeForAsset(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	}
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		return contentType
	}
	return "application/octet-stream"
}
