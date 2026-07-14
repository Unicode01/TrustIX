package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"trustix.local/trustix/internal/buildinfo"
	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
)

const configExportArchiveVersion = 1

type configExportRequest struct {
	IncludePrivateKeys bool `json:"include_private_keys,omitempty"`
}

type configExportResponse struct {
	filename string
	payload  []byte
	manifest configExportManifest
}

type configExportManifest struct {
	Version             int                        `json:"version"`
	CreatedAt           time.Time                  `json:"created_at"`
	DomainID            string                     `json:"domain_id"`
	IXID                string                     `json:"ix_id"`
	ConfigPath          string                     `json:"config_path,omitempty"`
	ConfigLogPath       string                     `json:"config_log_path,omitempty"`
	ConfigHead          headResponse               `json:"config_head"`
	Build               buildinfo.Info             `json:"build"`
	PrivateKeysIncluded bool                       `json:"private_keys_included"`
	PrivateKeysOmitted  int                        `json:"private_keys_omitted,omitempty"`
	Files               []configExportFileManifest `json:"files,omitempty"`
}

type configExportFileManifest struct {
	Roles       []string `json:"roles"`
	SourcePath  string   `json:"source_path"`
	ArchivePath string   `json:"archive_path"`
	SizeBytes   int64    `json:"size_bytes"`
	SHA256      string   `json:"sha256"`
	PrivateKey  bool     `json:"private_key,omitempty"`
}

type configExportFileCandidate struct {
	Role       string
	SourcePath string
	PrivateKey bool
	Required   bool
}

func (daemon *Daemon) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 4096)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request configExportRequest
	if len(bytes.TrimSpace(payload)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode config export request: %w", err))
			return
		}
	}
	response, err := daemon.exportConfigArchive(request)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	setSensitiveResponseHeaders(w)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", response.filename))
	w.Header().Set("X-TrustIX-Export-Manifest", response.manifestSummaryHeader())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response.payload)
}

func (response configExportResponse) manifestSummaryHeader() string {
	summary := struct {
		Version             int    `json:"version"`
		DomainID            string `json:"domain_id"`
		IXID                string `json:"ix_id"`
		PrivateKeysIncluded bool   `json:"private_keys_included"`
		PrivateKeysOmitted  int    `json:"private_keys_omitted,omitempty"`
		Files               int    `json:"files"`
	}{
		Version:             response.manifest.Version,
		DomainID:            response.manifest.DomainID,
		IXID:                response.manifest.IXID,
		PrivateKeysIncluded: response.manifest.PrivateKeysIncluded,
		PrivateKeysOmitted:  response.manifest.PrivateKeysOmitted,
		Files:               len(response.manifest.Files),
	}
	payload, err := json.Marshal(summary)
	if err != nil {
		return ""
	}
	return string(payload)
}

func (daemon *Daemon) exportConfigArchive(request configExportRequest) (configExportResponse, error) {
	snapshot, desired, configPath, logPath, err := daemon.configExportSnapshot()
	if err != nil {
		return configExportResponse{}, err
	}
	createdAt := time.Now().UTC()
	manifest := configExportManifest{
		Version:             configExportArchiveVersion,
		CreatedAt:           createdAt,
		DomainID:            string(desired.Domain.ID),
		IXID:                string(desired.IX.ID),
		ConfigPath:          configPath,
		ConfigLogPath:       logPath,
		ConfigHead:          snapshot.Head,
		Build:               buildinfo.Snapshot(),
		PrivateKeysIncluded: request.IncludePrivateKeys,
	}

	files, omittedPrivateKeys, err := daemon.configExportFiles(desired, configPath, request.IncludePrivateKeys)
	if err != nil {
		return configExportResponse{}, err
	}
	manifest.PrivateKeysOmitted = omittedPrivateKeys

	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	gzipWriter.Name = "trustix-config-export.tar"
	gzipWriter.ModTime = createdAt
	tarWriter := tar.NewWriter(gzipWriter)
	if err := writeConfigExportTar(tarWriter, createdAt, desired, snapshot, files, &manifest); err != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		return configExportResponse{}, err
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return configExportResponse{}, fmt.Errorf("close config export tar: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return configExportResponse{}, fmt.Errorf("close config export gzip: %w", err)
	}

	return configExportResponse{
		filename: configExportFilename(manifest),
		payload:  archive.Bytes(),
		manifest: manifest,
	}, nil
}

func (daemon *Daemon) configExportSnapshot() (configSnapshotEnvelope, config.Desired, string, string, error) {
	daemon.configMu.RLock()
	desired := daemon.desired
	head := daemon.head
	store := daemon.store
	logPath := daemon.logPath
	configPath := daemon.cfg.ConfigPath
	var events []configlog.Event
	var err error
	if store != nil && head.Seq > 0 {
		events, err = store.Range(1, head.Seq)
	}
	daemon.configMu.RUnlock()
	if err != nil {
		return configSnapshotEnvelope{}, config.Desired{}, "", "", err
	}
	events, head, err = daemon.configExportEventsWithDesiredBaseline(events, head, desired)
	if err != nil {
		return configSnapshotEnvelope{}, config.Desired{}, "", "", err
	}
	snapshot := configSnapshotEnvelope{
		DomainID:    string(desired.Domain.ID),
		IXID:        string(desired.IX.ID),
		Head:        headResponse{Seq: head.Seq, Hash: head.Hash},
		Events:      events,
		Signers:     daemon.signerCertificatesForEvents(events),
		GeneratedAt: time.Now().UTC(),
	}
	return snapshot, desired, configPath, logPath, nil
}

func (daemon *Daemon) configExportEventsWithDesiredBaseline(events []configlog.Event, head configlog.Head, desired config.Desired) ([]configlog.Event, configlog.Head, error) {
	payload, err := json.Marshal(desired)
	if err != nil {
		return nil, configlog.Head{}, fmt.Errorf("encode export desired baseline: %w", err)
	}
	resource := desiredResourceForIX(desired.IX.ID)
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Resource != resource && !(event.Resource == "/desired" && desired.IX.ID == daemon.desired.IX.ID) {
			continue
		}
		if bytes.Equal(event.Payload, payload) {
			return events, head, nil
		}
		break
	}
	event, plannedHead, changed, err := daemon.signedConfigEventAtHead(resource, configlog.ActionUpsert, payload, desired, nil, head)
	if err != nil {
		return nil, configlog.Head{}, fmt.Errorf("sign export desired baseline: %w", err)
	}
	if !changed || event == nil {
		return events, head, nil
	}
	return append(append([]configlog.Event(nil), events...), *event), plannedHead, nil
}

type configExportFile struct {
	manifest configExportFileManifest
	payload  []byte
}

func (daemon *Daemon) configExportFiles(desired config.Desired, configPath string, includePrivateKeys bool) ([]configExportFile, int, error) {
	candidates := configExportFileCandidates(desired, configPath)
	type groupedFile struct {
		sourcePath string
		privateKey bool
		required   bool
		roles      []string
	}
	grouped := make(map[string]*groupedFile)
	order := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		sourcePath := strings.TrimSpace(candidate.SourcePath)
		if sourcePath == "" {
			continue
		}
		key := configExportPathKey(sourcePath)
		group, ok := grouped[key]
		if !ok {
			group = &groupedFile{sourcePath: sourcePath}
			grouped[key] = group
			order = append(order, key)
		}
		group.privateKey = group.privateKey || candidate.PrivateKey
		group.required = group.required || candidate.Required
		if candidate.Role != "" && !containsConfigExportRole(group.roles, candidate.Role) {
			group.roles = append(group.roles, candidate.Role)
		}
	}

	usedArchivePaths := make(map[string]struct{}, len(grouped))
	files := make([]configExportFile, 0, len(grouped))
	omittedPrivateKeys := 0
	for _, key := range order {
		group := grouped[key]
		if group.privateKey && !includePrivateKeys {
			omittedPrivateKeys++
			continue
		}
		payload, err := os.ReadFile(group.sourcePath)
		if err != nil {
			if !group.required && os.IsNotExist(err) {
				continue
			}
			return nil, omittedPrivateKeys, fmt.Errorf("read export file %q: %w", group.sourcePath, err)
		}
		sum := sha256.Sum256(payload)
		archivePath := configExportArchivePath(group.roles, group.sourcePath, usedArchivePaths)
		files = append(files, configExportFile{
			manifest: configExportFileManifest{
				Roles:       append([]string(nil), group.roles...),
				SourcePath:  group.sourcePath,
				ArchivePath: archivePath,
				SizeBytes:   int64(len(payload)),
				SHA256:      hex.EncodeToString(sum[:]),
				PrivateKey:  group.privateKey,
			},
			payload: payload,
		})
	}
	sort.SliceStable(files, func(i, j int) bool {
		return files[i].manifest.ArchivePath < files[j].manifest.ArchivePath
	})
	return files, omittedPrivateKeys, nil
}

func configExportFileCandidates(desired config.Desired, configPath string) []configExportFileCandidate {
	candidates := []configExportFileCandidate{
		{Role: "config.source", SourcePath: configPath, Required: false},
		{Role: "ix.certificate", SourcePath: desired.IX.CertPath, Required: true},
		{Role: "ix.private_key", SourcePath: desired.IX.KeyPath, PrivateKey: true, Required: true},
	}
	for _, path := range desired.Domain.TrustRoots {
		candidates = append(candidates, configExportFileCandidate{Role: "domain.trust_root", SourcePath: string(path), Required: true})
	}
	for _, path := range desired.IX.RouteAuthorizations {
		candidates = append(candidates, configExportFileCandidate{Role: "ix.route_authorization", SourcePath: path, Required: true})
	}
	if normalizedManagementTLSIdentity(desired.Management.TLS.Identity) == managementTLSIdentityCustomCert {
		candidates = append(candidates,
			configExportFileCandidate{Role: "management.tls.certificate", SourcePath: desired.Management.TLS.CertPath, Required: true},
			configExportFileCandidate{Role: "management.tls.private_key", SourcePath: desired.Management.TLS.KeyPath, PrivateKey: true, Required: true},
		)
	}
	if normalizedTransportTLSIdentityMode(desired.TransportPolicy.TLSIdentity.Mode) == transportTLSIdentityCustomCert {
		candidates = append(candidates,
			configExportFileCandidate{Role: "transport.tls.certificate", SourcePath: desired.TransportPolicy.TLSIdentity.CertPath, Required: strings.TrimSpace(desired.TransportPolicy.TLSIdentity.CertPath) != ""},
			configExportFileCandidate{Role: "transport.tls.private_key", SourcePath: desired.TransportPolicy.TLSIdentity.KeyPath, PrivateKey: true, Required: strings.TrimSpace(desired.TransportPolicy.TLSIdentity.KeyPath) != ""},
		)
		for _, path := range desired.TransportPolicy.TLSIdentity.TrustRoots {
			candidates = append(candidates, configExportFileCandidate{Role: "transport.tls.trust_root", SourcePath: path, Required: true})
		}
	}
	return candidates
}

func writeConfigExportTar(tarWriter *tar.Writer, createdAt time.Time, desired config.Desired, snapshot configSnapshotEnvelope, files []configExportFile, manifest *configExportManifest) error {
	desiredPayload, err := json.MarshalIndent(desired, "", "  ")
	if err != nil {
		return fmt.Errorf("encode desired config: %w", err)
	}
	if err := addConfigExportTarFile(tarWriter, "desired.json", desiredPayload, 0o600, createdAt); err != nil {
		return err
	}
	snapshotPayload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config snapshot: %w", err)
	}
	if err := addConfigExportTarFile(tarWriter, "config-snapshot.json", snapshotPayload, 0o600, createdAt); err != nil {
		return err
	}
	configLogPayload, err := encodeConfigLogEvents(snapshot.Events)
	if err != nil {
		return err
	}
	if err := addConfigExportTarFile(tarWriter, "config.log", configLogPayload, 0o600, createdAt); err != nil {
		return err
	}
	for _, file := range files {
		manifest.Files = append(manifest.Files, file.manifest)
		mode := int64(0o644)
		if file.manifest.PrivateKey {
			mode = 0o600
		}
		if err := addConfigExportTarFile(tarWriter, file.manifest.ArchivePath, file.payload, mode, createdAt); err != nil {
			return err
		}
	}
	manifestPayload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode export manifest: %w", err)
	}
	return addConfigExportTarFile(tarWriter, "manifest.json", manifestPayload, 0o600, createdAt)
}

func encodeConfigLogEvents(events []configlog.Event) ([]byte, error) {
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return nil, fmt.Errorf("encode config log event %d: %w", event.Seq, err)
		}
	}
	return payload.Bytes(), nil
}

func addConfigExportTarFile(tarWriter *tar.Writer, name string, payload []byte, mode int64, modTime time.Time) error {
	name = strings.TrimLeft(strings.ReplaceAll(name, "\\", "/"), "/")
	if name == "" || strings.Contains(name, "../") {
		return fmt.Errorf("invalid export archive path %q", name)
	}
	header := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(payload)),
		ModTime: modTime,
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("write export tar header %q: %w", name, err)
	}
	if _, err := tarWriter.Write(payload); err != nil {
		return fmt.Errorf("write export tar file %q: %w", name, err)
	}
	return nil
}

func configExportArchivePath(roles []string, sourcePath string, used map[string]struct{}) string {
	role := "file"
	if len(roles) > 0 {
		role = roles[0]
	}
	base := filepath.Base(sourcePath)
	if base == "." || base == string(filepath.Separator) || strings.TrimSpace(base) == "" {
		base = "file"
	}
	candidate := "files/" + sanitizeArchiveSegment(role) + "/" + sanitizeArchiveSegment(base)
	if _, ok := used[candidate]; !ok {
		used[candidate] = struct{}{}
		return candidate
	}
	sum := sha256.Sum256([]byte(sourcePath))
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	for i := 8; i <= len(sum)*2; i += 8 {
		suffix := hex.EncodeToString(sum[:])[:i]
		candidate = "files/" + sanitizeArchiveSegment(role) + "/" + sanitizeArchiveSegment(stem+"-"+suffix+ext)
		if _, ok := used[candidate]; !ok {
			used[candidate] = struct{}{}
			return candidate
		}
	}
	for index := 1; ; index++ {
		candidate = fmt.Sprintf("files/%s/%s-%d", sanitizeArchiveSegment(role), sanitizeArchiveSegment(base), index)
		if _, ok := used[candidate]; !ok {
			used[candidate] = struct{}{}
			return candidate
		}
	}
}

func configExportFilename(manifest configExportManifest) string {
	stamp := manifest.CreatedAt.Format("20060102T150405Z")
	return fmt.Sprintf("trustix-%s-%s-%s.tar.gz", sanitizeArchiveSegment(manifest.DomainID), sanitizeArchiveSegment(manifest.IXID), stamp)
}

func configExportPathKey(sourcePath string) string {
	abs, err := filepath.Abs(sourcePath)
	if err != nil {
		return filepath.Clean(sourcePath)
	}
	return filepath.Clean(abs)
}

func sanitizeArchiveSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
		if ok {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(builder.String(), "-.")
	if out == "" {
		return "unknown"
	}
	return out
}

func containsConfigExportRole(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
