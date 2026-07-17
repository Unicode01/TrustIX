package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/routing"
)

const (
	maxConfigRestoreArchiveBytes             int64 = 64 << 20
	maxConfigRestoreArchiveEntryBytes        int64 = 32 << 20
	maxConfigRestoreArchiveUncompressedBytes int64 = 96 << 20
	maxConfigRestoreArchiveFiles                   = 128
	maxConfigRestoreArchiveEntries                 = 256
)

type configRestoreArchiveResponse struct {
	Restored             bool                             `json:"restored"`
	DomainID             string                           `json:"domain_id"`
	IXID                 string                           `json:"ix_id"`
	Head                 headResponse                     `json:"head"`
	FilesRestored        []configRestoreArchiveFileStatus `json:"files_restored,omitempty"`
	FilesSkipped         int                              `json:"files_skipped,omitempty"`
	PrivateKeysRestored  int                              `json:"private_keys_restored,omitempty"`
	CreatedConfigLogCopy string                           `json:"created_config_log_backup,omitempty"`
}

type configValidateArchiveResponse struct {
	Valid               bool         `json:"valid"`
	Restorable          bool         `json:"restorable"`
	DomainID            string       `json:"domain_id"`
	IXID                string       `json:"ix_id"`
	Head                headResponse `json:"head"`
	Files               int          `json:"files"`
	PrivateKeysIncluded bool         `json:"private_keys_included"`
	PrivateKeyFiles     int          `json:"private_key_files"`
	RecoveryComplete    bool         `json:"recovery_complete"`
}

type configRestoreArchiveFileStatus struct {
	SourcePath  string   `json:"source_path"`
	ArchivePath string   `json:"archive_path"`
	Roles       []string `json:"roles,omitempty"`
	BackupPath  string   `json:"backup_path,omitempty"`
	PrivateKey  bool     `json:"private_key,omitempty"`
}

type parsedConfigRestoreArchive struct {
	Manifest        configExportManifest
	Snapshot        configSnapshotEnvelope
	ConfigLogEvents []configlog.Event
	Entries         map[string][]byte
}

type configRestoreArchiveCandidate struct {
	SourcePath string
	Roles      map[string]struct{}
	PrivateKey bool
}

type configRestoreFileChange struct {
	targetPath string
	backupPath string
	created    bool
}

type configSnapshotRestoreResult struct {
	head          configlog.Head
	createdBackup string
	committed     bool
}

type configRestoreMutableState struct {
	members        map[core.IXID]memberRecord
	pendingMembers map[core.IXID]pendingMemberRecord
	signerCerts    map[core.SignerID]*x509.Certificate
	localAd        advertisementResponse
	runtimeEpoch   uint64
}

type validatedConfigRestoreArchiveFile struct {
	manifest    configExportFileManifest
	archivePath string
	payload     []byte
}

func (daemon *Daemon) handleConfigValidateArchive(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, maxConfigRestoreArchiveBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	response, err := daemon.validateConfigArchive(payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	setSensitiveResponseHeaders(w)
	writeJSON(w, http.StatusOK, response)
}

func (daemon *Daemon) handleConfigRestoreArchive(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, maxConfigRestoreArchiveBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := daemon.validateConfigArchive(payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	response, err := daemon.restoreConfigArchive(r.Context(), payload)
	if err != nil {
		var committed *committedConfigMutationError
		if errors.As(err, &committed) {
			writeConfigMutationError(w, err)
		} else {
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (daemon *Daemon) restoreConfigArchive(ctx context.Context, payload []byte) (response configRestoreArchiveResponse, resultErr error) {
	archive, err := parseConfigRestoreArchive(payload)
	if err != nil {
		return configRestoreArchiveResponse{}, err
	}
	if err := daemon.validateConfigRestoreArchiveMetadata(archive); err != nil {
		return configRestoreArchiveResponse{}, err
	}
	restoredDesired, ok, err := daemon.latestLocalDesiredFromEventsWithoutRuntimeValidation(archive.Snapshot.Events)
	if err != nil {
		return configRestoreArchiveResponse{}, err
	}
	if !ok {
		return configRestoreArchiveResponse{}, fmt.Errorf("restore archive has no desired event for local IX %q", daemon.desired.IX.ID)
	}

	fileStatuses, changes, skipped, privateKeys, err := daemon.restoreConfigArchiveFiles(archive, restoredDesired)
	if err != nil {
		if rollbackErr := rollbackConfigRestoreFiles(changes); rollbackErr != nil {
			return configRestoreArchiveResponse{}, errors.Join(err, fmt.Errorf("rollback partially restored files: %w", rollbackErr))
		}
		return configRestoreArchiveResponse{}, err
	}
	commitFiles := false
	defer func() {
		if !commitFiles {
			if err := rollbackConfigRestoreFiles(changes); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("rollback restored files: %w", err))
			}
		}
	}()

	result, err := daemon.restoreConfigSnapshotFromArchive(ctx, archive.Snapshot)
	if result.committed {
		commitFiles = true
	}
	if err != nil {
		return configRestoreArchiveResponse{}, err
	}
	commitFiles = true
	return configRestoreArchiveResponse{
		Restored:             true,
		DomainID:             archive.Manifest.DomainID,
		IXID:                 archive.Manifest.IXID,
		Head:                 headResponse{Seq: result.head.Seq, Hash: result.head.Hash},
		FilesRestored:        fileStatuses,
		FilesSkipped:         skipped,
		PrivateKeysRestored:  privateKeys,
		CreatedConfigLogCopy: result.createdBackup,
	}, nil
}

func (daemon *Daemon) validateConfigArchive(payload []byte) (configValidateArchiveResponse, error) {
	archive, err := parseConfigRestoreArchive(payload)
	if err != nil {
		return configValidateArchiveResponse{}, err
	}
	if err := daemon.validateConfigRestoreArchiveMetadata(archive); err != nil {
		return configValidateArchiveResponse{}, err
	}

	var restoredDesired config.Desired
	var ok bool
	daemon.configMu.Lock()
	_, err = daemon.verifyConfigSnapshotLocked(archive.Snapshot)
	if err == nil {
		var desiredErr error
		restoredDesired, ok, desiredErr = daemon.latestLocalDesiredFromEvents(archive.Snapshot.Events)
		if desiredErr != nil {
			err = desiredErr
		} else if !ok {
			err = fmt.Errorf("restore archive has no desired event for local IX %q", daemon.desired.IX.ID)
		}
	}
	daemon.configMu.Unlock()
	if err != nil {
		return configValidateArchiveResponse{}, err
	}
	files, privateKeyFiles, err := daemon.validateConfigRestoreArchiveFiles(archive, restoredDesired)
	if err != nil {
		return configValidateArchiveResponse{}, err
	}
	return configValidateArchiveResponse{
		Valid:               true,
		Restorable:          true,
		DomainID:            archive.Manifest.DomainID,
		IXID:                archive.Manifest.IXID,
		Head:                archive.Manifest.ConfigHead,
		Files:               len(files),
		PrivateKeysIncluded: archive.Manifest.PrivateKeysIncluded,
		PrivateKeyFiles:     privateKeyFiles,
		RecoveryComplete:    archive.Manifest.PrivateKeysIncluded && archive.Manifest.PrivateKeysOmitted == 0 && privateKeyFiles > 0,
	}, nil
}

func parseConfigRestoreArchive(payload []byte) (archive parsedConfigRestoreArchive, resultErr error) {
	if len(bytes.TrimSpace(payload)) == 0 {
		return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive body is required")
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return parsedConfigRestoreArchive{}, fmt.Errorf("open restore archive gzip: %w", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close restore archive gzip: %w", err))
		}
	}()

	tarReader := tar.NewReader(gzipReader)
	entries := make(map[string][]byte)
	var total int64
	entryCount := 0
	fileCount := 0
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return parsedConfigRestoreArchive{}, fmt.Errorf("read restore archive tar: %w", err)
		}
		entryCount++
		if entryCount > maxConfigRestoreArchiveEntries {
			return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive has more than %d entries", maxConfigRestoreArchiveEntries)
		}
		if header.Typeflag == tar.TypeDir {
			if _, err := normalizeRestoreArchivePath(header.Name); err != nil {
				return parsedConfigRestoreArchive{}, err
			}
			continue
		}
		if !header.FileInfo().Mode().IsRegular() {
			return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive entry %q is not a regular file", header.Name)
		}
		fileCount++
		if fileCount > maxConfigRestoreArchiveFiles {
			return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive has more than %d files", maxConfigRestoreArchiveFiles)
		}
		name, err := normalizeRestoreArchivePath(header.Name)
		if err != nil {
			return parsedConfigRestoreArchive{}, err
		}
		if _, exists := entries[name]; exists {
			return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive has duplicate entry %q", name)
		}
		if header.Size < 0 || header.Size > maxConfigRestoreArchiveEntryBytes {
			return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive entry %q size %d exceeds %d bytes", name, header.Size, maxConfigRestoreArchiveEntryBytes)
		}
		total += header.Size
		if total > maxConfigRestoreArchiveUncompressedBytes {
			return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive uncompressed size exceeds %d bytes", maxConfigRestoreArchiveUncompressedBytes)
		}
		content, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil {
			return parsedConfigRestoreArchive{}, fmt.Errorf("read restore archive entry %q: %w", name, err)
		}
		if int64(len(content)) != header.Size {
			return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive entry %q size mismatch: read %d want %d", name, len(content), header.Size)
		}
		entries[name] = content
	}

	var manifest configExportManifest
	if err := decodeStrictJSONEntry(entries, "manifest.json", &manifest); err != nil {
		return parsedConfigRestoreArchive{}, err
	}
	var snapshot configSnapshotEnvelope
	if err := decodeStrictJSONEntry(entries, "config-snapshot.json", &snapshot); err != nil {
		return parsedConfigRestoreArchive{}, err
	}
	var desired config.Desired
	if err := decodeStrictJSONEntry(entries, "desired.json", &desired); err != nil {
		return parsedConfigRestoreArchive{}, err
	}
	desired = config.Normalize(desired)
	if string(desired.Domain.ID) != manifest.DomainID || string(desired.IX.ID) != manifest.IXID {
		return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive desired identity is domain=%q ix=%q, want domain=%q ix=%q", desired.Domain.ID, desired.IX.ID, manifest.DomainID, manifest.IXID)
	}
	logEvents, err := decodeConfigLogEventsEntry(entries["config.log"])
	if err != nil {
		return parsedConfigRestoreArchive{}, err
	}
	if len(logEvents) > 0 {
		if len(logEvents) != len(snapshot.Events) {
			return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive config.log events=%d do not match snapshot events=%d", len(logEvents), len(snapshot.Events))
		}
		logHead, err := configLogHeadForEvents(logEvents)
		if err != nil {
			return parsedConfigRestoreArchive{}, fmt.Errorf("validate restore archive config.log: %w", err)
		}
		if logHead.Seq != snapshot.Head.Seq || logHead.Hash != snapshot.Head.Hash {
			return parsedConfigRestoreArchive{}, fmt.Errorf("restore archive config.log head mismatch: log seq=%d hash=%s snapshot seq=%d hash=%s",
				logHead.Seq, logHead.Hash, snapshot.Head.Seq, snapshot.Head.Hash)
		}
	}
	if err := validateRestoreArchiveEntrySet(entries, manifest); err != nil {
		return parsedConfigRestoreArchive{}, err
	}
	if err := validateRestoreArchiveDesiredEntry(desired, snapshot.Events, manifest.IXID); err != nil {
		return parsedConfigRestoreArchive{}, err
	}
	return parsedConfigRestoreArchive{
		Manifest:        manifest,
		Snapshot:        snapshot,
		ConfigLogEvents: logEvents,
		Entries:         entries,
	}, nil
}

func validateRestoreArchiveEntrySet(entries map[string][]byte, manifest configExportManifest) error {
	allowed := map[string]struct{}{
		"manifest.json":        {},
		"desired.json":         {},
		"config-snapshot.json": {},
		"config.log":           {},
	}
	for _, file := range manifest.Files {
		archivePath, err := normalizeRestoreArchivePath(file.ArchivePath)
		if err != nil {
			return err
		}
		if _, exists := allowed[archivePath]; exists {
			return fmt.Errorf("restore archive manifest has duplicate or reserved archive path %q", archivePath)
		}
		allowed[archivePath] = struct{}{}
	}
	for name := range entries {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("restore archive contains unreferenced file %q", name)
		}
	}
	return nil
}

func validateRestoreArchiveDesiredEntry(desired config.Desired, events []configlog.Event, ixID string) error {
	resource := "/ix/" + ixID + "/desired"
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if string(event.Resource) != resource && string(event.Resource) != "/desired" {
			continue
		}
		var eventDesired config.Desired
		if err := json.Unmarshal(event.Payload, &eventDesired); err != nil {
			return fmt.Errorf("decode restore archive desired event seq %d: %w", event.Seq, err)
		}
		if !desiredConfigsEqual(desired, config.Normalize(eventDesired)) {
			return fmt.Errorf("restore archive desired.json does not match latest desired event seq %d", event.Seq)
		}
		return nil
	}
	return fmt.Errorf("restore archive has no desired event for IX %q", ixID)
}

func normalizeRestoreArchivePath(raw string) (string, error) {
	raw = strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	if raw == "" || path.IsAbs(raw) {
		return "", fmt.Errorf("invalid restore archive path %q", raw)
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", fmt.Errorf("invalid restore archive path %q", raw)
	}
	return cleaned, nil
}

func decodeStrictJSONEntry(entries map[string][]byte, name string, target any) error {
	payload, ok := entries[name]
	if !ok {
		return fmt.Errorf("restore archive missing %s", name)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode restore archive %s: %w", name, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("decode restore archive %s trailing content: %w", name, err)
	}
	return fmt.Errorf("decode restore archive %s: trailing JSON content", name)
}

func decodeConfigLogEventsEntry(payload []byte) ([]configlog.Event, error) {
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	events := make([]configlog.Event, 0)
	for {
		var event configlog.Event
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode restore archive config.log: %w", err)
		}
		events = append(events, event)
	}
	return events, nil
}

func configLogHeadForEvents(events []configlog.Event) (configlog.Head, error) {
	store := configlog.NewMemoryStore()
	if err := store.AppendBatch(events); err != nil {
		return configlog.Head{}, err
	}
	return store.Head()
}

func (daemon *Daemon) validateConfigRestoreArchiveMetadata(archive parsedConfigRestoreArchive) error {
	if archive.Manifest.Version != configExportArchiveVersion {
		return fmt.Errorf("restore archive version is %d, want %d", archive.Manifest.Version, configExportArchiveVersion)
	}
	if archive.Manifest.DomainID != string(daemon.desired.Domain.ID) {
		return fmt.Errorf("restore archive domain is %q, want %q", archive.Manifest.DomainID, daemon.desired.Domain.ID)
	}
	if archive.Manifest.IXID != string(daemon.desired.IX.ID) {
		return fmt.Errorf("restore archive ix is %q, want %q", archive.Manifest.IXID, daemon.desired.IX.ID)
	}
	if archive.Snapshot.DomainID != archive.Manifest.DomainID {
		return fmt.Errorf("restore archive snapshot domain is %q, want manifest %q", archive.Snapshot.DomainID, archive.Manifest.DomainID)
	}
	if archive.Snapshot.IXID != "" && archive.Snapshot.IXID != archive.Manifest.IXID {
		return fmt.Errorf("restore archive snapshot ix is %q, want manifest %q", archive.Snapshot.IXID, archive.Manifest.IXID)
	}
	if archive.Manifest.ConfigHead.Seq != archive.Snapshot.Head.Seq || archive.Manifest.ConfigHead.Hash != archive.Snapshot.Head.Hash {
		return fmt.Errorf("restore archive manifest head mismatch: manifest seq=%d hash=%s snapshot seq=%d hash=%s",
			archive.Manifest.ConfigHead.Seq, archive.Manifest.ConfigHead.Hash, archive.Snapshot.Head.Seq, archive.Snapshot.Head.Hash)
	}
	return nil
}

func (daemon *Daemon) latestLocalDesiredFromEventsWithoutRuntimeValidation(events []configlog.Event) (config.Desired, bool, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Resource != desiredResourceForIX(daemon.desired.IX.ID) && !daemon.eventIsLocalDesired(event, daemon.desired.IX.ID) {
			continue
		}
		var desired config.Desired
		if err := json.Unmarshal(event.Payload, &desired); err != nil {
			return config.Desired{}, false, fmt.Errorf("decode desired event seq %d: %w", event.Seq, err)
		}
		desired = config.Normalize(desired)
		if desired.Domain.ID != daemon.desired.Domain.ID {
			return config.Desired{}, false, fmt.Errorf("desired event seq %d domain is %q, want %q", event.Seq, desired.Domain.ID, daemon.desired.Domain.ID)
		}
		if desired.IX.ID != daemon.desired.IX.ID {
			return config.Desired{}, false, fmt.Errorf("desired event seq %d ix is %q, want %q", event.Seq, desired.IX.ID, daemon.desired.IX.ID)
		}
		return desired, true, nil
	}
	return config.Desired{}, false, nil
}

func (daemon *Daemon) restoreConfigArchiveFiles(archive parsedConfigRestoreArchive, restoredDesired config.Desired) ([]configRestoreArchiveFileStatus, []configRestoreFileChange, int, int, error) {
	files, _, err := daemon.validateConfigRestoreArchiveFiles(archive, restoredDesired)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	statuses := make([]configRestoreArchiveFileStatus, 0, len(files))
	changes := make([]configRestoreFileChange, 0, len(files))
	skipped := 0
	privateKeys := 0
	for _, validated := range files {
		file := validated.manifest
		backupPath, changed, err := writeConfigRestoreFile(file.SourcePath, validated.payload, file.PrivateKey)
		if changed {
			changes = append(changes, configRestoreFileChange{
				targetPath: file.SourcePath,
				backupPath: backupPath,
				created:    backupPath == "",
			})
		}
		if err != nil {
			rollbackErr := rollbackConfigRestoreFiles(changes)
			if rollbackErr != nil {
				return nil, nil, skipped, privateKeys, errors.Join(err, fmt.Errorf("rollback partially restored files: %w", rollbackErr))
			}
			return nil, nil, skipped, privateKeys, err
		}
		if !changed {
			skipped++
			continue
		}
		statuses = append(statuses, configRestoreArchiveFileStatus{
			SourcePath:  file.SourcePath,
			ArchivePath: validated.archivePath,
			Roles:       append([]string(nil), file.Roles...),
			BackupPath:  backupPath,
			PrivateKey:  file.PrivateKey,
		})
		if file.PrivateKey {
			privateKeys++
		}
	}
	return statuses, changes, skipped, privateKeys, nil
}

func (daemon *Daemon) validateConfigRestoreArchiveFiles(archive parsedConfigRestoreArchive, restoredDesired config.Desired) ([]validatedConfigRestoreArchiveFile, int, error) {
	daemon.configMu.RLock()
	currentDesired := daemon.desired
	configPath := daemon.cfg.ConfigPath
	daemon.configMu.RUnlock()

	currentCandidates := configRestoreCandidateMap(configExportFileCandidates(currentDesired, configPath))
	restoredCandidates := configRestoreCandidateMap(configExportFileCandidates(restoredDesired, configPath))
	validated := make([]validatedConfigRestoreArchiveFile, 0, len(archive.Manifest.Files))
	privateKeyFiles := 0
	for _, file := range archive.Manifest.Files {
		archivePath, err := normalizeRestoreArchivePath(file.ArchivePath)
		if err != nil {
			return nil, privateKeyFiles, err
		}
		payload, ok := archive.Entries[archivePath]
		if !ok {
			return nil, privateKeyFiles, fmt.Errorf("restore archive manifest references missing file %q", archivePath)
		}
		if err := verifyRestoreArchiveFilePayload(file, payload); err != nil {
			return nil, privateKeyFiles, err
		}
		if file.PrivateKey && !archive.Manifest.PrivateKeysIncluded {
			return nil, privateKeyFiles, fmt.Errorf("restore archive file %q is a private key but manifest private_keys_included=false", archivePath)
		}
		if !file.PrivateKey && containsPrivateKeyPEM(payload) {
			return nil, privateKeyFiles, fmt.Errorf("restore archive file %q contains private key material but is not marked private_key", archivePath)
		}

		targetKey := configExportPathKey(file.SourcePath)
		current, currentOK := currentCandidates[targetKey]
		restored, restoredOK := restoredCandidates[targetKey]
		if !currentOK || !restoredOK {
			return nil, privateKeyFiles, fmt.Errorf("restore archive file %q target %q is not allowed by current and restored config", archivePath, file.SourcePath)
		}
		if !restoreArchiveRolesAllowed(file.Roles, current) || !restoreArchiveRolesAllowed(file.Roles, restored) {
			return nil, privateKeyFiles, fmt.Errorf("restore archive file %q roles %v are not allowed for target %q", archivePath, file.Roles, file.SourcePath)
		}
		if file.PrivateKey != current.PrivateKey || file.PrivateKey != restored.PrivateKey {
			return nil, privateKeyFiles, fmt.Errorf("restore archive file %q private_key=%t does not match configured target role", archivePath, file.PrivateKey)
		}
		if file.PrivateKey {
			privateKeyFiles++
		}
		validated = append(validated, validatedConfigRestoreArchiveFile{
			manifest:    file,
			archivePath: archivePath,
			payload:     payload,
		})
	}
	return validated, privateKeyFiles, nil
}

func verifyRestoreArchiveFilePayload(file configExportFileManifest, payload []byte) error {
	if file.SizeBytes != int64(len(payload)) {
		return fmt.Errorf("restore archive file %q size mismatch: manifest=%d actual=%d", file.ArchivePath, file.SizeBytes, len(payload))
	}
	sum := sha256Bytes(payload)
	if !strings.EqualFold(file.SHA256, sum) {
		return fmt.Errorf("restore archive file %q sha256 mismatch: manifest=%s actual=%s", file.ArchivePath, file.SHA256, sum)
	}
	return nil
}

func sha256Bytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func configRestoreCandidateMap(candidates []configExportFileCandidate) map[string]configRestoreArchiveCandidate {
	result := make(map[string]configRestoreArchiveCandidate, len(candidates))
	for _, candidate := range candidates {
		sourcePath := strings.TrimSpace(candidate.SourcePath)
		if sourcePath == "" {
			continue
		}
		key := configExportPathKey(sourcePath)
		entry := result[key]
		if entry.Roles == nil {
			entry.SourcePath = sourcePath
			entry.Roles = make(map[string]struct{})
		}
		if candidate.Role != "" {
			entry.Roles[candidate.Role] = struct{}{}
		}
		entry.PrivateKey = entry.PrivateKey || candidate.PrivateKey
		result[key] = entry
	}
	return result
}

func restoreArchiveRolesAllowed(roles []string, candidate configRestoreArchiveCandidate) bool {
	if len(roles) == 0 || len(candidate.Roles) == 0 {
		return false
	}
	for _, role := range roles {
		if _, ok := candidate.Roles[role]; ok {
			return true
		}
	}
	return false
}

func containsPrivateKeyPEM(payload []byte) bool {
	return bytes.Contains(payload, []byte("PRIVATE KEY")) ||
		bytes.Contains(payload, []byte("EC PRIVATE KEY")) ||
		bytes.Contains(payload, []byte("RSA PRIVATE KEY"))
}

func writeConfigRestoreFile(targetPath string, payload []byte, privateKey bool) (backupResult string, changedResult bool, resultErr error) {
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" {
		return "", false, fmt.Errorf("restore target path is required")
	}
	mode := os.FileMode(0o644)
	if privateKey {
		mode = 0o600
	}
	exists := false
	var existingMode os.FileMode
	if info, err := os.Lstat(targetPath); err == nil {
		if !info.Mode().IsRegular() {
			return "", false, fmt.Errorf("restore target %q is not a regular file", targetPath)
		}
		exists = true
		existingMode = info.Mode().Perm()
	} else if err != nil && !os.IsNotExist(err) {
		return "", false, fmt.Errorf("stat restore target %q: %w", targetPath, err)
	}
	if exists {
		current, err := os.ReadFile(targetPath)
		if err != nil {
			return "", false, fmt.Errorf("read existing restore target %q: %w", targetPath, err)
		}
		if bytes.Equal(current, payload) && restoreFileModeEqual(existingMode, mode) {
			return "", false, nil
		}
	}
	dir := filepath.Dir(targetPath)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", false, fmt.Errorf("create restore target directory %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(targetPath)+".restore-*")
	if err != nil {
		return "", false, fmt.Errorf("create temp restore file for %q: %w", targetPath, err)
	}
	tmpPath := tmp.Name()
	tmpClosed := false
	defer func() {
		if !tmpClosed {
			if err := tmp.Close(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("close temp restore file %q: %w", tmpPath, err))
			}
		}
		if tmpPath != "" {
			if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove temp restore file %q: %w", tmpPath, err))
			}
		}
	}()
	if _, err := tmp.Write(payload); err != nil {
		return "", false, fmt.Errorf("write temp restore file %q: %w", tmpPath, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return "", false, fmt.Errorf("chmod temp restore file %q: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		return "", false, fmt.Errorf("sync temp restore file %q: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		tmpClosed = true
		return "", false, fmt.Errorf("close temp restore file %q: %w", tmpPath, err)
	}
	tmpClosed = true

	backupPath := ""
	if exists {
		backupPath, err = uniqueRestoreBackupPath(targetPath)
		if err != nil {
			return "", false, err
		}
		if err := os.Rename(targetPath, backupPath); err != nil {
			return "", false, fmt.Errorf("backup restore target %q: %w", targetPath, err)
		}
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		if backupPath != "" {
			if restoreErr := os.Rename(backupPath, targetPath); restoreErr != nil {
				return backupPath, true, errors.Join(
					fmt.Errorf("install restore target %q: %w", targetPath, err),
					fmt.Errorf("restore backup %q to %q: %w", backupPath, targetPath, restoreErr),
				)
			}
			if syncErr := syncStateDirectory(dir); syncErr != nil {
				return "", false, errors.Join(
					fmt.Errorf("install restore target %q: %w", targetPath, err),
					fmt.Errorf("sync restored backup directory %q: %w", dir, syncErr),
				)
			}
		}
		return "", false, fmt.Errorf("install restore target %q: %w", targetPath, err)
	}
	tmpPath = ""
	if err := syncStateDirectory(dir); err != nil {
		return backupPath, true, &stateFileCommitError{Err: fmt.Errorf("sync restore target directory %q: %w", dir, err)}
	}
	return backupPath, true, nil
}

func uniqueRestoreBackupPath(targetPath string) (string, error) {
	base := targetPath + ".restore-backup." + time.Now().UTC().Format("20060102T150405.000000000Z")
	for index := 0; ; index++ {
		candidate := base
		if index > 0 {
			candidate = fmt.Sprintf("%s.%d", base, index)
		}
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", fmt.Errorf("stat restore backup candidate %q: %w", candidate, err)
		}
	}
}

func rollbackConfigRestoreFiles(changes []configRestoreFileChange) error {
	var errs []error
	for i := len(changes) - 1; i >= 0; i-- {
		change := changes[i]
		if change.created {
			if err := os.Remove(change.targetPath); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove created restore target %q: %w", change.targetPath, err))
				continue
			}
			if err := syncStateDirectory(filepath.Dir(change.targetPath)); err != nil {
				errs = append(errs, fmt.Errorf("sync restore target directory for %q: %w", change.targetPath, err))
			}
			continue
		}
		if change.backupPath == "" {
			continue
		}
		if err := os.Remove(change.targetPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove restored target %q: %w", change.targetPath, err))
			continue
		}
		if err := os.Rename(change.backupPath, change.targetPath); err != nil {
			errs = append(errs, fmt.Errorf("restore backup %q to %q: %w", change.backupPath, change.targetPath, err))
			continue
		}
		if err := syncStateDirectory(filepath.Dir(change.targetPath)); err != nil {
			errs = append(errs, fmt.Errorf("sync restore target directory for %q: %w", change.targetPath, err))
		}
	}
	return errors.Join(errs...)
}

func (daemon *Daemon) restoreConfigSnapshotFromArchive(ctx context.Context, snapshot configSnapshotEnvelope) (configSnapshotRestoreResult, error) {
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()
	if daemon.store == nil {
		return configSnapshotRestoreResult{}, fmt.Errorf("config log store is not initialized")
	}
	usedSigners, err := daemon.verifyConfigSnapshotLocked(snapshot)
	if err != nil {
		return configSnapshotRestoreResult{}, err
	}
	restoredDesired, ok, err := daemon.latestLocalDesiredFromEvents(snapshot.Events)
	if err != nil {
		return configSnapshotRestoreResult{}, err
	}
	if !ok {
		return configSnapshotRestoreResult{}, fmt.Errorf("restore archive has no desired event for local IX %q", daemon.desired.IX.ID)
	}

	oldDesired := daemon.desired
	oldHead := daemon.head
	oldDomain := daemon.cfg.DomainID
	oldIX := daemon.cfg.IXID
	oldFlows := daemon.snapshotFlows()
	oldState := daemon.snapshotConfigRestoreMutableState()
	storeHead, err := daemon.store.Head()
	if err != nil {
		return configSnapshotRestoreResult{}, fmt.Errorf("read config log before restore: %w", err)
	}
	if storeHead != oldHead {
		return configSnapshotRestoreResult{}, fmt.Errorf("config log head changed before restore: runtime=%+v store=%+v", oldHead, storeHead)
	}
	oldEvents, err := configLogEventsThroughHead(daemon.store, storeHead)
	if err != nil {
		return configSnapshotRestoreResult{}, fmt.Errorf("snapshot current config log before restore: %w", err)
	}
	archiveHead := configlog.Head{Seq: snapshot.Head.Seq, Hash: snapshot.Head.Hash}
	if err := daemon.switchDesiredRuntime(ctx, restoredDesired, archiveHead); err != nil {
		return configSnapshotRestoreResult{}, err
	}
	var commitErr error
	if err := daemon.store.ReplaceAll(snapshot.Events); err != nil {
		if configlog.CommitSucceeded(err) {
			commitErr = err
		} else {
			restoreErr := daemon.restoreDesiredRuntimeState(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows)
			if restoreErr != nil {
				return configSnapshotRestoreResult{}, errors.Join(
					fmt.Errorf("replace config log from restore archive: %w", err),
					fmt.Errorf("restore previous runtime: %w", restoreErr),
				)
			}
			return configSnapshotRestoreResult{}, fmt.Errorf("replace config log from restore archive: %w", err)
		}
	}
	result := configSnapshotRestoreResult{
		head:          archiveHead,
		createdBackup: latestConfigLogBackupPath(daemon.logPath),
		committed:     true,
	}
	head, err := daemon.store.Head()
	if err != nil {
		return daemon.rollbackFailedConfigSnapshotRestore(ctx, "config restore", result, fmt.Errorf("read restored config log head: %w", err), oldEvents, oldDesired, oldHead, oldDomain, oldIX, oldFlows, oldState)
	}
	result.head = head
	if _, err := daemon.applyLatestDomainTrustFromLogLocked(ctx); err != nil {
		return daemon.rollbackFailedConfigSnapshotRestore(ctx, "config restore", result, err, oldEvents, oldDesired, oldHead, oldDomain, oldIX, oldFlows, oldState)
	}
	if err := daemon.afterAdmissionStateChangedLocked(ctx); err != nil {
		return daemon.rollbackFailedConfigSnapshotRestore(ctx, "config restore", result, err, oldEvents, oldDesired, oldHead, oldDomain, oldIX, oldFlows, oldState)
	}
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		return daemon.rollbackFailedConfigSnapshotRestore(ctx, "config restore", result, err, oldEvents, oldDesired, oldHead, oldDomain, oldIX, oldFlows, oldState)
	}
	if err := daemon.commitConfigSignerCertificates(usedSigners, true); err != nil {
		return daemon.rollbackFailedConfigSnapshotRestore(ctx, "config restore", result, err, oldEvents, oldDesired, oldHead, oldDomain, oldIX, oldFlows, oldState)
	}
	if commitErr != nil {
		daemon.requestRuntimeReconcile("config restore durability", commitErr)
		return result, newCommittedConfigMutationError("config restore", commitErr)
	}
	return result, nil
}

func configLogEventsThroughHead(store configlog.Store, head configlog.Head) ([]configlog.Event, error) {
	if head.Seq == 0 {
		return nil, nil
	}
	return store.Range(1, head.Seq)
}

func (daemon *Daemon) snapshotConfigRestoreMutableState() configRestoreMutableState {
	state := configRestoreMutableState{}
	daemon.membershipMu.RLock()
	state.members = make(map[core.IXID]memberRecord, len(daemon.members))
	for id, record := range daemon.members {
		state.members[id] = record
	}
	state.pendingMembers = make(map[core.IXID]pendingMemberRecord, len(daemon.pendingMembers))
	for id, record := range daemon.pendingMembers {
		state.pendingMembers[id] = record
	}
	state.localAd = daemon.localAd
	state.runtimeEpoch = daemon.runtimeEpoch
	daemon.membershipMu.RUnlock()

	daemon.signerMu.RLock()
	state.signerCerts = make(map[core.SignerID]*x509.Certificate, len(daemon.signerCerts))
	for id, certificate := range daemon.signerCerts {
		state.signerCerts[id] = certificate
	}
	daemon.signerMu.RUnlock()
	return state
}

func (daemon *Daemon) restoreConfigRestoreMutableState(state configRestoreMutableState) error {
	daemon.membershipMu.Lock()
	daemon.members = state.members
	daemon.pendingMembers = state.pendingMembers
	daemon.localAd = state.localAd
	daemon.runtimeEpoch = state.runtimeEpoch
	daemon.membershipMu.Unlock()

	daemon.signerMu.Lock()
	daemon.signerCerts = state.signerCerts
	daemon.signerMu.Unlock()

	return errors.Join(
		wrapRestoreError("persist previous members", daemon.persistMembers()),
		wrapRestoreError("persist previous pending members", daemon.persistPendingMembers()),
		wrapRestoreError("persist previous config signer cache", daemon.persistConfigSignerCache()),
	)
}

func wrapRestoreError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (daemon *Daemon) rollbackFailedConfigSnapshotRestore(
	ctx context.Context,
	operation string,
	result configSnapshotRestoreResult,
	cause error,
	oldEvents []configlog.Event,
	oldDesired config.Desired,
	oldHead configlog.Head,
	oldDomain core.DomainID,
	oldIX core.IXID,
	oldFlows map[routing.FlowKey]routing.FlowBinding,
	oldState configRestoreMutableState,
) (configSnapshotRestoreResult, error) {
	replaceErr := daemon.store.ReplaceAll(oldEvents)
	if replaceErr != nil && !configlog.CommitSucceeded(replaceErr) {
		err := errors.Join(
			cause,
			fmt.Errorf("rollback previous config log: %w", replaceErr),
		)
		daemon.requestRuntimeReconcile(operation+" rollback", err)
		return result, newCommittedConfigMutationError(operation, err)
	}
	stateErr := daemon.restoreConfigRestoreMutableState(oldState)
	runtimeErr := daemon.restoreDesiredRuntimeState(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows)
	rollbackErr := errors.Join(
		wrapRestoreError("rollback previous config log durability", replaceErr),
		stateErr,
		wrapRestoreError("restore previous runtime", runtimeErr),
	)
	if rollbackErr != nil {
		daemon.requestRuntimeReconcile(operation+" rollback", rollbackErr)
		return configSnapshotRestoreResult{}, errors.Join(cause, fmt.Errorf("restore rollback incomplete: %w", rollbackErr))
	}
	return configSnapshotRestoreResult{}, fmt.Errorf("restore failed and was rolled back: %w", cause)
}
