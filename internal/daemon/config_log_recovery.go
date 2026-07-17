package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
)

type configLogVerifyResponse struct {
	Valid       bool                    `json:"valid"`
	Path        string                  `json:"path,omitempty"`
	Head        headResponse            `json:"head"`
	Events      int                     `json:"events"`
	DomainID    core.DomainID           `json:"domain_id,omitempty"`
	FirstSeq    uint64                  `json:"first_seq,omitempty"`
	LastSeq     uint64                  `json:"last_seq,omitempty"`
	Resources   map[string]int          `json:"resources,omitempty"`
	Signers     map[string]int          `json:"signers,omitempty"`
	Backups     []configLogBackupStatus `json:"backups,omitempty"`
	GeneratedAt time.Time               `json:"generated_at"`
	Error       string                  `json:"error,omitempty"`
}

type configLogBackupStatus struct {
	Path       string       `json:"path"`
	SizeBytes  int64        `json:"size_bytes"`
	ModifiedAt time.Time    `json:"modified_at"`
	Head       headResponse `json:"head,omitempty"`
	Events     int          `json:"events,omitempty"`
	Valid      bool         `json:"valid"`
	Error      string       `json:"error,omitempty"`
}

type configRestoreBackupRequest struct {
	Path string `json:"path"`
}

type configRestoreBackupResponse struct {
	Restored bool                    `json:"restored"`
	Backup   string                  `json:"backup"`
	Created  string                  `json:"created_backup,omitempty"`
	Head     headResponse            `json:"head"`
	Verify   configLogVerifyResponse `json:"verify"`
}

func (daemon *Daemon) verifyCurrentConfigLog() configLogVerifyResponse {
	daemon.configMu.RLock()
	path := daemon.logPath
	store := daemon.store
	daemon.configMu.RUnlock()
	result := configLogVerifyResponse{
		Path:        path,
		Resources:   make(map[string]int),
		Signers:     make(map[string]int),
		GeneratedAt: time.Now().UTC(),
	}
	backups, err := configLogBackups(path)
	if err == nil {
		result.Backups = backups
	} else {
		result.Error = err.Error()
	}
	if store == nil {
		result.Valid = false
		if result.Error == "" {
			result.Error = "config log store is not initialized"
		}
		return result
	}
	daemon.configMu.RLock()
	verifyErr := daemon.verifyConfigLogStoreLocked(store, &result)
	daemon.configMu.RUnlock()
	if verifyErr != nil {
		result.Valid = false
		if result.Error == "" {
			result.Error = verifyErr.Error()
		}
		return result
	}
	result.Valid = result.Error == ""
	return result
}

func (daemon *Daemon) verifyConfigLogStoreLocked(store configlog.Store, result *configLogVerifyResponse) error {
	head, err := store.Head()
	if err != nil {
		return err
	}
	result.Head = headResponse{Seq: head.Seq, Hash: head.Hash}
	result.Events = int(head.Seq)
	if head.Seq == 0 {
		return nil
	}
	events, err := store.Range(1, head.Seq)
	if err != nil {
		return err
	}
	result.FirstSeq = events[0].Seq
	result.LastSeq = events[len(events)-1].Seq
	result.DomainID = events[0].DomainID
	for _, event := range events {
		result.Resources[string(event.Resource)]++
		result.Signers[string(event.SignerID)]++
	}
	return daemon.verifyExistingConfigLog(store, daemon.desired)
}

func (daemon *Daemon) restoreConfigLogBackup(ctx context.Context, backupPath string) (configRestoreBackupResponse, error) {
	backupPath = strings.TrimSpace(backupPath)
	if backupPath == "" {
		return configRestoreBackupResponse{}, newConfigMutationRequestError(fmt.Errorf("backup path is required"))
	}
	info, err := os.Stat(backupPath)
	if err != nil {
		return configRestoreBackupResponse{}, newConfigMutationRequestError(fmt.Errorf("stat backup %q: %w", backupPath, err))
	}
	if info.IsDir() {
		return configRestoreBackupResponse{}, newConfigMutationRequestError(fmt.Errorf("backup %q is a directory", backupPath))
	}
	store, err := configlog.NewFileStore(backupPath)
	if err != nil {
		return configRestoreBackupResponse{}, newConfigMutationRequestError(fmt.Errorf("load backup config log %q: %w", backupPath, err))
	}

	daemon.configMu.Lock()
	verify := configLogVerifyResponse{
		Path:        backupPath,
		Resources:   make(map[string]int),
		Signers:     make(map[string]int),
		GeneratedAt: time.Now().UTC(),
	}
	if err := daemon.verifyConfigLogStoreLocked(store, &verify); err != nil {
		daemon.configMu.Unlock()
		verify.Valid = false
		verify.Error = err.Error()
		return configRestoreBackupResponse{Backup: backupPath, Verify: verify}, newConfigMutationRequestError(err)
	}
	domainID := daemon.desired.Domain.ID
	ixID := daemon.desired.IX.ID
	daemon.configMu.Unlock()
	verify.Valid = true
	var events []configlog.Event
	if verify.Events > 0 {
		events, err = store.Range(1, uint64(verify.Events))
		if err != nil {
			return configRestoreBackupResponse{Backup: backupPath, Verify: verify}, newConfigMutationRequestError(err)
		}
	}
	backupHead, err := store.Head()
	if err != nil {
		return configRestoreBackupResponse{Backup: backupPath, Verify: verify}, newConfigMutationRequestError(err)
	}
	result, err := daemon.restoreConfigSnapshotFromArchive(ctx, configSnapshotEnvelope{
		DomainID:    string(domainID),
		IXID:        string(ixID),
		Head:        headResponse{Seq: backupHead.Seq, Hash: backupHead.Hash},
		Events:      events,
		GeneratedAt: time.Now().UTC(),
	})
	if err != nil {
		return configRestoreBackupResponse{Backup: backupPath, Verify: verify}, err
	}
	return configRestoreBackupResponse{
		Restored: true,
		Backup:   backupPath,
		Created:  result.createdBackup,
		Head:     headResponse{Seq: result.head.Seq, Hash: result.head.Hash},
		Verify:   verify,
	}, nil
}

func (daemon *Daemon) restoreLatestLocalDesiredFromLogLocked(ctx context.Context) error {
	if daemon.store == nil {
		return nil
	}
	head, err := daemon.store.Head()
	if err != nil || head.Seq == 0 {
		return err
	}
	events, err := daemon.store.Range(1, head.Seq)
	if err != nil {
		return err
	}
	restoredDesired, ok, err := daemon.latestLocalDesiredFromEvents(events)
	if err != nil || !ok {
		return err
	}
	if desiredConfigsEqual(daemon.desired, restoredDesired) {
		return nil
	}
	if _, err := daemon.ensureKernelModules(ctx, restoredDesired); err != nil {
		return err
	}
	daemon.setRuntimeDesired(restoredDesired, head)
	return nil
}

func (daemon *Daemon) latestLocalDesiredFromEvents(events []configlog.Event) (config.Desired, bool, error) {
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
		if err := daemon.validateDesiredForRuntime(desired); err != nil {
			return config.Desired{}, false, fmt.Errorf("validate desired event seq %d: %w", event.Seq, err)
		}
		return desired, true, nil
	}
	return config.Desired{}, false, nil
}

func configLogBackups(logPath string) ([]configLogBackupStatus, error) {
	if logPath == "" {
		return nil, nil
	}
	matches, err := configlog.BackupFiles(logPath)
	if err != nil {
		return nil, err
	}
	backups := make([]configLogBackupStatus, 0, len(matches))
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			backups = append(backups, configLogBackupStatus{Path: path, Valid: false, Error: err.Error()})
			continue
		}
		status := configLogBackupStatus{Path: path, SizeBytes: info.Size(), ModifiedAt: info.ModTime().UTC()}
		store, err := configlog.NewFileStore(path)
		if err != nil {
			status.Valid = false
			status.Error = err.Error()
			backups = append(backups, status)
			continue
		}
		head, err := store.Head()
		if err != nil {
			status.Valid = false
			status.Error = err.Error()
			backups = append(backups, status)
			continue
		}
		status.Valid = true
		status.Head = headResponse{Seq: head.Seq, Hash: head.Hash}
		status.Events = int(head.Seq)
		backups = append(backups, status)
	}
	return backups, nil
}

func latestConfigLogBackupPath(logPath string) string {
	backups, err := configLogBackups(logPath)
	if err != nil || len(backups) == 0 {
		return ""
	}
	return backups[len(backups)-1].Path
}
