package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trustix.local/trustix/internal/configlog"
	iptunneltransport "trustix.local/trustix/internal/transport/iptunnel"
)

type stateFilesStatus struct {
	Files []stateFileStatus `json:"files"`
}

type stateFileStatus struct {
	Name                    string    `json:"name"`
	Path                    string    `json:"path,omitempty"`
	Exists                  bool      `json:"exists"`
	SizeBytes               int64     `json:"size_bytes,omitempty"`
	ModifiedAt              time.Time `json:"modified_at,omitempty"`
	Mode                    string    `json:"mode,omitempty"`
	Status                  string    `json:"status"`
	Detail                  string    `json:"detail,omitempty"`
	Records                 int       `json:"records,omitempty"`
	ExpiredRecords          int       `json:"expired_records,omitempty"`
	Backups                 int       `json:"backups,omitempty"`
	BackupKeep              int       `json:"backup_keep,omitempty"`
	BackupOverLimit         bool      `json:"backup_over_limit,omitempty"`
	EarliestExpiry          time.Time `json:"earliest_expiry,omitempty"`
	LatestExpiry            time.Time `json:"latest_expiry,omitempty"`
	QuarantinedCandidates   int       `json:"quarantined_candidates,omitempty"`
	WorldReadableOrWritable bool      `json:"world_readable_or_writable,omitempty"`
}

func writeStateFileAtomic(path string, payload []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (daemon *Daemon) stateFilesStatus() stateFilesStatus {
	files := []stateFileStatus{
		daemon.configLogFileStatus(),
		daemon.membersFileStatus(),
		daemon.pendingMembersFileStatus(),
		daemon.ipTunnelStateFileStatus(),
	}
	return stateFilesStatus{Files: files}
}

func (daemon *Daemon) stateFilesDoctorCheck() doctorCheck {
	status := daemon.stateFilesStatus()
	worst := "ok"
	details := make([]string, 0, len(status.Files))
	for _, file := range status.Files {
		switch file.Status {
		case "degraded":
			worst = "degraded"
		case "warn":
			if worst == "ok" {
				worst = "warn"
			}
		}
		detail := fmt.Sprintf("%s status=%s exists=%t", file.Name, file.Status, file.Exists)
		if file.Path != "" {
			detail += " path=" + file.Path
		}
		if file.Records > 0 {
			detail += fmt.Sprintf(" records=%d", file.Records)
		}
		if file.ExpiredRecords > 0 {
			detail += fmt.Sprintf(" expired=%d", file.ExpiredRecords)
		}
		if file.Backups > 0 {
			detail += fmt.Sprintf(" backups=%d", file.Backups)
		}
		if file.BackupKeep > 0 {
			detail += fmt.Sprintf(" backup_keep=%d", file.BackupKeep)
		}
		if file.BackupOverLimit {
			detail += " backup_over_limit=true"
		}
		if file.Detail != "" {
			detail += " detail=" + file.Detail
		}
		details = append(details, detail)
	}
	return doctorCheck{Name: "state_files", Status: worst, Detail: joinDetails(details)}
}

func (daemon *Daemon) configLogFileStatus() stateFileStatus {
	status := inspectStateFile("config_log", daemon.logPath)
	backupKeep := configlog.BackupKeepFromEnv()
	status.BackupKeep = backupKeep
	backups, backupErr := configLogBackups(daemon.logPath)
	if backupErr == nil {
		status.Backups = len(backups)
		if backupKeep > 0 && len(backups) > backupKeep {
			status.BackupOverLimit = true
			if status.Status == "ok" {
				status.Status = "warn"
				status.Detail = fmt.Sprintf("backup count %d exceeds retention %d", len(backups), backupKeep)
			} else if status.Detail == "" {
				status.Detail = fmt.Sprintf("backup count %d exceeds retention %d", len(backups), backupKeep)
			}
		}
	} else if status.Detail == "" {
		status.Status = "warn"
		status.Detail = backupErr.Error()
	}
	preVerifyDetail := status.Detail
	if !status.Exists || status.Status == "degraded" {
		return status
	}
	verify := daemon.verifyCurrentConfigLog()
	if !verify.Valid {
		status.Status = "degraded"
		status.Detail = verify.Error
		return status
	}
	status.Records = verify.Events
	detail := fmt.Sprintf("head_seq=%d backups=%d backup_keep=%d verify=ok", verify.Head.Seq, len(verify.Backups), backupKeep)
	if status.BackupOverLimit {
		detail += fmt.Sprintf("; backup count %d exceeds retention %d", status.Backups, backupKeep)
	}
	if preVerifyDetail != "" && !strings.Contains(detail, preVerifyDetail) {
		detail += "; " + preVerifyDetail
	}
	status.Detail = detail
	return status
}

func (daemon *Daemon) membersFileStatus() stateFileStatus {
	status := inspectStateFile("members", daemon.membershipStatePath())
	if !status.Exists || status.Status == "degraded" {
		return status
	}
	var state persistedMembers
	if err := decodeJSONFile(status.Path, &state); err != nil {
		status.Status = "warn"
		status.Detail = err.Error()
		return status
	}
	status.Records = len(state.Members)
	expired := 0
	now := time.Now().UTC()
	for _, record := range state.Members {
		if record.LastSeen.IsZero() || now.Sub(record.LastSeen) > memberRecordTTL {
			expired++
		}
	}
	status.ExpiredRecords = expired
	if expired > 0 && status.Status == "ok" {
		status.Status = "warn"
		status.Detail = "contains expired member record(s)"
	}
	return status
}

func (daemon *Daemon) pendingMembersFileStatus() stateFileStatus {
	status := inspectStateFile("pending_members", daemon.pendingMembershipStatePath())
	if !status.Exists || status.Status == "degraded" {
		return status
	}
	var state persistedPendingMembers
	if err := decodeJSONFile(status.Path, &state); err != nil {
		status.Status = "warn"
		status.Detail = err.Error()
		return status
	}
	status.Records = len(state.Pending)
	now := time.Now().UTC()
	expired := 0
	for _, record := range state.Pending {
		expiresAt := record.LastSeen.Add(pendingMemberTTL).UTC()
		if record.LastSeen.IsZero() || !expiresAt.After(now) {
			expired++
		}
		if !expiresAt.IsZero() {
			if status.EarliestExpiry.IsZero() || expiresAt.Before(status.EarliestExpiry) {
				status.EarliestExpiry = expiresAt
			}
			if status.LatestExpiry.IsZero() || expiresAt.After(status.LatestExpiry) {
				status.LatestExpiry = expiresAt
			}
		}
	}
	status.ExpiredRecords = expired
	if expired > 0 && status.Status == "ok" {
		status.Status = "warn"
		status.Detail = "contains expired pending admission record(s)"
	}
	return status
}

func (daemon *Daemon) ipTunnelStateFileStatus() stateFileStatus {
	path := filepath.Join(daemon.cfg.DataDir, "iptunnel", "state.json")
	status := inspectStateFile("iptunnel", path)
	if !status.Exists || status.Status == "degraded" {
		return status
	}
	records, err := iptunneltransport.NewManager(daemon.cfg.DataDir).Plan(context.Background())
	if err != nil {
		status.Status = "warn"
		status.Detail = err.Error()
		return status
	}
	status.Records = len(records)
	activeRefs := 0
	for _, record := range records {
		if record.RefCount > 0 {
			activeRefs += record.RefCount
		} else {
			activeRefs++
		}
	}
	status.Detail = fmt.Sprintf("active_tunnels=%d active_refs=%d", len(records), activeRefs)
	return status
}

func inspectStateFile(name, path string) stateFileStatus {
	status := stateFileStatus{Name: name, Path: path, Status: "ok"}
	if path == "" {
		status.Status = "warn"
		status.Detail = "path is not configured"
		return status
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			status.Exists = false
			status.QuarantinedCandidates = countQuarantinedStateFiles(path)
			status.Detail = "file does not exist"
			if status.QuarantinedCandidates > 0 {
				status.Status = "warn"
				status.Detail = fmt.Sprintf("file does not exist; %d quarantined bad file(s) exist", status.QuarantinedCandidates)
			}
			return status
		}
		status.Status = "degraded"
		status.Detail = err.Error()
		return status
	}
	status.Exists = true
	status.SizeBytes = info.Size()
	status.ModifiedAt = info.ModTime().UTC()
	status.Mode = info.Mode().Perm().String()
	if info.IsDir() {
		status.Status = "degraded"
		status.Detail = "path is a directory"
		return status
	}
	if info.Mode().Perm()&0o077 != 0 {
		status.Status = "warn"
		status.WorldReadableOrWritable = true
		status.Detail = fmt.Sprintf("permissions %s are broader than 0600", info.Mode().Perm())
	}
	status.QuarantinedCandidates = countQuarantinedStateFiles(path)
	if status.QuarantinedCandidates > 0 && status.Status == "ok" {
		status.Status = "warn"
		status.Detail = fmt.Sprintf("%d quarantined bad file(s) exist", status.QuarantinedCandidates)
	}
	return status
}

func decodeJSONFile(path string, target any) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(payload))) == 0 {
		return fmt.Errorf("file is empty")
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("decode %q: %w", path, err)
	}
	return nil
}

func quarantineBadStateFile(path string, cause error) (string, error) {
	if path == "" {
		return "", nil
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	base := path + ".bad." + time.Now().UTC().Format("20060102T150405.000000000Z")
	target := base
	for i := 1; ; i++ {
		if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
			break
		}
		target = fmt.Sprintf("%s.%d", base, i)
	}
	if err := os.Rename(path, target); err != nil {
		return "", fmt.Errorf("quarantine bad state file %q after %v: %w", path, cause, err)
	}
	return target, nil
}

func countQuarantinedStateFiles(path string) int {
	if path == "" {
		return 0
	}
	matches, err := filepath.Glob(path + ".bad.*")
	if err != nil {
		return 0
	}
	return len(matches)
}
