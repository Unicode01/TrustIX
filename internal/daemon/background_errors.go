package daemon

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type backgroundErrorStatus struct {
	Operation string    `json:"operation"`
	Error     string    `json:"error"`
	Count     uint64    `json:"count"`
	LastAt    time.Time `json:"last_at"`
}

const backgroundErrorStatusLimit = 1024

func (daemon *Daemon) recordBackgroundError(operation string, err error) {
	if daemon == nil || err == nil {
		return
	}
	operation = strings.TrimSpace(operation)
	if operation == "" {
		operation = "background_operation"
	}
	daemon.backgroundMu.Lock()
	if daemon.backgroundErrors == nil {
		daemon.backgroundErrors = make(map[string]backgroundErrorStatus)
	}
	if _, exists := daemon.backgroundErrors[operation]; !exists && len(daemon.backgroundErrors) >= backgroundErrorStatusLimit {
		oldestOperation := ""
		var oldestAt time.Time
		for candidate, status := range daemon.backgroundErrors {
			if oldestOperation == "" || status.LastAt.Before(oldestAt) {
				oldestOperation = candidate
				oldestAt = status.LastAt
			}
		}
		delete(daemon.backgroundErrors, oldestOperation)
	}
	status := daemon.backgroundErrors[operation]
	status.Operation = operation
	status.Error = err.Error()
	status.Count++
	status.LastAt = time.Now().UTC()
	daemon.backgroundErrors[operation] = status
	daemon.backgroundMu.Unlock()
}

func (daemon *Daemon) clearBackgroundErrorsWithPrefix(prefix string) {
	if daemon == nil {
		return
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return
	}
	daemon.backgroundMu.Lock()
	for operation := range daemon.backgroundErrors {
		if strings.HasPrefix(operation, prefix) {
			delete(daemon.backgroundErrors, operation)
		}
	}
	daemon.backgroundMu.Unlock()
}

func (daemon *Daemon) clearBackgroundError(operation string) {
	if daemon == nil {
		return
	}
	daemon.backgroundMu.Lock()
	delete(daemon.backgroundErrors, strings.TrimSpace(operation))
	daemon.backgroundMu.Unlock()
}

func (daemon *Daemon) backgroundErrorSnapshot() []backgroundErrorStatus {
	if daemon == nil {
		return nil
	}
	daemon.backgroundMu.Lock()
	statuses := make([]backgroundErrorStatus, 0, len(daemon.backgroundErrors))
	for _, status := range daemon.backgroundErrors {
		statuses = append(statuses, status)
	}
	daemon.backgroundMu.Unlock()
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Operation < statuses[j].Operation
	})
	return statuses
}

func (daemon *Daemon) backgroundErrorsDoctorCheck() doctorCheck {
	statuses := daemon.backgroundErrorSnapshot()
	if len(statuses) == 0 {
		return doctorCheck{Name: "background_errors", Status: "ok", Detail: "no active background errors"}
	}
	details := make([]string, 0, len(statuses))
	for _, status := range statuses {
		details = append(details, fmt.Sprintf("%s(count=%d): %s", status.Operation, status.Count, status.Error))
	}
	return doctorCheck{Name: "background_errors", Status: "degraded", Detail: strings.Join(details, "; ")}
}

func wrapOperationError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (daemon *Daemon) observeDataSessionCleanupError(operation string, err error) error {
	err = wrapOperationError(operation, err)
	if err == nil {
		return nil
	}
	daemon.recordBackgroundError("data_session_cleanup", err)
	daemon.requestRuntimeReconcile("data session cleanup", err)
	return err
}

func (daemon *Daemon) recordDataSessionCleanupError(operation string, err error) {
	err = wrapOperationError(operation, err)
	if err == nil {
		return
	}
	daemon.recordBackgroundError("data_session_cleanup", err)
	daemon.requestRuntimeReconcile("data session cleanup", err)
}
