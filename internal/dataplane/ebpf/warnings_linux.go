//go:build linux

package ebpf

import "strings"

const managerWarningLimit = 256

func appendManagerWarning(warnings []string, warning string) []string {
	warning = strings.TrimSpace(warning)
	if warning == "" {
		return warnings
	}
	for _, existing := range warnings {
		if existing == warning {
			return warnings
		}
	}
	if len(warnings) >= managerWarningLimit {
		start := len(warnings) - managerWarningLimit + 1
		copy(warnings, warnings[start:])
		warnings = warnings[:managerWarningLimit-1]
	}
	return append(warnings, warning)
}
