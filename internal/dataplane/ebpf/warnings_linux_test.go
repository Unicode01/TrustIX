//go:build linux

package ebpf

import (
	"fmt"
	"testing"
)

func TestAppendManagerWarningDeduplicatesAndTrims(t *testing.T) {
	warnings := appendManagerWarning(nil, "  first warning  ")
	warnings = appendManagerWarning(warnings, "first warning")
	warnings = appendManagerWarning(warnings, "   ")
	if len(warnings) != 1 || warnings[0] != "first warning" {
		t.Fatalf("deduplicated warnings = %#v", warnings)
	}
}

func TestAppendManagerWarningBoundsOldestEntries(t *testing.T) {
	var warnings []string
	for i := 0; i < managerWarningLimit+10; i++ {
		warnings = appendManagerWarning(warnings, fmt.Sprintf("warning-%03d", i))
	}
	if len(warnings) != managerWarningLimit {
		t.Fatalf("warning count = %d, want %d", len(warnings), managerWarningLimit)
	}
	if warnings[0] != "warning-010" || warnings[len(warnings)-1] != "warning-265" {
		t.Fatalf("bounded warning range = %q .. %q", warnings[0], warnings[len(warnings)-1])
	}
}
