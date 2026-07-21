package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRuntimeProfilesWritePrivateFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(runtimeProfileDirEnv, dir)
	t.Setenv(mutexProfileFractionEnv, "1")
	t.Setenv(blockProfileRateEnv, "1")

	stop := startRuntimeProfilesFromEnv()
	stop()

	for _, component := range []string{"heap", "mutex", "block"} {
		matches, err := filepath.Glob(filepath.Join(dir, "trustixd-*-"+component+".pprof"))
		if err != nil {
			t.Fatalf("glob %s profile: %v", component, err)
		}
		if len(matches) != 1 {
			t.Fatalf("%s profiles = %v, want one", component, matches)
		}
		info, err := os.Stat(matches[0])
		if err != nil {
			t.Fatalf("stat %s profile: %v", component, err)
		}
		if info.Size() == 0 {
			t.Fatalf("%s profile is empty", component)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s profile mode = %o, want 600", component, info.Mode().Perm())
		}
	}
}

func TestProfileRateFromEnvRejectsInvalidValues(t *testing.T) {
	const name = "TRUSTIX_TEST_PROFILE_RATE"
	for _, value := range []string{"", "0", "-1", "invalid"} {
		t.Setenv(name, value)
		if got := profileRateFromEnv(name); got != 0 {
			t.Fatalf("profile rate for %q = %d, want 0", value, got)
		}
	}
	t.Setenv(name, "17")
	if got := profileRateFromEnv(name); got != 17 {
		t.Fatalf("profile rate = %d, want 17", got)
	}
}
