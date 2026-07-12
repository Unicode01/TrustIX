package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReleaseLinuxDisablesGoVCSStamping(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "build-release-linux.sh"))
	if err != nil {
		t.Fatalf("read build-release-linux.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		`"$go_bin" build -buildvcs=false -overlay`,
		`"$go_bin" build -buildvcs=false -trimpath`,
		`"$go_bin" test -c -buildvcs=false -overlay`,
		`"$go_bin" test -c -buildvcs=false -ldflags`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("build-release-linux.sh should disable Go VCS stamping with %q", want)
		}
	}
}

func TestBuildReleaseLinuxPackagesPythonScriptDependencies(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "build-release-linux.sh"))
	if err != nil {
		t.Fatalf("read build-release-linux.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		`for script_src in "${repo_root}"/scripts/*.py`,
		`copy_file "$script_src" "${pkg_dir}/scripts/${script_name}" 0755`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("build-release-linux.sh should package Python script dependencies with %q", want)
		}
	}
}
