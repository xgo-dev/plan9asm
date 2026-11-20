package gotoolprofile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAMD64LegacyDownloadMetadataKeepsDependencyRole(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(t.TempDir(), "legacy.mod")
	member := filepath.Join(root, "go.mod")
	for _, name := range []string{metadata, member} {
		if err := os.WriteFile(name, []byte("module example.invalid/legacy\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	metadata, err = filepath.EvalSymlinks(metadata)
	if err != nil {
		t.Fatal(err)
	}
	// This checks only the role predicate, not authenticated ZIP observation.
	source := &amd64DownloadedModule{root: root, modulePath: "example.invalid/legacy",
		sourceModule: "example.invalid/legacy", sourceVersion: "v1.0.0", goMod: metadata,
		goModOrigin: ProxyGoModProtocol}
	actual := &amd64OriginalListModule{Path: source.modulePath, Version: source.sourceVersion, Dir: root, GoMod: metadata}
	if !source.matches(actual, false) {
		t.Fatal("exact dependency metadata was lost")
	}
	actual.GoMod = member
	if source.matches(actual, false) {
		t.Fatal("external proxy metadata was relabeled as an original ZIP member")
	}
	actual.GoMod, actual.Main, actual.Version, actual.GoVersion = metadata, true, "", "1.16"
	if source.matches(actual, true) {
		t.Fatal("legacy dependency borrowed a cache-CWD main role")
	}
}
