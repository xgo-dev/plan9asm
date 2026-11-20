package plan9asm

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Match concrete home-directory paths, not repository-relative paths or
// placeholders. Deployment-specific values belong in untracked configuration.
var personalWorkspacePath = regexp.MustCompile(`(?:/(?:Users|home)/[[:alnum:]_.-]+/|[A-Za-z]:[\\/]+Users[\\/]+[[:alnum:]_.-]+[\\/]|~/(?:source|src|workspace|projects)/)`)

func TestRepositoryDoesNotEmbedPersonalWorkspacePaths(t *testing.T) {
	err := filepath.WalkDir(".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "_out", "vendor", "node_modules", "bin", "data":
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(name) {
		case ".go", ".md", ".sh", ".yml", ".yaml", ".json", ".jsonl", ".toml", ".txt", ".ps1", ".plist", ".in":
		default:
			return nil
		}
		contents, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(contents), "\n") {
			if personalWorkspacePath.MatchString(line) {
				t.Errorf("%s:%d embeds a personal workspace path; use a relative path or configurable placeholder", name, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPersonalWorkspacePathPolicy(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{strings.Join([]string{"", "Users", "developer", "project"}, "/"), true},
		{strings.Join([]string{"", "home", "developer", "project"}, "/"), true},
		{strings.Join([]string{"C:", "Users", "developer", "project"}, `\`), true},
		{strings.Join([]string{"~", "source", "project"}, "/"), true},
		{"testdata/discovery/ledger", false},
		{"$WORKSPACE/project", false},
		{"@CHECKOUT_ROOT@/scripts/sync-results.sh", false},
	} {
		if got := personalWorkspacePath.MatchString(tc.path); got != tc.want {
			t.Errorf("path policy detection=%v, want %v", got, tc.want)
		}
	}
}
