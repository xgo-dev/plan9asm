package gotoolprofile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstrumentationAsmdeclWorkspaceIdentityAndCleanup(t *testing.T) {
	for _, scenario := range []string{"control", "missing", "replaced", "nonregular config", "cleanup error", "cleanup incomplete", "missing cleanup"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			name := filepath.Join(root, "owned")
			if err := os.Mkdir(name, 0700); err != nil {
				t.Fatal(err)
			}
			identity, err := os.Lstat(name)
			if err != nil {
				t.Fatal(err)
			}
			physical, err := filepath.EvalSymlinks(name)
			if err != nil {
				t.Fatal(err)
			}
			owned := &instrumentationAsmdeclWorkspace{name: name, physical: physical, identity: identity}
			filename := filepath.Join(name, "ordinary.cfg")
			if err := os.WriteFile(filename, []byte("actual config guard fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := owned.verifyConfig(); err != nil {
				t.Fatal(err)
			}
			remove := os.RemoveAll
			cleanupFailure := errors.New("owned cleanup fixture failure")
			switch scenario {
			case "missing":
				if err := os.RemoveAll(name); err != nil {
					t.Fatal(err)
				}
			case "replaced":
				if err := os.Rename(name, filepath.Join(root, "original")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
			case "nonregular config":
				if err := os.Remove(filename); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filename, 0700); err != nil {
					t.Fatal(err)
				}
			case "cleanup error":
				remove = func(string) error { return cleanupFailure }
			case "cleanup incomplete":
				remove = func(string) error { return nil }
			case "missing cleanup":
				remove = nil
			}
			if scenario == "nonregular config" {
				if err := owned.verifyConfig(); err == nil {
					t.Fatal("accepted a nonregular configuration leaf")
				}
				if err := owned.close(os.RemoveAll); err != nil {
					t.Fatal(err)
				}
				return
			}
			err = owned.close(remove)
			if scenario == "control" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted incomplete ownership or cleanup")
			}
			if scenario == "cleanup error" && !errors.Is(err, cleanupFailure) {
				t.Fatalf("lost original cleanup error: %v", err)
			}
			if scenario == "replaced" {
				if _, err := os.Lstat(name); err != nil {
					t.Fatal("removed replacement directory")
				}
			}
		})
	}
}
