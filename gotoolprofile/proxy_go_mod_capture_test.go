package gotoolprofile

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"
)

// This is real public metadata authentication and actual Go environment/path
// binding. It deliberately does not download or execute the external module;
// the separate whole-ZIP verifier must still prove its original source bytes.
func TestDownloadedProxyGoModAuthenticatedConsumerBinding(t *testing.T) {
	for _, axis := range []string{"valid", "bytes", "identity", "unsigned", "missing inclusion", "wrong path", "symlink", "cancelled"} {
		t.Run(axis, func(t *testing.T) {
			origin := fixtureProxyGoMod(t)
			cache, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			name, err := module.EscapePath(origin.Module)
			if err != nil {
				t.Fatal(err)
			}
			version, err := module.EscapeVersion(origin.Version)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(cache, "cache/download", filepath.FromSlash(name), "@v", version+".mod")
			if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte(origin.Contents), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			identity := origin.Module
			switch axis {
			case "bytes":
				if err := os.WriteFile(file, []byte(origin.Contents+"// altered\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "identity":
				identity += "/different"
			case "unsigned":
				origin.SignedTree = strings.Split(origin.SignedTree, "\n\n")[0] + "\n"
			case "missing inclusion":
				origin.Inclusion = nil
			case "wrong path":
				file = filepath.Join(t.TempDir(), "copied.mod")
				if err := os.WriteFile(file, []byte(origin.Contents), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := filepath.Join(t.TempDir(), "other.mod")
				if err := os.Rename(file, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, file); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				cancel()
			}
			binary, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			var env []string
			for _, item := range os.Environ() {
				key, _, _ := strings.Cut(item, "=")
				if key != "GOMODCACHE" && key != "GOTOOLCHAIN" && key != "GOWORK" && key != "GOFLAGS" && key != "GOPROXY" {
					env = append(env, item)
				}
			}
			env = append(env, "GOMODCACHE="+cache, "GOTOOLCHAIN=local", "GOWORK=off", "GOFLAGS=", "GOPROXY=off")
			actual, path, err := CaptureDownloadedProxyGoMod(ctx, binary, t.TempDir(), env, identity, origin.Version, origin.ModuleSum, origin.GoModSum, file, origin)
			if axis != "valid" {
				if err == nil {
					t.Fatal("altered proxy metadata source accepted")
				}
				return
			}
			if err != nil || path != file || !reflect.DeepEqual(actual, origin) {
				t.Fatalf("authenticated current consumer binding: %v", err)
			}
			actual.Inclusion[0] = "mutated public projection"
			if actual.Inclusion[0] == origin.Inclusion[0] {
				t.Fatal("caller projection shares authenticated origin storage")
			}
		})
	}
}
