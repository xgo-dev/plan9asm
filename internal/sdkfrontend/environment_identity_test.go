package sdkfrontend

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestOrdinaryEnvironmentActualCommandPathIdentity(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "actual")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	sdkEnvironmentAlias(t, alias, actual)
	sdkAlias := filepath.Join(root, "sdk")
	sdkEnvironmentAlias(t, sdkAlias, runtime.GOROOT())
	for _, profile := range []string{"off", "saved-config"} {
		t.Run(profile, func(t *testing.T) {
			config := "off"
			if profile == "saved-config" {
				config = filepath.Join(alias, "go-env")
				if err := os.WriteFile(config, []byte("GOPROXY=https://actual-config.invalid,direct\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			input := append(os.Environ(), "GOENV="+config, "GOROOT="+sdkAlias,
				"GOOS=linux", "GOARCH=amd64", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=", "GOPACKAGESDRIVER=off")
			for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
				path := filepath.Join(alias, key)
				if key == "TMPDIR" || key == "GOTMPDIR" {
					if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
						t.Fatal(err)
					}
				}
				input = append(input, key+"="+path)
			}
			if runtime.GOOS == "windows" {
				// Native handle resolution must bind the same actual target,
				// not guess identity from drive case or slash replacement.
				for _, key := range []string{"GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR", "GOENV"} {
					path := config
					if key == "GOROOT" {
						path = sdkAlias
					} else if key != "GOENV" {
						path = filepath.Join(alias, key)
					}
					if path != "off" {
						volume := filepath.VolumeName(path)
						input = append(input, key+"="+filepath.ToSlash(strings.ToLower(volume)+strings.TrimPrefix(path, volume)))
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			keys := []string{"GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH", "GOENV", "CGO_ENABLED", "GOPROXY", "GOFLAGS"}
			before, stderr, err := gotoolprofile.RunBounded(ctx, "", input, "go", append([]string{"env", "-json"}, keys...)...)
			if err != nil || len(stderr) != 0 {
				t.Fatalf("actual original compiler profile: %v; %s", err, stderr)
			}
			var original map[string]string
			if err := json.Unmarshal(before, &original); err != nil {
				t.Fatal(err)
			}
			environment, err := OrdinaryEnvironment("linux", "amd64", input)
			if err != nil {
				t.Fatal(err)
			}
			provided, err := EnvironmentValues(environment)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
				canonical, err := sourcepath.Resolve(provided[key])
				if err != nil || canonical != provided[key] {
					t.Errorf("actual selected %s was not handed off in its opened physical spelling: got=%q physical=%q error=%v", key, provided[key], canonical, err)
				}
				requested := filepath.Join(alias, key)
				if key == "GOROOT" {
					requested = sdkAlias
				}
				want, err := sourcepath.Resolve(requested)
				if err != nil || provided[key] != want {
					t.Errorf("actual selected %s changed its filesystem target: %q != %q (%v)", key, provided[key], want, err)
				}
			}
			if config != "off" {
				want, err := sourcepath.Resolve(config)
				if err != nil || provided["GOENV"] != want {
					t.Errorf("saved config was disabled or lacks its physical identity: got=%q want=%q error=%v", provided["GOENV"], want, err)
				}
			}
			after, stderr, err := gotoolprofile.RunBounded(ctx, "", environment, "go", append([]string{"env", "-json"}, keys...)...)
			if err != nil || len(stderr) != 0 {
				t.Fatalf("actual canonical compiler profile: %v; %s", err, stderr)
			}
			var observed map[string]string
			if err := json.Unmarshal(after, &observed); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"CGO_ENABLED", "GOPROXY", "GOFLAGS"} {
				if observed[key] != original[key] {
					t.Errorf("canonical path handoff changed actual compiler default/config %s: %q != %q", key, observed[key], original[key])
				}
			}
		})
	}
}

func TestOrdinaryEnvironmentCommandPathRejectionPreservesInputs(t *testing.T) {
	checkCommandPathRejectionPreservesInputs(t, OrdinaryEnvironment)
}

func TestFeatureEnvironmentCommandPathRejectionPreservesInputs(t *testing.T) {
	checkCommandPathRejectionPreservesInputs(t, FeatureEnvironment)
}

func checkCommandPathRejectionPreservesInputs(t *testing.T, prepare func(string, string, []string) ([]string, error)) {
	t.Helper()
	for _, key := range []string{"GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		t.Run(key, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "original-not-directory")
			const original = "selected original file, not command storage\n"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			input := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", key+"="+path)
			if output, err := prepare("linux", "amd64", input); err == nil || len(output) != 0 {
				t.Fatalf("non-directory %s supplied a command/source profile: %v", key, err)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != original {
				t.Fatalf("preparing %s replaced its original file: %v", key, err)
			}
		})
	}
	for _, key := range []string{"TMPDIR", "GOTMPDIR"} {
		t.Run("missing-"+key, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "missing")
			input := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", key+"="+path)
			if output, err := prepare("linux", "amd64", input); err == nil || len(output) != 0 {
				t.Fatalf("missing selected %s was silently substituted: %v", key, err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("selected missing %s was repaired after observation: %v", key, err)
			}
		})
	}
}

func TestOrdinaryEnvironmentRetainsGOPATHComponentSelection(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "actual")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	sdkEnvironmentAlias(t, alias, actual)
	paths := []string{filepath.Join(alias, "first"), filepath.Join(alias, "second")}
	var want []string
	for _, path := range paths {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		physical, err := sourcepath.Resolve(path)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, physical)
	}
	input := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOPATH="+strings.Join(paths, string(filepath.ListSeparator)))
	environment, err := OrdinaryEnvironment("linux", "amd64", input)
	if err != nil {
		t.Fatal(err)
	}
	values, err := EnvironmentValues(environment)
	if err != nil {
		t.Fatal(err)
	}
	if values["GOPATH"] != strings.Join(want, string(filepath.ListSeparator)) {
		t.Fatalf("actual ordered GOPATH components were collapsed or lack their physical identities: %q != %q", values["GOPATH"], want)
	}
}
