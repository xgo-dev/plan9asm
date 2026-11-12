package gotoolprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Stock Go reports the implicit 1.16 language for a main module, but preserves
// the absent GoVersion field on a dependency. Neither role rewrites go.mod.
func TestAMD64DownloadedDefaultLanguageActualGo(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	for _, variant := range []string{"fixed-local-no-go", "foreign-no-go"} {
		t.Run(variant, func(t *testing.T) {
			request, module, version := amd64DownloadedObservationFixture(t, variant)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			data, stderr, err := RunBounded(ctx, request.Directory, request.Environment, request.GoBinary,
				"list", "-export", "-json", "-mod=readonly", ".")
			if err != nil || len(stderr) != 0 {
				t.Fatalf("actual default-language Go export failed: %v; %s", err, stderr)
			}
			var actual amd64OriginalListPackage
			if err := json.Unmarshal(data, &actual); err != nil || actual.Module == nil ||
				actual.Module.GoVersion != "1.16" || actual.Export == "" {
				t.Fatalf("actual main-module language/export not observed: %v; %s", err, data)
			}
			observed, err := captureAMD64DownloadedForTest(ctx, request, module, version)
			if err != nil {
				t.Fatal("Go-accepted absent language directive lost original source observation", err)
			}
			defer func() {
				if err := observed.Close(); err != nil {
					t.Error(err)
				}
			}()
			for _, wrong := range []string{"", "1.20", "1.27.1"} {
				changed := *actual.Module
				changed.GoVersion = wrong
				if observed.downloaded.primary.matches(&changed, true) {
					t.Fatalf("implicit main language accepted foreign metadata %q", wrong)
				}
			}
			if variant == "foreign-no-go" {
				foreign := observed.state.packages["example.invalid/foreign-observation"]
				if foreign.Module == nil || foreign.Module.Main || foreign.Module.GoVersion != "" || foreign.Export == "" {
					t.Fatal("missing-language dependency was changed to a main-module role")
				}
				changed := *foreign.Module
				changed.GoVersion = "1.16"
				if _, err := observed.downloaded.module(&changed); err == nil {
					t.Fatal("dependency borrowed the main-module default metadata")
				}
			}
			if err := observed.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(request.Directory, "go.mod")
			before, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(name, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, append(append([]byte(nil), before...), []byte("\ngo 1.20\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if err := observed.Verify(ctx); err == nil {
				t.Fatal("a new language directive retained the old observation")
			}
			if err := os.WriteFile(name, before, 0600); err != nil {
				t.Fatal(err)
			}
			if err := observed.Verify(ctx); err == nil {
				t.Fatal("restoring absent language revived a revoked observation")
			}
		})
	}
}

func TestAMD64OriginalDefaultLanguageActualGo(t *testing.T) {
	request := amd64OriginalObservationFixture(t, "numeric")
	if err := os.WriteFile(filepath.Join(request.Directory, "go.mod"), []byte("module "+request.PackagePath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
	if err != nil {
		t.Fatal("owned original module lost actual implicit language", err)
	}
	defer func() {
		if err := observed.Close(); err != nil {
			t.Error(err)
		}
	}()
	if observed.state.packages[request.PackagePath].Module.GoVersion != "1.16" {
		t.Fatal("original observation did not retain actual Go main language")
	}
	if err := observed.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}
