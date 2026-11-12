//go:build go1.27 && unix

package gotoolprofile

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestInstrumentationOrdinaryAsmdeclOwnedDirectoryCompletion(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t),
		os.Environ(), "darwin/arm64", InstrumentationRace, "0", nil, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"control", "replace before tool", "replace after tool", "cleanup error", "cleanup permissions"} {
		t.Run(scenario, func(t *testing.T) {
			input := instrumentationOriginalFixture(t, marker.Early)
			inventory, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := PlanInstrumentationOriginalPackage(input, inventory, marker.Early, ".", nil)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := CaptureInstrumentationOriginalExport(ctx, binary, input.SourceRoot, os.Environ(),
				input, inventory, marker, plan, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			var owned, backup, blocked string
			var original, replacement os.FileInfo
			actualToolCompleted := false
			cleanupObserved := false
			var actualCleanupError error
			cleanupFailure := errors.New("independent owned cleanup fixture failure")
			remove := os.RemoveAll
			if scenario == "cleanup error" || scenario == "cleanup permissions" {
				remove = func(name string) error {
					if !actualToolCompleted || name != owned {
						t.Fatal("cleanup was not bound to the successful actual analyzer workspace")
					}
					cleanupObserved = true
					if scenario == "cleanup error" {
						actualCleanupError = cleanupFailure
					} else {
						actualCleanupError = os.RemoveAll(name)
					}
					return actualCleanupError
				}
			}
			t.Cleanup(func() {
				if blocked != "" {
					if err := os.Chmod(blocked, 0700); err != nil && !os.IsNotExist(err) {
						t.Errorf("restore exact owned cleanup fixture: %v", err)
					}
				}
				for name, identity := range map[string]os.FileInfo{backup: original, owned: replacement} {
					if name == "" || identity == nil {
						continue
					}
					info, err := os.Lstat(name)
					if os.IsNotExist(err) {
						continue
					}
					if err != nil || !os.SameFile(info, identity) {
						t.Errorf("refuse changed exact fixture directory cleanup: %s", name)
						continue
					}
					if err := os.RemoveAll(name); err != nil {
						t.Errorf("exact fixture directory cleanup: %v", err)
					}
				}
			})
			replace := func() {
				data, err := os.ReadFile(filepath.Join(owned, "ordinary.cfg"))
				if err != nil {
					t.Fatal(err)
				}
				backup = owned + ".fixture-original"
				if err := os.Rename(owned, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(owned, 0700); err != nil {
					t.Fatal(err)
				}
				replacement, err = os.Lstat(owned)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(owned, "ordinary.cfg"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			run := func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
				if !reflect.DeepEqual(args, instrumentationOrdinaryAsmdeclArgs()) {
					return RunBounded(ctx, dir, env, name, args...)
				}
				owned = dir
				original, err = os.Lstat(owned)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "replace before tool" {
					replace()
				}
				stdout, stderr, toolErr := RunBounded(ctx, dir, env, name, args...)
				if toolErr != nil || len(stdout)+len(stderr) != 0 {
					t.Fatalf("actual official analyzer fixture: %v; %s; %s", toolErr, stdout, stderr)
				}
				actualToolCompleted = true
				if scenario == "replace after tool" {
					replace()
				}
				if scenario == "cleanup error" {
					replacement = original
				}
				if scenario == "cleanup permissions" {
					blocked = filepath.Join(owned, "blocked")
					if err := os.Mkdir(blocked, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(blocked, "leaf"), []byte("owned fixture"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(blocked, 0); err != nil {
						t.Fatal(err)
					}
					replacement = original
				}
				return stdout, stderr, toolErr
			}
			modeEnv := instrumentationFixtureEnvironment(os.Environ(), marker.Early)
			err = runInstrumentationOrdinaryAsmdecl(ctx, binary, input.SourceRoot, modeEnv, input, plan, &proof.Package,
				map[string]string{proof.Package.PackagePath: proof.ArchiveSHA256}, run, remove)
			if !actualToolCompleted {
				t.Fatalf("fixture did not reach actual official analyzer: %v", err)
			}
			if scenario == "cleanup error" || scenario == "cleanup permissions" {
				if !cleanupObserved {
					t.Fatal("cleanup fixture did not observe the actual completion path")
				}
				if actualCleanupError == nil {
					if err != nil {
						t.Fatalf("successful actual removal was reported as a failure: %v", err)
					}
					t.Log("actual mode-000 removal succeeded; no permission-denial claim")
				} else if !errors.Is(err, actualCleanupError) {
					t.Fatalf("lost independently observed cleanup cause: cleanup=%v producer=%v", actualCleanupError, err)
				}
				if scenario == "cleanup error" && !errors.Is(err, cleanupFailure) {
					t.Fatalf("successful analyzer did not preserve the distinct cleanup sentinel: %v", err)
				}
			} else if scenario == "control" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(owned); !os.IsNotExist(err) {
					t.Fatalf("successful original directory not cleaned: %v", err)
				}
			} else if err == nil {
				t.Fatal("successful actual analyzer hid owned-directory replacement or cleanup failure")
			}
			if backup != "" {
				info, err := os.Lstat(owned)
				if err != nil || !os.SameFile(info, replacement) {
					t.Fatal("producer deleted or changed replacement directory")
				}
			}
		})
	}
}
