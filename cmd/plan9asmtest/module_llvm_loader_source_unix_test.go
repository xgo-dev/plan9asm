//go:build unix

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// cmd/go/internal/work/buildid.go defines an executable build ID as
// linkAction/mainAction/mainContent/binaryContent. Compare the complete build
// inputs, not the last output hash: external linkers can change Mach-O UUIDs
// between otherwise identical builds. Source/tool/library scopes and both
// independently built and executed outputs are still checked below.
func moduleLLVMLoaderBuildInputs(data []byte) ([3]string, error) {
	var inputs [3]string
	parts := strings.Split(strings.TrimSpace(string(data)), "/")
	if len(parts) != 4 {
		return inputs, fmt.Errorf("expected four-part Go executable build ID")
	}
	for _, part := range parts {
		hash, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || len(hash) != 15 {
			return inputs, fmt.Errorf("invalid Go executable build ID hash")
		}
	}
	copy(inputs[:], parts[:3])
	return inputs, nil
}

func TestModuleLLVMLoaderBuildInputIdentityContract(t *testing.T) {
	parts := []string{
		"4Sv_jAoZLEHEiToUJqjp", "Gh9vhQpOPgyFAE1zV7cQ",
		"54B443LuDoOsCwYlS76d", "d1YRB_sIJnUt9MGYvdNO",
	}
	want, err := moduleLLVMLoaderBuildInputs([]byte(strings.Join(parts, "/") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	for index, role := range []string{"link-action", "main-action", "main-content", "binary-content"} {
		t.Run(role, func(t *testing.T) {
			changed := append([]string(nil), parts...)
			changed[index] = "YjHc7jzVQ6eG97PMevqY"
			got, err := moduleLLVMLoaderBuildInputs([]byte(strings.Join(changed, "/")))
			if err != nil || (got == want) != (index == 3) {
				t.Fatalf("input/output identities confused: got=%v want=%v err=%v", got, want, err)
			}
		})
	}
	for _, malformed := range []string{
		"", strings.Join(parts[:3], "/"), strings.Join(parts, "/") + "/extra",
		"!/" + strings.Join(parts[1:], "/"), strings.Join(parts[:3], "/") + "/!",
	} {
		if _, err := moduleLLVMLoaderBuildInputs([]byte(malformed)); err == nil {
			t.Errorf("malformed build ID accepted: %q", malformed)
		}
	}
}

func TestModuleLLVMLoaderRepeatedBuildRetainsIndependentActualScopes(t *testing.T) {
	moduleFixtureEnvironment(t)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	physicalParent, err := filepath.EvalSymlinks(out)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{Go: goBinary, Dir: moduleLLVMConsumerFixture(t), Module: true,
		Timeout: 2 * time.Minute, Flags: []string{"-p=2"}}
	before := filepath.Join(out, "before")
	first, err := captureCIScope(context.Background(), cfg, before)
	if err != nil {
		t.Fatal("fresh first source/tool/environment/library scope", err)
	}
	firstID, err := moduleDependencyCommand(context.Background(), cfg, filepath.Join(out, "first-buildid"), goBinary,
		"tool", "buildid", before+"-llvm-loader")
	if err != nil || len(strings.TrimSpace(string(firstID))) == 0 {
		t.Fatal("actual first Go loader build identity", err)
	}
	// The second scope must build and execute its own output; it cannot execute
	// this first binary or copy the first loader's observation as a new proof.
	if err := os.Remove(before + "-llvm-loader"); err != nil {
		t.Fatal(err)
	}
	after := filepath.Join(out, "after")
	last, err := captureCIScope(context.Background(), cfg, after)
	if err != nil {
		t.Fatal("fresh second source/tool/environment/library scope", err)
	}
	lastID, err := moduleDependencyCommand(context.Background(), cfg, filepath.Join(out, "last-buildid"), goBinary,
		"tool", "buildid", after+"-llvm-loader")
	if err != nil {
		t.Fatal("actual second Go loader build identity", err)
	}
	firstInputs, err := moduleLLVMLoaderBuildInputs(firstID)
	if err != nil {
		t.Fatal("actual first Go loader build inputs", err)
	}
	lastInputs, err := moduleLLVMLoaderBuildInputs(lastID)
	if err != nil {
		t.Fatal("actual second Go loader build inputs", err)
	}
	if firstInputs != lastInputs {
		t.Errorf("identical request-owned probe content changes actual Go build inputs: first=%q second=%q", firstID, lastID)
	}
	if !reflect.DeepEqual(first, last) {
		t.Fatal("independent unchanged scopes differ")
	}
	if err := verifyModuleDependencyArtifacts(out, moduleReport{Scope: first}); err != nil {
		t.Fatal("full dependency artifact readback", err)
	}
	for _, stem := range []string{before, after} {
		var origins map[string]string
		if err := ciReadJSON(stem+"-origins.json", &origins); err != nil {
			t.Fatal(err)
		}
		if origins["llvm-loader-source"] != filepath.Join(physicalParent, ".llvm-loader-source", "main.go") {
			t.Errorf("actual Go build source not bound to this request: %q", origins["llvm-loader-source"])
		}
		var loaded moduleLoadedLibrary
		if err := ciReadJSON(stem+"-llvm-loaded-library.json", &loaded); err != nil {
			t.Fatal(err)
		}
		run, err := os.ReadFile(stem + "-llvm-loader-run.stdout")
		if err != nil || string(run) != loaded.Path+"\n" || loaded.SHA != first.Tools["llvm-loaded"] {
			t.Fatal("fresh actual loader result/byte identity missing", err)
		}
	}
	metadata := before + "-llvm-loader-source.json"
	original, err := os.ReadFile(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"missing", "foreign-source", "foreign-artifact", "changed-bytes", "missing-tool-origin"} {
		t.Run(mutation, func(t *testing.T) {
			var changed moduleLLVMProbeSource
			if err := ciReadJSON(metadata, &changed); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing":
				changed = moduleLLVMProbeSource{}
			case "foreign-source":
				changed.Path = filepath.Join(changed.Parent, "unconsumed.go")
			case "foreign-artifact":
				changed.Artifact = filepath.Join(changed.Parent, "after-llvm-loader.go")
			case "changed-bytes":
				changed.SHA = strings.Repeat("0", 64)
			case "missing-tool-origin":
				delete(first.Tools, "llvm-loader-source")
			}
			if err := ciWriteJSON(metadata, changed); err != nil {
				t.Fatal(err)
			}
			if err := verifyModuleDependencyArtifacts(out, moduleReport{Scope: first}); err == nil {
				t.Fatal("compiled source role omission/change accepted")
			}
			if err := os.WriteFile(metadata, original, 0600); err != nil {
				t.Fatal(err)
			}
			first.Tools["llvm-loader-source"] = last.Tools["llvm-loader-source"]
		})
	}
	t.Log("Two fresh actual Go builds and two loader executions; original 2m child budgets and complete source/tool/environment/library captures remain independent.")
}

func TestModuleLLVMProbeSourceAtomicCreationAndCancellation(t *testing.T) {
	parent := t.TempDir()
	physical, err := filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	results := make(chan moduleLLVMProbeInput, 16)
	failures := make(chan error, 16)
	for index := 0; index < 16; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			input, err := prepareModuleLLVMProbeSource(context.Background(), filepath.Join(parent, "scope"))
			if err != nil {
				failures <- err
			} else {
				results <- input
			}
		}()
	}
	workers.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	for input := range results {
		if input.source.Path != filepath.Join(physical, ".llvm-loader-source", "main.go") || input.verify(context.Background()) != nil {
			t.Fatal("parallel creator observed incomplete/foreign source", input.source)
		}
	}
	files, err := os.ReadDir(filepath.Join(parent, ".llvm-loader-source"))
	if err != nil || len(files) != 1 || files[0].Name() != "main.go" {
		t.Fatalf("creator staging ownership did not close: %v %v", files, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prepareModuleLLVMProbeSource(ctx, filepath.Join(parent, "cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled producer acquired a role", err)
	}
	input, err := prepareModuleLLVMProbeSource(context.Background(), filepath.Join(parent, "existing"))
	if err != nil || !errors.Is(input.verify(ctx), context.Canceled) || input.verify(context.Background()) != nil {
		t.Fatal("cancellation deleted or changed another producer's source role", err)
	}
	empty := t.TempDir()
	if _, err := prepareModuleLLVMProbeSource(ctx, filepath.Join(empty, "cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	files, err = os.ReadDir(empty)
	if err != nil || len(files) != 0 {
		t.Fatal("cancelled first creator wrote artifacts", files, err)
	}
}

func TestModuleLLVMProbeSourceRejectsForeignAndReplacedRoles(t *testing.T) {
	for _, name := range []string{"parent-file", "parent-symlink", "directory-file", "directory-symlink", "source-directory", "source-symlink", "different-bytes", "oversized-prefix"} {
		t.Run(name, func(t *testing.T) {
			var err error
			container := t.TempDir()
			parent := filepath.Join(container, "parent")
			foreign := t.TempDir()
			if name == "parent-file" {
				if err := os.WriteFile(parent, []byte("foreign parent"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if name == "parent-symlink" {
				if err := os.Symlink(foreign, parent); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				directory := filepath.Join(parent, ".llvm-loader-source")
				if name == "directory-file" {
					if err := os.WriteFile(directory, []byte("foreign directory"), 0600); err != nil {
						t.Fatal(err)
					}
				} else if name == "directory-symlink" {
					if err := os.Symlink(foreign, directory); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(directory, 0700); err != nil {
						t.Fatal(err)
					}
					source := filepath.Join(directory, "main.go")
					switch name {
					case "source-directory":
						err = os.Mkdir(source, 0700)
					case "source-symlink":
						err = os.Symlink(filepath.Join(foreign, "main.go"), source)
					case "different-bytes":
						err = os.WriteFile(source, []byte("package foreign\n"), 0600)
					case "oversized-prefix":
						err = os.WriteFile(source, []byte(moduleLLVMLoaderProbe+"x"), 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := prepareModuleLLVMProbeSource(context.Background(), filepath.Join(parent, "before")); err == nil {
				t.Fatal("foreign source role acquired producer authority")
			}
			files, err := os.ReadDir(foreign)
			if err != nil || len(files) != 0 {
				t.Fatal("rejected alias mutated foreign directory", files, err)
			}
		})
	}
	parent := t.TempDir()
	input, err := prepareModuleLLVMProbeSource(context.Background(), filepath.Join(parent, "before"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(input.source.Path, input.source.Path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input.source.Path, []byte(moduleLLVMLoaderProbe), 0600); err != nil {
		t.Fatal(err)
	}
	if input.verify(context.Background()) == nil {
		t.Fatal("same-byte replacement changed the original compiled source identity")
	}
}

type moduleLLVMProbeSwapContext struct {
	context.Context
	calls int
	swap  func()
}

func (ctx *moduleLLVMProbeSwapContext) Err() error {
	ctx.calls++
	if ctx.calls == 2 {
		ctx.swap()
	}
	return nil
}

func TestModuleLLVMProbeSourceCleanupRejectsReplacedDirectory(t *testing.T) {
	for _, role := range []string{"directory", "same-byte-file"} {
		t.Run(role, func(t *testing.T) {
			parent := t.TempDir()
			directory := filepath.Join(parent, ".llvm-loader-source")
			var foreignStage, originalStage string
			canary := []byte("another owner's closed temporary file\n")
			if role == "same-byte-file" {
				canary = []byte(moduleLLVMLoaderProbe)
			}
			ctx := &moduleLLVMProbeSwapContext{Context: context.Background()}
			ctx.swap = func() {
				entries, err := os.ReadDir(directory)
				if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".pending-") {
					t.Fatalf("expected the creator's complete staged file: %v %v", entries, err)
				}
				foreignStage = filepath.Join(directory, entries[0].Name())
				if role == "directory" {
					if err := os.Rename(directory, directory+"-original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(directory, 0700); err != nil {
						t.Fatal(err)
					}
					originalStage = filepath.Join(directory+"-original", entries[0].Name())
				} else {
					originalStage = foreignStage + ".original"
					if err := os.Rename(foreignStage, originalStage); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(foreignStage, canary, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := prepareModuleLLVMProbeSource(ctx, filepath.Join(parent, "before")); err == nil {
				t.Error("replaced physical role acquired the producer authority")
			}
			actual, err := os.ReadFile(foreignStage)
			if err != nil || !reflect.DeepEqual(actual, canary) {
				t.Errorf("cleanup deleted or changed another owner's same-named temporary: %q %v", actual, err)
			}
			if _, err := os.Lstat(filepath.Join(directory, "main.go")); !os.IsNotExist(err) {
				t.Error("replaced role published a foreign main.go", err)
			}
			// An unprovable moved path is quarantined, not rediscovered or
			// recursively cleaned. This test owns and retires the whole tree.
			actual, err = os.ReadFile(originalStage)
			if err != nil || string(actual) != moduleLLVMLoaderProbe {
				t.Fatal("the original closed temporary was changed", err)
			}
		})
	}
}
