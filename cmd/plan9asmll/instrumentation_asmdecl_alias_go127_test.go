//go:build go1.27

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestInstrumentationMetadataOrdinaryAsmdeclExactVersionReplacement(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	canonical := input.Original.Module
	input.Original.Module, input.Original.Version = "example.invalid/modearchive", "v1.0.0"
	invocation, env := instrumentationVersionedFixture(t, ctx, input)
	input.Original.Module = canonical
	caller := "module example.invalid/invocation\n\ngo 1.24\n\nrequire " + canonical + " v1.0.0\n" +
		"replace " + canonical + " v1.0.0 => " + input.Original.SourceModule + " v1.0.0\n"
	if err := os.WriteFile(filepath.Join(invocation, "go.mod"), []byte(caller), 0600); err != nil {
		t.Fatal(err)
	}
	replanInstrumentationMetadataFixture(t, input)
	// This actual local fileproxy fixture is not official-SumDB authentication.
	// It exercises only the existing caller-authenticated version-replace role;
	// production must still receive that independent original archive trust.
	consumer, err := captureInstrumentationMetadata(ctx, input, invocation, env, t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	selected := consumer.Metadata.Selection.Packages[0]
	if selected.SourceRole != "version_replace" || selected.ModulePath != canonical ||
		selected.SourceModule != input.Original.SourceModule || selected.ModuleVersion != "v1.0.0" ||
		selected.SourceVersion != "v1.0.0" || consumer.Source.Dir == consumer.Source.WorkDir {
		t.Fatalf("exact original archive namespace role was replaced or invented: %#v", selected)
	}
	if err := gotoolprofile.ValidatePackageModule(input.Original, selected); err != nil {
		t.Fatal(err)
	}
	if err := gotoolprofile.ValidateInstrumentationMetadata(input, ".", nil, consumer.Metadata); err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	exports := map[string]string{selected.PackagePath: consumer.Metadata.OriginalExportSHA256}
	for _, dependency := range consumer.Metadata.Dependencies {
		exports[dependency.Source.PackagePath] = dependency.Source.ExportSHA256
	}
	modeEnv := featureEnvironment(env, input.Observation.Early.Environment)
	for _, scenario := range []string{
		"control", "missing replacement", "replacement path", "replacement version", "replacement main",
		"nested replacement", "local replacement", "module root", "replacement root", "metadata bytes",
		"namespace metadata missing", "metadata after tool", "missing export", "extra export",
	} {
		t.Run(scenario, func(t *testing.T) {
			expected := make(map[string]string, len(exports))
			for name, digest := range exports {
				expected[name] = digest
			}
			if scenario == "missing export" {
				delete(expected, canonical+"/dep")
			}
			if scenario == "extra export" {
				expected[canonical+"/unselected"] = consumer.Metadata.OriginalExportSHA256
			}
			changed := false
			var metadata string
			run := func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
				stdout, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, name, args...)
				if err != nil || len(stderr) != 0 {
					return stdout, stderr, err
				}
				if len(args) > 1 && args[0] == "list" && args[1] == "-deps" {
					decoder := json.NewDecoder(bytes.NewReader(stdout))
					var result bytes.Buffer
					for {
						var pkg map[string]json.RawMessage
						if err := decoder.Decode(&pkg); err == io.EOF {
							break
						} else if err != nil {
							t.Fatal(err)
						}
						var path string
						if err := json.Unmarshal(pkg["ImportPath"], &path); err != nil {
							t.Fatal(err)
						}
						if path == canonical {
							var module, replacement map[string]json.RawMessage
							if err := json.Unmarshal(pkg["Module"], &module); err != nil {
								t.Fatal(err)
							}
							if err := json.Unmarshal(module["Replace"], &replacement); err != nil {
								t.Fatal(err)
							}
							if err := json.Unmarshal(replacement["GoMod"], &metadata); err != nil {
								t.Fatal(err)
							}
							switch scenario {
							case "missing replacement":
								delete(module, "Replace")
							case "replacement path":
								replacement["Path"] = json.RawMessage(`"example.invalid/other"`)
							case "replacement version":
								replacement["Version"] = json.RawMessage(`"v1.0.1"`)
							case "replacement main":
								replacement["Main"] = json.RawMessage(`true`)
							case "nested replacement":
								replacement["Replace"] = json.RawMessage(`{"Path":"example.invalid/nested","Version":"v1.0.0"}`)
							case "local replacement":
								delete(replacement, "Version")
							case "module root", "replacement root":
								root, err := json.Marshal(t.TempDir())
								if err != nil {
									t.Fatal(err)
								}
								if scenario == "module root" {
									module["Dir"] = root
								} else {
									replacement["Dir"] = root
								}
							case "namespace metadata missing":
								delete(module, "GoMod")
							case "metadata bytes":
								file := filepath.Join(t.TempDir(), "go.mod")
								if err := os.WriteFile(file, []byte("module example.invalid/changed\n"), 0600); err != nil {
									t.Fatal(err)
								}
								replacement["GoMod"], err = json.Marshal(file)
								if err != nil {
									t.Fatal(err)
								}
							}
							if scenario != "missing replacement" {
								module["Replace"], err = json.Marshal(replacement)
								if err != nil {
									t.Fatal(err)
								}
							}
							pkg["Module"], err = json.Marshal(module)
							if err != nil {
								t.Fatal(err)
							}
							changed = true
						}
						if err := json.NewEncoder(&result).Encode(pkg); err != nil {
							t.Fatal(err)
						}
					}
					return result.Bytes(), stderr, err
				}
				if scenario == "metadata after tool" && reflect.DeepEqual(args, []string{"tool", "vet", "-asmdecl", "ordinary.cfg"}) {
					data, err := os.ReadFile(metadata)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := os.WriteFile(metadata, data, 0600); err != nil {
							t.Errorf("restore owned fixture metadata: %v", err)
						}
					})
					if err := os.WriteFile(metadata, append(data, []byte("// late mutation\n")...), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return stdout, stderr, err
			}
			err := gotoolprofile.RunInstrumentationOrdinaryAsmdecl(ctx, binary, invocation, modeEnv, input.Original,
				input.Plan, &selected, expected, run)
			if !changed {
				t.Fatalf("did not consume fresh actual Go ordinary JSON: %v", err)
			}
			if scenario == "control" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("changed source/replacement/export binding was accepted")
			}
		})
	}
	if _, err := gotoolprofile.CaptureInstrumentationOriginalExport(ctx, binary, invocation, env, input.Original,
		input.Sources, input.Observation, input.Plan, gotoolprofile.RunBounded); err == nil || !strings.Contains(err.Error(), "dependency") {
		t.Fatalf("dependency-free OriginalExport foundation was broadened: %v", err)
	}
}
