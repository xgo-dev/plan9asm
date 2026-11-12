package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

const ordinaryGlobalDependency = "example.com/declsource/state"

type ordinaryGlobalCLIFixture struct {
	pkg, dependency *packages.Package
	task            asmTask
	config          compileConfig
	sources         map[string][]byte
}

func ordinaryGlobalCLIProfile(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"GOROOT": runtime.GOROOT(), "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
		"GOFLAGS": "", "GOEXPERIMENT": "", "GOPACKAGESDRIVER": "off", "GOPROXY": "off",
		"CGO_ENABLED": "0", "GOAMD64": "v1", "GO386": "sse2", "GOARM": "", "GOARM64": "", "GOWASM": "",
	} {
		t.Setenv(key, value)
	}
}

// The actual loader keeps declarations type-only. The complete local and
// direct-import syntax must be acquired only for this assembly candidate,
// without changing the stored package graph or starting another Go selection.
func ordinaryGlobalCLIActualFixture(t *testing.T, arch string) ordinaryGlobalCLIFixture {
	t.Helper()
	return ordinaryGlobalCLIActualFixtureProfile(t, arch, "v1")
}

func ordinaryGlobalCLIActualFixtureProfile(t *testing.T, arch, profile string) ordinaryGlobalCLIFixture {
	t.Helper()
	ordinaryGlobalCLIProfile(t)
	t.Setenv("GOAMD64", profile)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	symbol := strings.NewReplacer("/", "∕", ".", "·").Replace(ordinaryGlobalDependency)
	var assembly strings.Builder
	for _, row := range []struct{ name, instruction string }{
		{"Local", "CMPB ·Flags(SB),$1"},
		{"ImportedByte", "CMPB " + symbol + "·Flags(SB),$1"},
		{"ImportedWord", "CMPL " + symbol + "·Word(SB),$0x12345678"},
	} {
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-4\n%s\nJNE different\nMOVL $1,ret+0(FP)\nRET\ndifferent:\nMOVL $0,ret+0(FP)\nRET\n", row.name, row.instruction)
	}
	inputs := map[string]string{
		"go.mod":                        "module example.com/declsource\n\ngo 1.24\n",
		"state/state.go":                "package state\ntype Byte uint8\nvar Flags Byte = 1\n",
		"state/word_linux.go":           "//go:build linux\n\npackage state\nvar Word uint32 = 0x12345678\n",
		"state/word_other.go":           "//go:build !linux\n\npackage state\nvar Word uint64\n",
		"consumer/consumer.go":          "package consumer\nimport state \"" + ordinaryGlobalDependency + "\"\nvar _ = state.Flags\nvar _ = state.Word\nvar Flags uint8 = 1\nfunc Local() uint32\nfunc ImportedByte() uint32\nfunc ImportedWord() uint32\n",
		"consumer/profile_v2.go":        "//go:build amd64.v2\n\npackage consumer\nconst SelectedCPUProfile = 2\n",
		"consumer/profile_baseline.go":  "//go:build !amd64.v2\n\npackage consumer\nconst SelectedCPUProfile = 1\n",
		"consumer/reads_" + arch + ".s": assembly.String(),
	}
	sources := make(map[string][]byte, len(inputs))
	for name, source := range inputs {
		file := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		sources[file] = []byte(source)
	}
	t.Chdir(filepath.Join(directory, "consumer"))
	ctx := arm64PrivateCLIContext(t)
	selected, environment, err := loadPkgsInEnvironment("linux", arch, []string{"."}, nil, "", true, false, nil)
	if err != nil || len(selected) != 1 || selected[0].PkgPath != "example.com/declsource/consumer" {
		t.Fatalf("actual ordinary package load failed: %v %+v", err, selected)
	}
	pkg := selected[0]
	dependency := pkg.Imports[ordinaryGlobalDependency]
	if pkg.Types == nil || pkg.TypesSizes == nil || dependency == nil || dependency.Types == nil ||
		len(dependency.CompiledGoFiles) != 2 || len(pkg.Syntax) != 0 || len(dependency.Syntax) != 0 {
		t.Fatal("fixture lost its real typed, syntax-free package selection")
	}
	word, ok := dependency.Types.Scope().Lookup("Word").(*types.Var)
	if !ok || !types.Identical(word.Type(), types.Typ[types.Uint32]) || pkg.TypesSizes.Sizeof(word.Type()) != 4 {
		t.Fatal("actual selected Linux declaration is not the original uint32")
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = ctx
	config.x86CallerSelections = captureX86CallerSelectionsInEnvironment(selected, "linux/"+arch, environment)
	return ordinaryGlobalCLIFixture{pkg, dependency,
		asmTask{PkgPath: pkg.PkgPath, AsmFile: filepath.Join(pkg.Dir, "reads_"+arch+".s"), OutLL: filepath.Join(t.TempDir(), "reads.ll")},
		config, sources}
}

func ordinaryGlobalRequireIR(t *testing.T, source, path string) {
	t.Helper()
	for _, name := range []string{path + ".Flags", ordinaryGlobalDependency + ".Flags", ordinaryGlobalDependency + ".Word"} {
		if !strings.Contains(source, `@"`+name+`" = external global `) {
			t.Fatal("mutable Go global lost its original external namespace", name)
		}
	}
	for _, name := range []string{"Local", "ImportedByte", "ImportedWord"} {
		if !strings.Contains(source, `define i32 @"`+path+"."+name+`"(`) {
			t.Fatal("complete original source entry was cropped", name)
		}
	}
	if strings.Count(source, "load volatile i8") != 2 || strings.Count(source, "load volatile i32") != 1 {
		t.Fatal("ordinary declaration reads lost their complete exact-width effects")
	}
}

func TestCompileOneOrdinaryGlobalDeclarationsCompleteSource(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			fixture := ordinaryGlobalCLIActualFixture(t, arch)
			originalType, importedType := fixture.pkg.Types, fixture.dependency.Types
			// Retained object compilation must keep the complete source.
			fixture.config.MaxFunctions, fixture.config.MaxInstructions = 1, 1
			if err := compileOne(fixture.pkg, plan9asm.ArchAMD64, "linux", arch, targetTriple("linux", arch),
				fixture.task, false, fixture.config); err != nil {
				t.Fatal("complete ordinary same-package/imported declaration source failed", err)
			}
			ir, err := os.ReadFile(fixture.task.OutLL)
			if err != nil {
				t.Fatal(err)
			}
			ordinaryGlobalRequireIR(t, string(ir), fixture.pkg.PkgPath)
			object := strings.TrimSuffix(fixture.task.OutLL, ".ll") + ".o"
			if info, err := os.Lstat(object); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatal("actual complete-source LLVM22 object is missing", err)
			}
			parts, err := filepath.Glob(strings.TrimSuffix(fixture.task.OutLL, ".ll") + ".part-*")
			if err != nil || len(parts) != 0 {
				t.Fatal("ordinary complete declaration source was split before binding", parts, err)
			}
			if fixture.pkg.Types != originalType || fixture.dependency.Types != importedType ||
				len(fixture.pkg.Syntax) != 0 || len(fixture.dependency.Syntax) != 0 {
				t.Fatal("one candidate changed the actual light-load types or retained source ASTs")
			}
			// The validation-only path would normally split at these limits.
			// It must independently bind and emit the same complete GoModule.
			fixture.config.KeepObj = false
			fixture.task.OutLL = filepath.Join(filepath.Dir(fixture.task.OutLL), "validation-only.ll")
			if err := compileOne(fixture.pkg, plan9asm.ArchAMD64, "linux", arch, targetTriple("linux", arch),
				fixture.task, false, fixture.config); err != nil {
				t.Fatal("ordinary declarations were split on the validation-only path", err)
			}
			ir, err = os.ReadFile(fixture.task.OutLL)
			if err != nil {
				t.Fatal(err)
			}
			ordinaryGlobalRequireIR(t, string(ir), fixture.pkg.PkgPath)
			parts, err = filepath.Glob(strings.TrimSuffix(fixture.task.OutLL, ".ll") + ".part-*")
			if err != nil || len(parts) != 0 {
				t.Fatal("validation-only ordinary declarations emitted cropped source chunks", parts, err)
			}
			for name, expected := range fixture.sources {
				actual, err := os.ReadFile(name)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("translation changed an original selected source", name, err)
				}
			}
		})
	}
}

func TestCompileOneOrdinaryGlobalDeclarationsSelectionGuards(t *testing.T) {
	for _, mutation := range []string{"missing-source", "wrong-platform-source", "missing-import-types", "output-is-imported-source"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := ordinaryGlobalCLIActualFixture(t, "amd64")
			fixture.config.Enabled = false
			const retained = "previous verified output\n"
			if mutation == "output-is-imported-source" {
				fixture.task.OutLL = filepath.Join(fixture.dependency.Dir, "state.go")
			} else if err := os.WriteFile(fixture.task.OutLL, []byte(retained), 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(fixture.task.OutLL)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing-source":
				if err := os.Rename(filepath.Join(fixture.dependency.Dir, "state.go"), filepath.Join(t.TempDir(), "retained-original.go")); err != nil {
					t.Fatal(err)
				}
			case "wrong-platform-source":
				changed := 0
				for index, name := range fixture.dependency.CompiledGoFiles {
					if filepath.Base(name) == "word_linux.go" {
						fixture.dependency.CompiledGoFiles[index] = filepath.Join(fixture.dependency.Dir, "word_other.go")
						changed++
					}
				}
				if changed != 1 {
					t.Fatal("platform source mutation did not apply exactly once")
				}
			case "missing-import-types":
				fixture.dependency.Types = nil
			}
			if err := compileOne(fixture.pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				fixture.task, false, fixture.config); err == nil {
				t.Fatal("missing or mismatched selected declarations acquired read authority")
			}
			after, err := os.ReadFile(fixture.task.OutLL)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected declaration source changed a retained output/input", err)
			}
		})
	}
}

func TestCompileOneOrdinaryGlobalDeclarationsLateGuard(t *testing.T) {
	for _, mutation := range []string{"same-size-bytes", "equal-byte-node", "same-package-bytes"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := ordinaryGlobalCLIActualFixture(t, "amd64")
			fixture.config.Enabled = false
			const retained = "previous verified output\n"
			if err := os.WriteFile(fixture.task.OutLL, []byte(retained), 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			fixture.config.Context = &continuationOutputCallbackContext{Context: fixture.config.Context,
				directory: filepath.Dir(fixture.task.OutLL), basename: filepath.Base(fixture.task.OutLL), callback: func() {
					called = true
					file := filepath.Join(fixture.dependency.Dir, "state.go")
					if mutation == "same-package-bytes" {
						file = filepath.Join(fixture.pkg.Dir, "consumer.go")
					}
					original := fixture.sources[file]
					if mutation == "equal-byte-node" {
						if err := os.Rename(file, filepath.Join(t.TempDir(), "retained-original.go")); err != nil {
							t.Fatal(err)
						}
					} else {
						changed := bytes.Replace(original, []byte("= 1"), []byte("= 2"), 1)
						if bytes.Equal(changed, original) || len(changed) != len(original) {
							t.Fatal("same-size source mutation did not apply")
						}
						original = changed
					}
					if err := os.WriteFile(file, original, 0600); err != nil {
						t.Fatal(err)
					}
				}}
			err := compileOne(fixture.pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				fixture.task, false, fixture.config)
			if !called || err == nil {
				t.Fatalf("late actual imported-source guard was not reached: called=%t error=%v", called, err)
			}
			if after, err := os.ReadFile(fixture.task.OutLL); err != nil || string(after) != retained {
				t.Fatal("late source failure published unverified IR", err)
			}
		})
	}
}

func TestCompileOneOrdinaryGlobalDeclarationsPrivateTailSourceAudit(t *testing.T) {
	for _, mutation := range []string{"complete", "unknown-helper-input", "unreferenced-helper-escape"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := ordinaryGlobalCLIActualFixture(t, "amd64")
			fixture.config.Enabled = false
			original := string(fixture.sources[fixture.task.AsmFile])
			body := "CMPB ·Flags(SB),$1\nJNE different\nMOVL $1,ret+0(FP)\nRET\ndifferent:\nMOVL $0,ret+0(FP)\nRET\n"
			if strings.Count(original, body) != 1 {
				t.Fatal("local root body must be replaced exactly once")
			}
			helper := "TEXT value<>(SB),4,$0-0\nJNE different\nMOVL $1,ret+0(FP)\nRET\ndifferent:\nMOVL $0,ret+0(FP)\nRET\n"
			source := strings.Replace(original, body, "CMPB ·Flags(SB),$1\nJMP value<>(SB)\n", 1) + helper
			if mutation == "unknown-helper-input" {
				source = strings.TrimSuffix(source, helper) + strings.Replace(helper, "MOVL $1,ret+0(FP)", "MOVL R15,ret+0(FP)", 1)
			} else if mutation == "unreferenced-helper-escape" {
				source += "TEXT unused<>(SB),4,$0-0\nCALL foreign(SB)\nRET\n"
			}
			if err := os.WriteFile(fixture.task.AsmFile, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			const retained = "previous verified output\n"
			if err := os.WriteFile(fixture.task.OutLL, []byte(retained), 0600); err != nil {
				t.Fatal(err)
			}
			err := compileOneAttempt(fixture.pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				fixture.task, false, fixture.config)
			output, readErr := os.ReadFile(fixture.task.OutLL)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if mutation == "complete" {
				if err != nil {
					t.Fatal("complete private tail source was not consumed", err)
				}
				ordinaryGlobalRequireIR(t, string(output), fixture.pkg.PkgPath)
			} else if err == nil || string(output) != retained {
				t.Fatal("invalid private helper was dropped or published", err)
			}
		})
	}
}

func TestCompileOneOrdinaryGlobalDeclarationsLoadEnvironmentIdentity(t *testing.T) {
	for _, axis := range []string{"actual-v2", "GOAMD64=v2", "GOFLAGS=-tags=unselected", "GOROOT=unselected", "late-CPU-change"} {
		t.Run(axis, func(t *testing.T) {
			profile := "v1"
			if axis == "actual-v2" {
				profile = "v2"
			}
			fixture := ordinaryGlobalCLIActualFixtureProfile(t, "amd64", profile)
			selectedProfile, ok := fixture.pkg.Types.Scope().Lookup("SelectedCPUProfile").(*types.Const)
			if !ok || selectedProfile.Val().ExactString() != strings.TrimPrefix(profile, "v") {
				t.Fatal("actual selected feature-tagged source does not match the load profile", selectedProfile)
			}
			fixture.config.Enabled = false
			selected := *fixture.config.x86CallerSelections[fixture.pkg]
			selected.env = append([]string(nil), selected.env...)
			fixture.config.x86CallerSelections = map[*packages.Package]*x86CallerPackageSelection{fixture.pkg: &selected}
			const retained = "previous verified output\n"
			if err := os.WriteFile(fixture.task.OutLL, []byte(retained), 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			if axis == "late-CPU-change" {
				fixture.config.Context = &continuationOutputCallbackContext{Context: fixture.config.Context,
					directory: filepath.Dir(fixture.task.OutLL), basename: filepath.Base(fixture.task.OutLL), callback: func() {
						called = true
						selected.env = append(selected.env, "GOAMD64=v2")
					}}
			} else if axis != "actual-v2" {
				selected.env = append(selected.env, axis)
			}
			err := compileOne(fixture.pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				fixture.task, false, fixture.config)
			if axis == "actual-v2" {
				if err != nil {
					t.Fatal("actual nonbaseline load was mislabeled as an invalid mutation", err)
				}
				output, readErr := os.ReadFile(fixture.task.OutLL)
				if readErr != nil {
					t.Fatal(readErr)
				}
				ordinaryGlobalRequireIR(t, string(output), fixture.pkg.PkgPath)
				return
			}
			if axis == "late-CPU-change" && !called {
				t.Fatal("late actual load-environment mutation was not reached", err)
			}
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("changed environment borrowed the original package selection", err)
			}
			if _, retryable := x86SDKNumericalRetryCause(err); retryable {
				t.Fatal("changed load environment became a retryable source exclusion", err)
			}
			if after, readErr := os.ReadFile(fixture.task.OutLL); readErr != nil || string(after) != retained {
				t.Fatal("changed load environment published output", readErr)
			}
		})
	}
}
