package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestSupplementalTestDeclarationsUseActualTypedRole(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"darwin/amd64", "linux/amd64", "windows/amd64", "linux/386", "windows/386"} {
		t.Run(target, func(t *testing.T) {
			input, dir := testDeclarationRoleFixture(t, target)
			t.Chdir(dir)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			env := featureEnvironment(os.Environ(), input.Observed.Environment)
			for _, tests := range []bool{false, true} {
				args := []string{"list", "-export", "-json"}
				if tests {
					args = append(args, "-test")
				}
				args = append(args, ".")
				if _, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, "go", args...); err != nil {
					t.Fatalf("actual stock Go export tests=%v: %v\n%s", tests, err, stderr)
				}
			}
			config, err := resolveCompileConfig(true, "", true, 0)
			if err != nil {
				t.Fatal(err)
			}
			config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
			parts := strings.Split(target, "/")
			report, _, err := runOneTarget(targetSpec{Goos: parts[0], Goarch: parts[1]}, []string{"."}, nil,
				input.AsmFiles, input.Module, t.TempDir(), false, 0, true, false, true, repo, config)
			if err != nil || report.Failed != 0 || report.Success != 1 {
				t.Fatalf("real bodyless test declaration was replaced by inferred i64: %#v: %v", report, err)
			}
			if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
				t.Fatal(err)
			}
			for _, pkg := range report.FeatureSelection.Packages {
				for _, name := range pkg.GoFiles {
					if strings.HasSuffix(name, "_test.go") {
						t.Fatal("supplemental test declaration was falsely recorded as ordinary source")
					}
				}
			}
			if len(report.FeatureSelection.TestDeclarations) != 1 || len(report.FeatureSelection.TestDeclarations[0].Declarations) != 3 {
				t.Fatal("actual typed test signatures were not retained independently")
			}
			checkTestDeclarationReaderMutations(t, input, report.FeatureSelection)
		})
	}
}

func checkTestDeclarationReaderMutations(t *testing.T, input *featureInput, proof *gotoolprofile.SelectionProof) {
	t.Helper()
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*gotoolprofile.SelectionProof){
		"missing protocol":   func(p *gotoolprofile.SelectionProof) { p.SignatureSourceProtocol = "" },
		"missing test proof": func(p *gotoolprofile.SelectionProof) { p.TestDeclarations = nil },
		"missing use":        func(p *gotoolprofile.SelectionProof) { p.CPP[0].Signatures = nil },
		"wrong export":       func(p *gotoolprofile.SelectionProof) { p.TestDeclarations[0].ExportSHA256 = strings.Repeat("a", 64) },
		"wrong tool": func(p *gotoolprofile.SelectionProof) {
			p.TestDeclarations[0].CompileToolSHA256 = strings.Repeat("a", 64)
		},
		"wrong target":  func(p *gotoolprofile.SelectionProof) { p.TestDeclarations[0].Target = "js/wasm" },
		"wrong profile": func(p *gotoolprofile.SelectionProof) { p.TestDeclarations[0].ProfileID = strings.Repeat("a", 64) },
		"wrong tags":    func(p *gotoolprofile.SelectionProof) { p.TestDeclarations[0].CustomTags = []string{"alternate"} },
		"wrong variant": func(p *gotoolprofile.SelectionProof) {
			p.TestDeclarations[0].VariantID = p.TestDeclarations[0].PackagePath + ".test"
		},
		"wrong type": func(p *gotoolprofile.SelectionProof) {
			p.TestDeclarations[0].Declarations[0].GoType = "func(uint64) uint64"
		},
		"wrong layout": func(p *gotoolprofile.SelectionProof) {
			p.TestDeclarations[0].Declarations[0].Layout = json.RawMessage(`{"Ret":"i64"}`)
		},
		"removed test source": func(p *gotoolprofile.SelectionProof) { delete(p.TestDeclarations[0].SourceSHA256, "decl_test.go") },
		"changed test source": func(p *gotoolprofile.SelectionProof) {
			p.TestDeclarations[0].SourceSHA256["decl_test.go"] = strings.Repeat("a", 64)
		},
		"removed source selection": func(p *gotoolprofile.SelectionProof) { p.TestDeclarations[0].GoFiles = p.Packages[0].GoFiles },
		"ordinary test role": func(p *gotoolprofile.SelectionProof) {
			p.Packages[0].GoFiles = append(p.Packages[0].GoFiles, "decl_test.go")
		},
		"falsely ordinary signature": func(p *gotoolprofile.SelectionProof) { p.CPP[0].Signatures[0].Role = "ordinary_decl" },
		"unconsumed symbol": func(p *gotoolprofile.SelectionProof) {
			p.TestDeclarations[0].Declarations[0].Symbol += "Extra"
		},
		"missing dependency export": func(p *gotoolprofile.SelectionProof) { p.TestDeclarations[0].Imports = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var changed gotoolprofile.SelectionProof
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := gotoolprofile.ValidateSelection(input, &changed, nil, true); err == nil {
				t.Fatal("changed/omitted supplemental source proof was accepted")
			}
		})
	}
}

func TestSupplementalTestDeclarationsRejectUnprovedSourceRole(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"poison":            "package header\nfunc U8ToF32s(x uint8) float32\nvar Poison = undefinedTestOnly\n",
		"external":          "package header_test\nfunc U8ToF32s(x uint8) float32\n",
		"body":              "package header\nfunc U8ToF32s(x uint8) float32 { return float32(x) }\n",
		"wrong typed width": "package header\nfunc U8ToF32s(x uint8) float64\n",
	} {
		t.Run(name, func(t *testing.T) {
			input, dir := testDeclarationRoleFixture(t, "linux/amd64")
			if err := os.WriteFile(filepath.Join(dir, "decl_test.go"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources["decl_test.go"], input.Headers["decl_test.go"] = featureBytesSHA256([]byte(source)), source
			if name == "wrong typed width" {
				// Keep the true declared frame size so this reaches the typed
				// float-width check rather than source ABI-size applicability.
				asm := `TEXT ·U8ToF32s(SB),4,$0-16
	MOVBLZX x+0(FP), AX
	CVTSL2SS AX, X0
	MOVSS X0, ret+8(FP)
	RET
`
				filename := input.AsmFiles[0]
				if err := os.WriteFile(filepath.Join(dir, filename), []byte(asm), 0600); err != nil {
					t.Fatal(err)
				}
				input.Sources[filename], input.Headers[filename] = featureBytesSHA256([]byte(asm)), asm
			}
			t.Chdir(dir)
			config, err := resolveCompileConfig(true, "", true, 0)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
			report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil,
				input.AsmFiles, input.Module, t.TempDir(), false, 0, true, false, true, repo, config)
			if err == nil && report.Failed == 0 && report.NotApplicable == 0 {
				t.Fatal("unproved test declaration/type acquired a successful object")
			}
		})
	}
}

func TestSupplementalTestDeclarationsRejectMissingActualTestDependency(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	input, dir := testDeclarationRoleFixture(t, "linux/amd64")
	module, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod": string(module) + "\nrequire example.invalid/testonly v0.0.0\n" +
			"replace example.invalid/testonly => ./test-dependency-missing\n",
		"poison_test.go": "package header\nimport _ \"example.invalid/testonly\"\n",
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name] = featureBytesSHA256([]byte(source))
		if strings.HasSuffix(name, ".go") {
			input.Headers[name] = source
		}
	}
	input.Directories["."] = append(input.Directories["."], "poison_test.go")
	sort.Strings(input.Directories["."])
	t.Chdir(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	env := featureEnvironment(os.Environ(), input.Observed.Environment)
	if _, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, "go", "list", "-export", "-json", "."); err != nil {
		t.Fatalf("ordinary stock Go package unexpectedly required tests: %v; %s", err, stderr)
	}
	_, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, "go", "list", "-test", "-export", "-json", ".")
	if err == nil || !strings.Contains(string(stderr), "test-dependency-missing") {
		t.Fatalf("actual test dependency failure was not reproduced: %v; %s", err, stderr)
	}
	config, err := resolveCompileConfig(true, "", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
	report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil,
		input.AsmFiles, input.Module, t.TempDir(), false, 0, true, false, true, repo, config)
	if report.Failed != 1 || report.Success != 0 || report.NotApplicable != 0 ||
		len(report.Fails) != 1 || !strings.Contains(report.Fails[0].Err, "test-dependency-missing") {
		t.Fatalf("required test declaration became success/N/A or lost its actual missing dependency: %#v; %v", report, err)
	}
}

func testDeclarationRoleFixture(t *testing.T, target string) (*featureInput, string) {
	t.Helper()
	input, dir := generatedHeaderFixture(t, target)
	input.SignatureSourceProtocol = gotoolprofile.SignatureSourceProtocol
	word := 8
	if strings.HasSuffix(target, "/386") {
		word = 4
	}
	files := map[string]string{
		"layout.go": "package header\n",
		"decl_test.go": `package header
import "example.invalid/header/dep"
func U8ToF32s(x uint8) float32
func EchoF32(x dep.F32) dep.F32
func EchoF64(x float64) float64
`,
		"dep/layout.go": "package dep\ntype F32 = float32\n",
		input.AsmFiles[0]: fmt.Sprintf(`TEXT ·U8ToF32s(SB),4,$0-%d
	MOVBLZX x+0(FP), AX
	CVTSL2SS AX, X0
	MOVSS X0, ret+%d(FP)
	RET
TEXT ·EchoF32(SB),4,$0-%d
	MOVSS x+0(FP), X0
	MOVSS X0, ret+%d(FP)
	RET
TEXT ·EchoF64(SB),4,$0-16
	MOVSD x+0(FP), X0
	MOVSD X0, ret+8(FP)
	RET
`, word+4, word, word+4, word),
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name], input.Headers[name] = featureBytesSHA256([]byte(source)), source
	}
	input.Directories["."] = append(input.Directories["."], "decl_test.go")
	sort.Strings(input.Directories["."])
	return input, dir
}

func TestSupplementalTestCalleeDeclarationsAcrossSourceFiles(t *testing.T) {
	// Hosted machines need not export temporary roots. Exercise the production
	// environment setup rather than borrowing a developer's TMPDIR.
	t.Setenv("GOENV", "off")
	t.Setenv("TMPDIR", "")
	t.Setenv("GOTMPDIR", "")
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"darwin/amd64", "linux/amd64", "windows/amd64", "linux/386", "windows/386"} {
		t.Run(target, func(t *testing.T) {
			input, dir := testDeclarationRoleFixture(t, target)
			parts := strings.Split(target, "/")
			arch := parts[1]
			word := 8
			if arch == "386" {
				word = 4
			}
			callee := "callee_" + arch + ".s"
			sources := map[string]string{
				"decl_test.go": `package header
func CallF64(x float64) float64
func TailF64(x float64) float64
func CallF32(x uint8) float32
func TailF32(x uint8) float32
`,
				"callee_test.go": `package header
func ActualF64(x float64) float64
func ActualF32(x uint8) float32
func UnusedTestSymbol() uint64
`,
				input.AsmFiles[0]: `TEXT ·CallF64(SB),4,$16-16
	MOVSD x+0(FP), X0
	MOVSD X0, 0(SP)
	CALL ·ActualF64(SB)
	MOVSD 8(SP), X0
	MOVSD X0, ret+8(FP)
	RET
TEXT ·TailF64(SB),4,$0-16
	JMP ·ActualF64(SB)
`,
				callee: `TEXT ·ActualF64(SB),4,$0-16
	MOVSD x+0(FP), X0
	MOVSD X0, ret+8(FP)
	RET
`,
			}
			sources[input.AsmFiles[0]] += fmt.Sprintf(`TEXT ·CallF32(SB),4,$16-%d
	MOVBLZX x+0(FP), AX
	MOVB AX, 0(SP)
	CALL ·ActualF32(SB)
	MOVSS %d(SP), X0
	MOVSS X0, ret+%d(FP)
	RET
TEXT ·TailF32(SB),4,$0-%d
	JMP ·ActualF32(SB)
`, word+4, word, word, word+4)
			sources[callee] += fmt.Sprintf(`TEXT ·ActualF32(SB),4,$0-%d
	MOVBLZX x+0(FP), AX
	CVTSL2SS AX, X0
	MOVSS X0, ret+%d(FP)
	RET
`, word+4, word)
			for name, source := range sources {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				input.Sources[name], input.Headers[name] = featureBytesSHA256([]byte(source)), source
			}
			input.AsmFiles = append(input.AsmFiles, callee)
			input.Directories["."] = append(input.Directories["."], callee, "callee_test.go")
			sort.Strings(input.AsmFiles)
			sort.Strings(input.Directories["."])
			t.Chdir(dir)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			env := featureEnvironment(os.Environ(), input.Observed.Environment)
			if _, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, "go", "list", "-test", "-export", "-json", "."); err != nil {
				t.Fatalf("actual stock Go caller/callee declarations: %v\n%s", err, stderr)
			}
			config, err := resolveCompileConfig(true, "", true, 0)
			if err != nil {
				t.Fatal(err)
			}
			config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
			report, _, err := runOneTarget(targetSpec{Goos: parts[0], Goarch: arch}, []string{"."}, nil,
				input.AsmFiles, input.Module, t.TempDir(), false, 0, true, false, true, repo, config)
			if err != nil || report.Failed != 0 || report.Success != 2 {
				t.Fatalf("actual same-package test callee was inferred as i64: %#v: %v", report, err)
			}
			if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
				t.Fatal(err)
			}
			if len(report.FeatureSelection.TestDeclarations) != 1 || len(report.FeatureSelection.TestDeclarations[0].Declarations) != 6 {
				t.Fatal("callee declarations were duplicated or unused symbols were registered")
			}
			calleeUses := 0
			for _, cpp := range report.FeatureSelection.CPP {
				for _, signature := range cpp.Signatures {
					if signature.Callee {
						calleeUses++
						if signature.Symbol != input.Module+".ActualF64" && signature.Symbol != input.Module+".ActualF32" {
							t.Fatal("a symbol not consumed by this source acquired a callee role")
						}
					}
				}
			}
			if calleeUses != 2 {
				t.Fatal("CALL/JMP uses of one target were not normalized and deduplicated")
			}
			canonical, err := json.Marshal(report.FeatureSelection)
			if err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*gotoolprofile.SelectionProof){
				"entry disguised as callee": func(proof *gotoolprofile.SelectionProof) {
					proof.CPP[0].Signatures[0].Callee = true
					proof.CPP[0].Signatures[0].Role = "asm_fallback"
				},
				"callee disguised as entry": func(proof *gotoolprofile.SelectionProof) {
					for index := range proof.CPP[1].Signatures {
						proof.CPP[1].Signatures[index].Callee = false
					}
				},
				"wrong callee width": func(proof *gotoolprofile.SelectionProof) {
					proof.CPP[1].Signatures[0].LayoutSHA256 = strings.Repeat("a", 64)
				},
				"unconsumed callee symbol": func(proof *gotoolprofile.SelectionProof) {
					proof.CPP[1].Signatures[0].Symbol += "Other"
				},
			} {
				t.Run(name, func(t *testing.T) {
					var changed gotoolprofile.SelectionProof
					if err := json.Unmarshal(canonical, &changed); err != nil {
						t.Fatal(err)
					}
					mutate(&changed)
					if err := gotoolprofile.ValidateSelection(input, &changed, nil, true); err == nil {
						t.Fatal("changed entry/callee source identity was accepted")
					}
				})
			}
		})
	}
}
