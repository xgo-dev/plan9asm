package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestMacroOnlyAssemblyProducesRealObjectsAcrossSupportedTargets(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		for _, profiled := range []bool{false, true} {
			mode := "ordinary"
			if profiled {
				mode = "profiled"
			}
			t.Run(target+"/"+mode, func(t *testing.T) {
				input, dir := featureConsumerFixture(t)
				if err := os.Remove(filepath.Join(dir, "probe_amd64.s")); err != nil {
					t.Fatal(err)
				}
				const source = "// Shared macro definitions, with no object symbols.\n#define SHARED(X) MOVQ X, AX\n"
				if err := os.WriteFile(filepath.Join(dir, "macros.s"), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				delete(input.Sources, "probe_amd64.s")
				delete(input.Headers, "probe_amd64.s")
				input.Sources["macros.s"] = featureBytesSHA256([]byte(source))
				input.Headers["macros.s"] = source
				input.AsmFiles = []string{"macros.s"}
				input.Directories["."] = []string{"fallback.go", "go.mod", "macros.s", "selected.go"}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				input.Observed, err = gotoolprofile.Capture(ctx, binary, t.TempDir(), os.Environ(), target, nil, gotoolprofile.RunBounded)
				if err != nil {
					t.Fatal(err)
				}
				input.ID = gotoolprofile.ProfileID(input.Observed)
				config, err := resolveCompileConfig(true, "", true, 0)
				if err != nil {
					t.Fatal(err)
				}
				config.Context = ctx
				if profiled {
					config.FeaturePath = writeFeatureInput(t, input)
				}
				spec, err := parseTargetSpec(target)
				if err != nil {
					t.Fatal(err)
				}
				output := t.TempDir()
				t.Chdir(dir)
				report, _, err := runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module, output, false, 0, true, false, true, repoRoot, config)
				if err != nil || report.Success != 1 || report.Failed != 0 {
					t.Fatalf("macro-only scope must compile, not disappear: report=%+v err=%v", report, err)
				}
				object := filepath.Join(output, filepath.FromSlash(input.Module), "macros.s.o")
				if info, err := os.Stat(object); err != nil || info.Size() == 0 {
					t.Fatalf("reported success without a real LLVM object: %v", err)
				}
				if profiled {
					if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
						t.Fatalf("empty scope lacks actual CPP/LLVM consumption: %v", err)
					}
					checkEmptyAssemblyProofMutants(t, input, report.FeatureSelection)
				}
			})
		}
	}
}

func checkEmptyAssemblyProofMutants(t *testing.T, input *featureInput, original *featureSelectionProof) {
	t.Helper()
	if len(original.CPP) != 1 || original.CPP[0].Emission != "symbol_free" || original.CPP[0].EmptyAssembly == nil {
		t.Fatal("no explicit same-scope native emptiness witness")
	}
	for name, mutate := range map[string]func(*featureSelectionProof){
		"missing witness":  func(p *featureSelectionProof) { p.CPP[0].EmptyAssembly = nil },
		"missing emission": func(p *featureSelectionProof) { p.CPP[0].Emission = "" },
		"normal emission":  func(p *featureSelectionProof) { p.CPP[0].Emission = "assembly" },
		"source":           func(p *featureSelectionProof) { p.CPP[0].EmptyAssembly.SourceSHA256 = featureBytesSHA256(nil) },
		"package":          func(p *featureSelectionProof) { p.CPP[0].EmptyAssembly.PackagePath += "/other" },
		"profile":          func(p *featureSelectionProof) { p.CPP[0].EmptyAssembly.ProfileID = "wrong" },
		"target":           func(p *featureSelectionProof) { p.CPP[0].EmptyAssembly.Target = "linux/other" },
		"Go version":       func(p *featureSelectionProof) { p.CPP[0].EmptyAssembly.GoVersion = "go1.20.14" },
		"assembler":        func(p *featureSelectionProof) { p.CPP[0].EmptyAssembly.AsmToolSHA256 = featureBytesSHA256(nil) },
		"missing object":   func(p *featureSelectionProof) { p.CPP[0].EmptyAssembly.ObjectSHA256 = "" },
		"nonempty listing": func(p *featureSelectionProof) {
			p.CPP[0].EmptyAssembly.ListingSHA256 = featureBytesSHA256([]byte("symbol"))
		},
		"missing LLVM output": func(p *featureSelectionProof) { p.Outputs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			proof := *original
			proof.CPP = append([]featureCPPProof(nil), original.CPP...)
			empty := *original.CPP[0].EmptyAssembly
			proof.CPP[0].EmptyAssembly = &empty
			mutate(&proof)
			if err := gotoolprofile.ValidateSelection(input, &proof, nil, true); err == nil {
				t.Fatal("changed native empty-object scope or missing LLVM output was accepted")
			}
		})
	}
}

func TestEmptyAssemblyNativeOracleRejectsSymbolsAndInvalidSource(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg := compileConfig{Context: ctx}
	pkg := &packages.Package{PkgPath: "example.invalid/empty"}
	task := asmTask{AsmFile: filepath.Join(dir, "probe.s")}
	for _, test := range []struct {
		name    string
		source  string
		defines []string
		wantErr bool
	}{
		{name: "macro-only", source: "#define SHARED(X) MOVQ X, AX\n"},
		{name: "TEXT", source: "TEXT ·Probe(SB),$0-0\nRET\n", wantErr: true},
		{name: "GLOBL", source: "GLOBL ·zero(SB),$8\n", wantErr: true},
		{name: "DATA", source: "DATA ·payload+0(SB)/8,$1\nGLOBL ·payload(SB),$8\n", wantErr: true},
		{name: "invalid source", source: "NOT_A_GO_INSTRUCTION\n", wantErr: true},
		{name: "missing include", source: "#include \"missing.h\"\n", wantErr: true},
		{name: "missing final newline", source: "#define INCOMPLETE 1", wantErr: true},
		{name: "inactive CPU variant", source: "#ifdef GOAMD64_v3\nTEXT ·Probe(SB),$0-0\nRET\n#endif\n"},
		{name: "active CPU variant", source: "#ifdef GOAMD64_v3\nTEXT ·Probe(SB),$0-0\nRET\n#endif\n", defines: []string{"GOAMD64_v3"}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(task.AsmFile, []byte(test.source), 0600); err != nil {
				t.Fatal(err)
			}
			proof, err := proveEmptyAssembly(pkg, task, "linux/amd64", test.defines, cfg)
			if (err != nil) != test.wantErr || !test.wantErr && proof == nil {
				t.Fatalf("actual Go emptiness was invented: proof=%+v err=%v", proof, err)
			}
		})
	}
}
