package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestDataOnlyAssemblyCurrentSignatureProtocolAcrossTargets(t *testing.T) {
	repo, err := filepath.Abs("../..")
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
		t.Run(target, func(t *testing.T) {
			input, dir := featureConsumerFixture(t)
			if err := os.Remove(filepath.Join(dir, "probe_amd64.s")); err != nil {
				t.Fatal(err)
			}
			const source = "DATA ·payload+0(SB)/8,$0x123456789abcdef0\nGLOBL ·payload(SB),$8\nGLOBL ·zero(SB),$16\n"
			if err := os.WriteFile(filepath.Join(dir, "tables.s"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			delete(input.Sources, "probe_amd64.s")
			delete(input.Headers, "probe_amd64.s")
			input.Sources["tables.s"], input.Headers["tables.s"] = featureBytesSHA256([]byte(source)), source
			input.AsmFiles = []string{"tables.s"}
			input.SignatureSourceProtocol = gotoolprofile.SignatureSourceProtocol
			input.TestDependencySourceProtocol = gotoolprofile.TestDependencyProtocol
			input.Directories["."] = []string{"fallback.go", "go.mod", "selected.go", "tables.s"}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
			config.Context, config.FeaturePath = ctx, writeFeatureInput(t, input)
			spec, err := parseTargetSpec(target)
			if err != nil {
				t.Fatal(err)
			}
			output := t.TempDir()
			t.Chdir(dir)
			query := &gotoolprofile.SignatureQueryProof{Protocol: gotoolprofile.SignatureQueryProtocol}
			queryConfig := config
			queryConfig.Enabled, queryConfig.SignatureQuery = false, query
			queryReport, _, err := runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module,
				t.TempDir(), false, 0, false, false, true, repo, queryConfig)
			if err != nil || queryReport.Failed != 0 || queryReport.Success != 0 || query.Selection == nil ||
				len(query.Selection.Outputs) != 0 || len(query.Selection.TestDeclarations) != 0 || len(query.Requests) != 0 {
				t.Fatalf("data-only query acquired a final signature or LLVM outcome: report=%+v err=%v", queryReport, err)
			}
			if len(query.Selection.CPP) != 1 || query.Selection.CPP[0].Emission != "data_only" ||
				query.Selection.CPP[0].DataOnlyAssembly == nil {
				t.Fatal("query omitted the actual data-only source/native role")
			}
			if err := gotoolprofile.ValidateSignatureQuery(input, query, nil); err != nil {
				t.Fatalf("actual data-only metadata query was rejected: %v", err)
			}
			if err := gotoolprofile.ValidateSelection(input, query.Selection, nil, true); err == nil {
				t.Fatal("data-only native query was accepted as an LLVM object outcome")
			}
			report, _, err := runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module, output, false, 0, true, false, true, repo, config)
			if err != nil || report.Success != 1 || report.Failed != 0 {
				t.Fatalf("legitimate globals-only assembly must compile: report=%+v err=%v", report, err)
			}
			if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
				t.Fatalf("globals-only object was rejected by the current signature protocol: %v", err)
			}
			if !reflect.DeepEqual(query.Selection.CPP[0].DataOnlyAssembly, report.FeatureSelection.CPP[0].DataOnlyAssembly) {
				t.Fatal("query and final data-only native identities differ")
			}
			checkDataOnlyAssemblyProofMutants(t, input, report.FeatureSelection)
			object := filepath.Join(output, filepath.FromSlash(input.Module), "tables.s.o")
			if info, err := os.Stat(object); err != nil || info.Size() == 0 {
				t.Fatalf("globals-only success lacks a real LLVM object: %v", err)
			}
		})
	}
}

func TestDataOnlyNativeOracleBindsActualGoGlobalsAndRejectsTEXT(t *testing.T) {
	dir := t.TempDir()
	pkg := &packages.Package{PkgPath: "example.invalid/data"}
	task := asmTask{AsmFile: filepath.Join(dir, "data.s")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg := compileConfig{Context: ctx}
	for _, test := range []struct {
		name, source string
		mutate       func(*plan9asm.File)
		wantErr      bool
	}{
		{name: "BSS", source: "GLOBL ·zero(SB),$16\n"},
		{name: "static relocation", source: "DATA local<>+0(SB)/8,$·zero(SB)\nGLOBL local<>(SB),8,$8\nGLOBL ·zero(SB),$16\n"},
		{name: "TEXT", source: "GLOBL ·zero(SB),$16\nTEXT ·fn(SB),4,$0-0\nRET\n", wantErr: true},
		{name: "hidden TEXT", source: "GLOBL ·zero(SB),$16\nTEXT ·fn(SB),4,$0-0\nRET\n", mutate: func(f *plan9asm.File) { f.Funcs = nil }, wantErr: true},
		{name: "changed name", source: "GLOBL ·zero(SB),$16\n", mutate: func(f *plan9asm.File) { f.Globl[0].Sym = "·other" }, wantErr: true},
		{name: "changed size", source: "GLOBL ·zero(SB),$16\n", mutate: func(f *plan9asm.File) { f.Globl[0].Size++ }, wantErr: true},
		{name: "missing global", source: "GLOBL ·zero(SB),$16\n", mutate: func(f *plan9asm.File) { f.Globl = nil }, wantErr: true},
		{name: "duplicate global", source: "GLOBL ·zero(SB),$16\n", mutate: func(f *plan9asm.File) { f.Globl = append(f.Globl, f.Globl[0]) }, wantErr: true},
		{name: "missing DATA global", source: "DATA orphan<>+0(SB)/8,$1\n", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(task.AsmFile, []byte(test.source), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			if test.mutate != nil {
				test.mutate(file)
			}
			proof, err := proveDataOnlyAssembly(pkg, task, file, "linux/amd64", nil, cfg)
			if (err != nil) != test.wantErr || !test.wantErr && (proof == nil || len(proof.Symbols) == 0) {
				t.Fatalf("native data-only claim differs from Go and translated globals: proof=%+v err=%v", proof, err)
			}
		})
	}
}

func checkDataOnlyAssemblyProofMutants(t *testing.T, input *featureInput, original *featureSelectionProof) {
	t.Helper()
	if len(original.CPP) != 1 || original.CPP[0].Emission != "data_only" || original.CPP[0].DataOnlyAssembly == nil {
		t.Fatal("missing independently assembled data-only scope witness")
	}
	if len(original.CPP[0].DataOnlyAssembly.Symbols) != 2 {
		t.Fatal("native inventory omitted DATA/BSS symbols")
	}
	for name, mutate := range map[string]func(*featureSelectionProof){
		"missing witness":  func(p *featureSelectionProof) { p.CPP[0].DataOnlyAssembly = nil },
		"missing emission": func(p *featureSelectionProof) { p.CPP[0].Emission = "" },
		"normal emission":  func(p *featureSelectionProof) { p.CPP[0].Emission = "assembly" },
		"false empty":      func(p *featureSelectionProof) { p.CPP[0].Emission = "symbol_free" },
		"protocol": func(p *featureSelectionProof) {
			p.CPP[0].DataOnlyAssembly.Native.Protocol = gotoolprofile.EmptyAssemblyProtocol
		},
		"source": func(p *featureSelectionProof) {
			p.CPP[0].DataOnlyAssembly.Native.SourceSHA256 = featureBytesSHA256(nil)
		},
		"package":    func(p *featureSelectionProof) { p.CPP[0].DataOnlyAssembly.Native.PackagePath += "/other" },
		"profile":    func(p *featureSelectionProof) { p.CPP[0].DataOnlyAssembly.Native.ProfileID = "wrong" },
		"target":     func(p *featureSelectionProof) { p.CPP[0].DataOnlyAssembly.Native.Target = "linux/other" },
		"Go version": func(p *featureSelectionProof) { p.CPP[0].DataOnlyAssembly.Native.GoVersion = "go1.20.14" },
		"assembler": func(p *featureSelectionProof) {
			p.CPP[0].DataOnlyAssembly.Native.AsmToolSHA256 = featureBytesSHA256(nil)
		},
		"missing native object": func(p *featureSelectionProof) { p.CPP[0].DataOnlyAssembly.Native.ObjectSHA256 = "" },
		"empty listing": func(p *featureSelectionProof) {
			p.CPP[0].DataOnlyAssembly.Native.ListingSHA256 = featureBytesSHA256(nil)
		},
		"missing symbols": func(p *featureSelectionProof) { p.CPP[0].DataOnlyAssembly.Symbols = nil },
		"TEXT symbol":     func(p *featureSelectionProof) { p.CPP[0].DataOnlyAssembly.Symbols[0].Kind = "STEXT" },
		"negative size":   func(p *featureSelectionProof) { p.CPP[0].DataOnlyAssembly.Symbols[0].Size = -1 },
		"duplicate symbols": func(p *featureSelectionProof) {
			p.CPP[0].DataOnlyAssembly.Symbols[1] = p.CPP[0].DataOnlyAssembly.Symbols[0]
		},
		"missing LLVM object": func(p *featureSelectionProof) { p.Outputs = nil },
		"mixed signatures": func(p *featureSelectionProof) {
			p.CPP[0].Signatures = []gotoolprofile.SignatureSource{{Symbol: "unproved", Role: "asm_fallback", LayoutSHA256: featureBytesSHA256(nil)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			proof := *original
			proof.CPP = append([]featureCPPProof(nil), original.CPP...)
			dataOnly := *original.CPP[0].DataOnlyAssembly
			dataOnly.Symbols = append([]gotoolprofile.DataOnlySymbol(nil), dataOnly.Symbols...)
			proof.CPP[0].DataOnlyAssembly = &dataOnly
			mutate(&proof)
			if err := gotoolprofile.ValidateSelection(input, &proof, nil, true); err == nil {
				t.Fatal("changed data-only scope or missing mandatory object was accepted")
			}
		})
	}
}
