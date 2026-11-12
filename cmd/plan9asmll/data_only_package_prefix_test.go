package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestDataOnlyNativePackagePrefixNames(t *testing.T) {
	const source = "GLOBL ·payload(SB),$8\nGLOBL ·private<>(SB),$16\nGLOBL external·literal(SB),$4\n"
	for _, test := range []struct {
		path, prefix string
	}{
		{"example.invalid/asmhdr.dir", "example.invalid/asmhdr%2edir"},
		{"example.invalid/parent.dir/plain", "example.invalid/parent.dir/plain"},
		{"example.invalid/percent%name", "example.invalid/percent%25name"},
		{"example.invalid/é", "example.invalid/%c3%a9"},
		{"example.invalid/quote\"name", "example.invalid/quote%22name"},
		{"example.invalid/space name", "example.invalid/space%20name"},
		{"example.invalid/control\tname", "example.invalid/control%09name"},
		{"example.invalid/del\x7fname", "example.invalid/del%7fname"},
	} {
		t.Run(test.path, func(t *testing.T) {
			directory := t.TempDir()
			filename := filepath.Join(directory, "data.s")
			if err := os.WriteFile(filename, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			proof, err := proveDataOnlyAssembly(&packages.Package{PkgPath: test.path},
				asmTask{AsmFile: filename}, file, "linux/amd64", nil, compileConfig{Context: ctx})
			if err != nil {
				t.Fatalf("original Go data symbol prefix differs from its bound package: %v", err)
			}
			want := map[string]int64{
				test.prefix + ".payload": 8, test.prefix + ".private<>": 16, "external.literal": 4,
			}
			if len(proof.Symbols) != len(want) {
				t.Fatalf("incomplete original symbol inventory: %+v", proof.Symbols)
			}
			for _, symbol := range proof.Symbols {
				if size, found := want[symbol.Key()]; !found || size != symbol.Size {
					t.Fatalf("native spelling/static identity was rewritten: %+v", symbol)
				}
			}
			replacements := []string{"·other", "external·other"}
			if test.path != test.prefix {
				replacements = append(replacements, test.path+"·payload")
			}
			for _, replacement := range replacements {
				changed, err := plan9asm.Parse(plan9asm.ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				changed.Globl[0].Sym = replacement
				if _, err := proveDataOnlyAssembly(&packages.Package{PkgPath: test.path},
					asmTask{AsmFile: filename}, changed, "linux/amd64", nil, compileConfig{Context: ctx}); err == nil {
					t.Fatalf("native source name accepted a rewritten symbol: %q", replacement)
				}
			}
		})
	}
}

func TestDataOnlyEscapedPackageCurrentSignatureProof(t *testing.T) {
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			input, directory := featureConsumerFixture(t)
			input.Module = "example.invalid/asmhdr.dir"
			module := "module " + input.Module + "\n\ngo 1.24\n"
			if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte(module), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources["go.mod"] = featureBytesSHA256([]byte(module))
			if err := os.Remove(filepath.Join(directory, "probe_amd64.s")); err != nil {
				t.Fatal(err)
			}
			delete(input.Sources, "probe_amd64.s")
			delete(input.Headers, "probe_amd64.s")
			const source = "DATA ·payload+0(SB)/8,$0x123456789abcdef0\nGLOBL ·payload(SB),$8\nGLOBL ·zero(SB),$16\n"
			if err := os.WriteFile(filepath.Join(directory, "tables.s"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources["tables.s"], input.Headers["tables.s"] = featureBytesSHA256([]byte(source)), source
			input.AsmFiles = []string{"tables.s"}
			input.Directories["."] = []string{"fallback.go", "go.mod", "selected.go", "tables.s"}
			input.SignatureSourceProtocol = gotoolprofile.SignatureSourceProtocol
			input.TestDependencySourceProtocol = gotoolprofile.TestDependencyProtocol
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			input.Observed, err = gotoolprofile.Capture(ctx, goBinary, t.TempDir(), os.Environ(), target, nil, gotoolprofile.RunBounded)
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
			t.Chdir(directory)
			query := &gotoolprofile.SignatureQueryProof{Protocol: gotoolprofile.SignatureQueryProtocol}
			queryConfig := config
			queryConfig.Enabled, queryConfig.SignatureQuery = false, query
			result, _, err := runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module,
				t.TempDir(), false, 0, true, false, true, repository, queryConfig)
			if err != nil || result.Failed != 0 || result.Success != 0 || len(query.Requests) != 0 {
				t.Fatalf("data-only metadata query claims failure/signature/object: %+v, %v", result, err)
			}
			if err := gotoolprofile.ValidateSignatureQuery(input, query, nil); err != nil {
				t.Fatal(err)
			}
			if err := gotoolprofile.ValidateSelection(input, query.Selection, nil, true); err == nil {
				t.Fatal("native data-only query was accepted as a final LLVM object proof")
			}
			output := t.TempDir()
			result, _, err = runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module,
				output, false, 0, true, false, true, repository, config)
			if err != nil || result.Success != 1 || result.Failed != 0 || result.NotApplicable != 0 {
				t.Fatalf("escaped package data-only object: %+v, %v", result, err)
			}
			if err := gotoolprofile.ValidateSelection(input, result.FeatureSelection, nil, true); err != nil {
				t.Fatal(err)
			}
			checkDataOnlyAssemblyProofMutants(t, input, result.FeatureSelection)
			object := filepath.Join(output, filepath.FromSlash(input.Module), "tables.s.o")
			if info, err := os.Stat(object); err != nil || info.Size() == 0 {
				t.Fatalf("success omitted its actual LLVM object: %v", err)
			}
		})
	}
}
