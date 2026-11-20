package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestGeneratedHeaderMacroOnlyActualEmptyObjectsAcrossTargets(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		for _, include := range []string{"go_asm.h", "./go_asm.h"} {
			t.Run(target+"/"+include, func(t *testing.T) {
				input, dir := generatedHeaderFixture(t, target)
				source := "#include \"" + include + "\"\n#ifdef const_Imported\n#define GENERATED_LAYOUT(X) MOVQ X, AX\n#endif\n"
				file := input.AsmFiles[0]
				if err := os.WriteFile(filepath.Join(dir, file), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				input.Sources[file], input.Headers[file] = featureBytesSHA256([]byte(source)), source
				t.Chdir(dir)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				spec, err := parseTargetSpec(target)
				if err != nil {
					t.Fatal(err)
				}
				metadata, err := queryGeneratedHeaders(spec, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(),
					compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx})
				if err != nil {
					t.Fatal(err)
				}
				input.GeneratedHeaders = metadata
				config, err := resolveCompileConfig(true, "", true, 0)
				if err != nil {
					t.Fatal(err)
				}
				config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
				report, _, err := runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(), false, 0, true, false, true, repo, config)
				if err != nil || report.Success != 1 || report.Failed != 0 {
					t.Fatalf("actual full generated header must reach native empty-object oracle and LLVM object: %#v: %v", report, err)
				}
				proof := report.FeatureSelection
				if proof == nil || proof.GeneratedHeaders == nil || len(proof.CPP) != 1 || proof.CPP[0].Emission != "symbol_free" || proof.CPP[0].EmptyAssembly == nil ||
					proof.CPP[0].Inputs["generated/"+input.Module+"/go_asm.h"] == "" {
					t.Fatalf("macro-only generated scope disappeared or lost its actual compiler/assembler origin: %#v", proof)
				}
				if err := gotoolprofile.ValidateSelection(input, proof, nil, true); err != nil {
					t.Fatal(err)
				}
				checkEmptyAssemblyProofMutants(t, input, proof)
			})
		}
	}
}
