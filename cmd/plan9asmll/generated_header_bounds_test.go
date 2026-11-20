package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestGeneratedHeaderLargeMetadataAndIndependentConsumer(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			input, directory := generatedHeaderFixture(t, target)
			file := filepath.Join(directory, "layout.go")
			original, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var source strings.Builder
			source.Write(original)
			for index := 0; index < 5000; index++ {
				fmt.Fprintf(&source, "const Value%d = %d\n", index, index)
			}
			if err := os.WriteFile(file, []byte(source.String()), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources["layout.go"] = featureBytesSHA256([]byte(source.String()))
			input.Headers["layout.go"] = source.String()
			assembly := "#include \"go_asm.h\"\nTEXT ·Probe(SB),$0-0\nRET\n#ifdef const_Value4999\nDATA ·Late(SB)/8,$const_Value4999\nGLOBL ·Late(SB),8,$8\n#endif\n"
			if err := os.WriteFile(filepath.Join(directory, input.AsmFiles[0]), []byte(assembly), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources[input.AsmFiles[0]] = featureBytesSHA256([]byte(assembly))
			input.Headers[input.AsmFiles[0]] = assembly
			t.Chdir(directory)
			parts := strings.Split(target, "/")
			spec := targetSpec{Goos: parts[0], Goarch: parts[1]}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			config := compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx}
			metadata, err := queryGeneratedHeaders(spec, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(), config)
			if err != nil {
				t.Fatal(err)
			}
			if len(metadata.Headers) != 1 || len(metadata.Headers[0].Definitions) <= 5000 || metadata.Headers[0].Definitions["const_Value4999"] != "4999" {
				t.Fatal("actual compiler/selected-types query truncated large definitions")
			}
			encoded, err := json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			var replay gotoolprofile.MetadataProof
			if err := json.Unmarshal(encoded, &replay); err != nil {
				t.Fatal(err)
			}
			if err := gotoolprofile.ValidateMetadata(input, &replay, nil); err != nil {
				t.Fatal(err)
			}
			for name, mutation := range map[string]func(map[string]string){
				"late value":    func(definitions map[string]string) { definitions["const_Value4999"] = "7" },
				"late presence": func(definitions map[string]string) { delete(definitions, "const_Value4999") },
			} {
				t.Run(name, func(t *testing.T) {
					var changed gotoolprofile.MetadataProof
					if err := json.Unmarshal(encoded, &changed); err != nil {
						t.Fatal(err)
					}
					mutation(changed.Headers[0].Definitions)
					changed.Headers[0].DefinitionsSHA256 = gotoolprofile.HeaderDefinitionSHA256(changed.Headers[0].Definitions)
					if err := gotoolprofile.ValidateGeneratedHeaderAgreement(input, metadata, &changed, nil); err == nil {
						t.Fatal("self-consistent late definition mutation passed independent compiler agreement")
					}
				})
			}
			input.GeneratedHeaders = metadata
			config, err = resolveCompileConfig(true, "", true, 0)
			if err != nil {
				t.Fatal(err)
			}
			config.FeaturePath = writeFeatureInput(t, input)
			config.Context = ctx
			report, _, err := runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(), false, 0, true, false, true, repo, config)
			if err != nil || report.Success != 1 || report.Failed != 0 {
				t.Fatalf("large generated header Go/CPP/LLVM object failed: %#v: %v", report, err)
			}
			proof := report.FeatureSelection
			if proof.GeneratedHeaders == nil || len(proof.CPP) != 1 {
				t.Fatal("large metadata was not independently consumed by an actual LLVM object")
			}
			if err := gotoolprofile.ValidateSelection(input, proof, nil, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}
