package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestFeatureCPPCanonicalToolRelativeFiveArchitectureObjects(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			input, dir := generatedHeaderFixture(t, target)
			file := input.AsmFiles[0]
			source := "#include \"../../src/runtime/go_tls.h\"\nTEXT ·Probe(SB),$0-0\nRET\n"
			if err := os.WriteFile(filepath.Join(dir, file), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources[file], input.Headers[file] = featureBytesSHA256([]byte(source)), source
			tool := "src/runtime/go_tls.h"
			data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), tool))
			if err != nil {
				t.Fatal(err)
			}
			input.ToolSources = map[string]string{tool: featureBytesSHA256(data)}
			input.CPPIncludeSearchMisses = []gotoolprofile.CPPPackageSearchMiss{{
				Protocol: gotoolprofile.CPPPackageSearchMissProtocol, Assembly: file,
				Source: "module/" + file, Include: "../../src/runtime/go_tls.h",
				PackageCandidate: "../../src/runtime/go_tls.h", ToolSource: tool,
			}}
			t.Chdir(dir)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			config, err := resolveCompileConfig(true, "", true, 0)
			if err != nil {
				t.Fatal(err)
			}
			config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
			parts := strings.Split(target, "/")
			report, _, err := runOneTarget(targetSpec{Goos: parts[0], Goarch: parts[1]}, []string{"."}, nil,
				input.AsmFiles, input.Module, t.TempDir(), false, 0, true, false, true, repo, config)
			if err != nil || report.Success != 1 || report.Failed != 0 {
				t.Fatalf("real stock Go/package/CPP/LLVM tool fallback: %#v %v", report, err)
			}
			if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
				t.Fatal(err)
			}
			proofJSON, err := json.Marshal(report.FeatureSelection)
			if err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*gotoolprofile.SelectionProof){
				"missing absence": func(p *gotoolprofile.SelectionProof) { p.CPPIncludeSearchMisses = nil },
				"wrong source":    func(p *gotoolprofile.SelectionProof) { p.CPPIncludeSearchMisses[0].Source = "module/layout.go" },
				"wrong preferred": func(p *gotoolprofile.SelectionProof) {
					p.CPPIncludeSearchMisses[0].PackageCandidate = "../src/runtime/go_tls.h"
				},
				"wrong tool": func(p *gotoolprofile.SelectionProof) { p.CPPIncludeSearchMisses[0].ToolSource = "src/runtime/other.h" },
			} {
				t.Run(name, func(t *testing.T) {
					var changed gotoolprofile.SelectionProof
					if err := json.Unmarshal(proofJSON, &changed); err != nil {
						t.Fatal(err)
					}
					mutate(&changed)
					if err := gotoolprofile.ValidateSelection(input, &changed, nil, true); err == nil {
						t.Fatal("changed tool-relative search proof was accepted")
					}
				})
			}
		})
	}
}
