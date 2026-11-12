package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestFeatureCPPIncludedEOFDoesNotInventTranslationUnitNewline(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	const include = "../../src/runtime/go_tls.h"
	const header = "#include \"" + include + "\""
	const marker = "TEXT ·Probe(SB),$0-0\nRET\n"
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			input, dir := generatedHeaderFixture(t, target)
			file := input.AsmFiles[0]
			source := "#include \"eof.h\"\n\n" + marker
			for name, body := range map[string]string{file: source, "eof.h": header} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				input.Sources[name] = featureBytesSHA256([]byte(body))
			}
			input.Headers[file] = source
			input.Directories["."] = append(input.Directories["."], "eof.h")
			sort.Strings(input.Directories["."])
			tool := "src/runtime/go_tls.h"
			data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), tool))
			if err != nil {
				t.Fatal(err)
			}
			input.ToolSources = map[string]string{tool: featureBytesSHA256(data)}
			input.CPPIncludeSearchMisses = []gotoolprofile.CPPPackageSearchMiss{{
				Protocol: gotoolprofile.CPPPackageSearchMissProtocol, Assembly: file, Source: "module/eof.h",
				Include: include, PackageCandidate: include, ToolSource: tool,
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
				t.Fatalf("original included EOF Go/profile/CPP/LLVM object: %#v %v", report, err)
			}
			if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
				t.Fatal(err)
			}
			canonical, err := json.Marshal(report.FeatureSelection)
			if err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*gotoolprofile.SelectionProof){
				"drop absence": func(p *gotoolprofile.SelectionProof) { p.CPPIncludeSearchMisses = nil },
				"wrong parent": func(p *gotoolprofile.SelectionProof) { p.CPPIncludeSearchMisses[0].Source = "module/" + file },
			} {
				t.Run(name, func(t *testing.T) {
					var changed gotoolprofile.SelectionProof
					if err := json.Unmarshal(canonical, &changed); err != nil {
						t.Fatal(err)
					}
					mutate(&changed)
					if err := gotoolprofile.ValidateSelection(input, &changed, nil, true); err == nil {
						t.Fatal("included EOF consumer proof was downgraded")
					}
				})
			}
			canonicalDir, err := filepath.EvalSymlinks(dir)
			if err != nil {
				t.Fatal(err)
			}
			consumer := &featureConsumer{Input: input, Context: ctx, Dir: canonicalDir, Root: runtime.GOROOT()}
			originalMiss := input.CPPIncludeSearchMisses[0]
			input.CPPIncludeSearchMisses = nil
			if _, _, err := consumer.preprocessCPP(filepath.Join(canonicalDir, file), input.Module, nil); err == nil {
				t.Fatal("deleting the input absence contract downgraded active included EOF")
			}
			input.CPPIncludeSearchMisses = []gotoolprofile.CPPPackageSearchMiss{originalMiss}
			input.CPPIncludeSearchMisses[0].Source = "module/" + file
			if _, _, err := consumer.preprocessCPP(filepath.Join(canonicalDir, file), input.Module, nil); err == nil {
				t.Fatal("translation unit replaced the actual included-EOF operand parent")
			}
			input.CPPIncludeSearchMisses[0] = originalMiss

			// Updating the original bytes and hash cannot authorize a newline
			// that the active translation-unit input stack does not contain.
			source = marker + header
			if err := os.WriteFile(filepath.Join(dir, file), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources[file], input.Headers[file] = featureBytesSHA256([]byte(source)), source
			input.CPPIncludeSearchMisses[0].Source = "module/" + file
			if _, _, err := consumer.preprocessCPP(filepath.Join(canonicalDir, file), input.Module, nil); err == nil {
				t.Fatal("active CPP invented a translation-unit EOF newline")
			}
		})
	}
}
