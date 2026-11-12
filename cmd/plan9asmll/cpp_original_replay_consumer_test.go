package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestFeatureCPPOriginalExpandedOperandsRequireActualStageAndExactSet(t *testing.T) {
	for _, generated := range []bool{false, true} {
		name := "empty_active_set"
		if generated {
			name = "expanded_outside_operand"
		}
		t.Run(name, func(t *testing.T) {
			input, dir := generatedHeaderFixture(t, "linux/amd64")
			assembly := input.AsmFiles[0]
			source := "TEXT ·Probe(SB),4,$0-0\nRET\n"
			include, tool := "../../src/runtime/go_tls.h", "src/runtime/go_tls.h"
			if generated {
				source = "#define SELECT \\\n#include \"" + include + "\" \\\n\nSELECT\n" + source
			}
			if err := os.WriteFile(filepath.Join(dir, assembly), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources[assembly], input.Headers[assembly] = featureBytesSHA256([]byte(source)), source
			unit := gotoolprofile.CPPOriginalUnit{Includes: map[string]string{}}
			input.CPPSourceProtocol = gotoolprofile.CPPOriginalReplayProtocol
			input.CPPOriginals = &gotoolprofile.CPPOriginalReplayInput{
				Sources:                  map[string]string{"module/" + assembly: source},
				Units:                    map[string]gotoolprofile.CPPOriginalUnit{assembly: unit},
				RequiredExpandedOperands: map[string][]gotoolprofile.CPPPackageSearchMiss{},
			}
			if generated {
				data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), tool))
				if err != nil {
					t.Fatal(err)
				}
				input.ToolSources = map[string]string{tool: featureBytesSHA256(data)}
				input.CPPOriginals.Sources["tool/"+tool] = string(data)
				unit.Includes[include] = "tool/" + tool
			}
			canonical, err := filepath.EvalSymlinks(dir)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			consumer := &featureConsumer{Input: input, Context: ctx, Dir: canonical, Root: runtime.GOROOT()}
			file := filepath.Join(canonical, assembly)
			if _, _, err := consumer.preprocessCPP(file, input.Module, nil); err == nil {
				t.Fatal("input-only query graph was accepted at actual CPP/object stage")
			}
			_, _, required, err := gotoolprofile.ReplayCPPOriginal(input, assembly, input.Module, nil, nil)
			if err != nil || required == nil {
				t.Fatalf("actual full original replay did not return an explicit set: %v", err)
			}
			input.CPPOriginals.RequiredExpandedOperands[assembly] = required
			input.CPPIncludeSearchMisses = required
			if _, _, err := consumer.preprocessCPP(file, input.Module, nil); err != nil {
				t.Fatalf("complete independently supplied expanded set was rejected: %v", err)
			}
			encoded, err := gotoolprofile.MarshalConsumerInput(input)
			if err != nil {
				t.Fatal(err)
			}
			mutations := map[string]func(*gotoolprofile.ConsumerInput){
				"missing_set":          func(copy *gotoolprofile.ConsumerInput) { delete(copy.CPPOriginals.RequiredExpandedOperands, assembly) },
				"null_set":             func(copy *gotoolprofile.ConsumerInput) { copy.CPPOriginals.RequiredExpandedOperands[assembly] = nil },
				"delete_graph_only":    func(copy *gotoolprofile.ConsumerInput) { copy.CPPOriginals = nil },
				"delete_protocol_only": func(copy *gotoolprofile.ConsumerInput) { copy.CPPSourceProtocol = "" },
				"changed_original":     func(copy *gotoolprofile.ConsumerInput) { copy.CPPOriginals.Sources["module/"+assembly] += "\n" },
				"paired_original_and_hash": func(copy *gotoolprofile.ConsumerInput) {
					changed := copy.CPPOriginals.Sources["module/"+assembly] + "GLOBL ·forged(SB),$8\n"
					copy.CPPOriginals.Sources["module/"+assembly] = changed
					copy.Sources[assembly] = featureBytesSHA256([]byte(changed))
				},
				"extra_unconsumed_receipt": func(copy *gotoolprofile.ConsumerInput) {
					miss := gotoolprofile.CPPPackageSearchMiss{Protocol: gotoolprofile.CPPExpandedPackageSearchMissProtocol,
						Assembly: assembly, Include: include, PackageCandidate: include, ToolSource: tool}
					copy.CPPIncludeSearchMisses = append(copy.CPPIncludeSearchMisses, miss)
				},
			}
			if generated {
				mutations["paired_deleted_receipt"] = func(copy *gotoolprofile.ConsumerInput) {
					copy.CPPIncludeSearchMisses = nil
					copy.CPPOriginals.RequiredExpandedOperands[assembly] = []gotoolprofile.CPPPackageSearchMiss{}
				}
				mutations["paired_v1_downgrade"] = func(copy *gotoolprofile.ConsumerInput) {
					copy.CPPIncludeSearchMisses[0].Protocol = gotoolprofile.CPPPackageSearchMissProtocol
					copy.CPPIncludeSearchMisses[0].Source = "module/" + assembly
					copy.CPPOriginals.RequiredExpandedOperands[assembly] = copy.CPPIncludeSearchMisses
				}
				mutations["fake_physical_source"] = func(copy *gotoolprofile.ConsumerInput) { copy.CPPIncludeSearchMisses[0].Source = "module/" + assembly }
				mutations["paired_tool_body_hash"] = func(copy *gotoolprofile.ConsumerInput) {
					changed := copy.CPPOriginals.Sources["tool/"+tool] + "#define FORGED 1\n"
					copy.CPPOriginals.Sources["tool/"+tool] = changed
					copy.ToolSources[tool] = featureBytesSHA256([]byte(changed))
				}
			}
			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					var copy gotoolprofile.ConsumerInput
					if err := json.Unmarshal(encoded, &copy); err != nil {
						t.Fatal(err)
					}
					mutate(&copy)
					actual := *consumer
					actual.Input = &copy
					if _, _, err := actual.preprocessCPP(file, input.Module, nil); err == nil {
						t.Fatal("changed actual stage/source/absence inputs were accepted")
					}
				})
			}
			cancel()
			if _, _, err := consumer.preprocessCPP(file, input.Module, nil); err == nil {
				t.Fatal("canceled actual CPP read was accepted")
			}
		})
	}
}

func TestFeatureCPPExpandedOutsidePreferredFileAppearingIsRejected(t *testing.T) {
	parent := t.TempDir()
	module := filepath.Join(parent, "owned", "module")
	if err := os.MkdirAll(module, 0700); err != nil {
		t.Fatal(err)
	}
	miss := gotoolprofile.CPPPackageSearchMiss{Protocol: gotoolprofile.CPPExpandedPackageSearchMissProtocol,
		Assembly: "probe.s", Include: "../../src/runtime/go_tls.h", PackageCandidate: "../../src/runtime/go_tls.h", ToolSource: "src/runtime/go_tls.h"}
	if err := gotoolprofile.VerifyCPPPackageSearchMiss(miss, module, runtime.GOROOT()); err != nil {
		t.Fatal(err)
	}
	preferred := filepath.Join(parent, "src", "runtime", "go_tls.h")
	if err := os.MkdirAll(filepath.Dir(preferred), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(preferred, []byte("#define FORGED 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := gotoolprofile.VerifyCPPPackageSearchMiss(miss, module, runtime.GOROOT()); err == nil {
		t.Fatal("late preferred original package candidate did not revoke fallback")
	}
}
