package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

// Intel SDM Vol. 2, CPUID, INPUT EAX = 0 and INPUT EAX = 80000000H:
// these maximum-leaf queries have no ECX selector. Unknown and structured
// leaves keep their ECX input; syntax acceptance alone supplies neither input.
func TestX86CPUIDLeafDependentInputsThreeAPIs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "i386-unknown-linux-gnu"
		if arch == "amd64" {
			triple = "x86_64-unknown-linux-gnu"
		}
		for _, raw := range []bool{false, true} {
			query := "CPUID\n"
			if raw {
				query = x86RawDisplacementDirectives([]byte{0x0f, 0xa2})
			}
			for _, row := range []struct {
				name, setup string
				valid       bool
			}{
				{"missing-eax", "", false},
				{"partial-eax", "MOVB $0,AL\n", false},
				{"basic-max", "MOVL $0,AX\n", true},
				{"extended-max", "MOVL $0x80000000,AX\n", true},
				{"signed-extended-max", "MOVL $-2147483648,AX\n", true},
				{"xor-basic-max", "XORL AX,AX\n", true},
				{"partial-xor", "XORW AX,AX\n", false},
				{"unknown-leaf", "MOVL $1,AX\n", false},
				{"structured-leaf", "MOVL $7,AX\n", false},
				{"structured-partial-ecx", "MOVL $7,AX\nMOVB $0,CL\n", false},
				{"structured-complete", "MOVL $7,AX\nMOVL $0,CX\n", true},
				{"overwritten-leaf", "MOVL $0,AX\nMOVL $7,AX\n", false},
				{"partial-overwrite", "MOVL $0,AX\nMOVB $7,AL\n", false},
				{"word-overwrite", "MOVL $0,AX\nMOVW $7,AX\n", false},
				{"arithmetic-overwrite", "MOVL $0,AX\nINCL AX\n", false},
				{"unrelated-write", "MOVL $0,AX\nMOVL $7,DX\n", true},
			} {
				t.Run(fmt.Sprintf("%s/raw=%t/%s", arch, raw, row.name), func(t *testing.T) {
					source := "TEXT ·Query(SB),4,$0-4\n" + row.setup + query + "MOVL AX,ret+0(FP)\nRET\n"
					x86LEAActualTargetGoObject(t, arch, triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Query() uint32", arch, triple, api)
						if row.valid {
							if err != nil || strings.Count(ir, "asm sideeffect \"cpuid\"") != 1 {
								t.Error("architectural leaf inputs lost the original query/result", api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("query invented a missing leaf/subleaf input", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86CPUIDLeafDependenciesResultsThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct{ name, setup string }{
			{"basic-max", "XORL AX,AX\n"},
			{"extended-max", "MOVL $0x80000000,AX\n"},
		} {
			for _, raw := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/raw=%t", target.triple, row.name, raw), func(t *testing.T) {
					query := "CPUID\n"
					if raw {
						query = x86RawDisplacementDirectives([]byte{0x0f, 0xa2})
					}
					// Keep every architectural output observable, including ECX,
					// whose incoming value this particular leaf does not consume.
					source := "TEXT ·Query(SB),4,$0-16\n" + row.setup + query +
						"MOVL AX,a+0(FP)\nMOVL BX,b+4(FP)\nMOVL CX,c+8(FP)\nMOVL DX,d+12(FP)\nRET\n"
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Query() (a,b,c,d uint32)", target.arch, target.triple, api)
						if err != nil || strings.Count(ir, "asm sideeffect \"cpuid\"") != 1 {
							t.Error("maximum-leaf query lost its initialized outputs", api, err)
							continue
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						}
					}
				})
			}
		}
	}
}

func TestX86CPUIDLeafFactsJoinAndOverwriteThreeAPIs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		declaration := "func Query(selector uint32) uint32"
		pkg := mustGoPackage(t, "query", "package query\n"+declaration)
		sig, err := DeriveGoFuncABI0Signature("Query", pkg.Types.Scope().Lookup("Query").(*types.Func), arch, types.SizesFor("gc", arch))
		if err != nil || len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Type != I32 {
			t.Fatal("actual Go ABI0 query result unavailable", err)
		}
		resultOffset := sig.Frame.Results[0].Offset
		triple := "i386-unknown-linux-gnu"
		if arch == "amd64" {
			triple = "x86_64-unknown-linux-gnu"
		}
		for _, row := range []struct {
			name, body string
			valid      bool
		}{
			{"same-leaf-join", "CMPL selector+0(FP),$0\nJE left\nMOVL $0,AX\nJMP ready\nleft:\nXORL AX,AX\nready:\nCPUID\n", true},
			{"two-maxima-join", "CMPL selector+0(FP),$0\nJE left\nMOVL $0,AX\nJMP ready\nleft:\nMOVL $0x80000000,AX\nready:\nCPUID\n", true},
			{"structured-path-join", "CMPL selector+0(FP),$0\nJE left\nMOVL $0,AX\nJMP ready\nleft:\nMOVL $7,AX\nready:\nCPUID\n", false},
			{"undefined-path-join", "CMPL selector+0(FP),$0\nJE ready\nMOVL $0,AX\nready:\nCPUID\n", false},
			{"entry-value", "MOVL selector+0(FP),AX\nCPUID\n", false},
			{"entry-subleaf-defined", "MOVL selector+0(FP),AX\nMOVL $0,CX\nCPUID\n", true},
			{"overwritten-from-entry", "MOVL $0,AX\nMOVL selector+0(FP),AX\nCPUID\n", false},
			{"implicit-query-overwrite", "MOVL $0,AX\nRDTSC\nCPUID\n", false},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·Query(SB),4,$0-%d\n%sMOVL AX,ret+%d(FP)\nRET\n", resultOffset+4, row.body, resultOffset)
				x86LEAActualTargetGoObject(t, arch, triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if row.valid {
						if err != nil || ir == "" {
							t.Error("safe leaf join lost its complete result flow", api, err)
						}
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Error("query reused a leaf fact after an unknown write or CFG path", api, err)
					}
				}
			})
		}
	}
}

func TestX86CPUIDLeafFactTrackingRequiresQuery(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, query := range []string{"", "CPUID", "cpuid"} {
			t.Run(arch+"/query="+query, func(t *testing.T) {
				body := "MOVL $0,AX\n"
				if query != "" {
					body += "CPUID\nMOVL $0,AX\n"
				}
				file, err := Parse(ArchAMD64, "TEXT ·Flow(SB),4,$0-0\n"+body+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				for index := range file.Funcs[0].Instrs {
					if file.Funcs[0].Instrs[index].Op == OpCPUID {
						file.Funcs[0].Instrs[index].Op = Op(query)
					}
				}
				returns := 0
				err = checkX86ResultSourceFlow(file.Funcs[0], x86ResultState{}, nil, 0, arch,
					func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, mode string) bool {
						return x86ResultTransfer(ins, state, owned, offset, mode)
					}, func(state x86ResultState, _ int) error {
						returns++
						if state.cpuidRootLeaf != (query != "") {
							return fmt.Errorf("CPUID leaf fact tracking differs from the final source query inventory")
						}
						return nil
					})
				if err != nil || returns != 1 {
					t.Fatal("unrelated source flow carried CPUID state or a real query lost it", err, returns)
				}
			})
		}
	}
}

func TestX86CPUIDMaximumLeavesCompleteSourceMoveAliases(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	aliases := append([]string{"MOVQ"}, x86OriginalMOVQAliases(t)...)
	for _, target := range x86RawReturnTargets {
		for _, alias := range aliases {
			for _, leaf := range []struct {
				name, value string
				root        bool
			}{
				{"basic-max", "0", true},
				{"extended-max", "0x80000000", true},
				{"high32-basic-max", "0x100000000", true},
				{"structured-leaf", "7", false},
			} {
				t.Run(target.triple+"/"+alias+"/"+leaf.name, func(t *testing.T) {
					source := "TEXT ·Query(SB),4,$0-4\n" + alias + " $" + leaf.value + ",AX\nCPUID\nMOVL AX,ret+0(FP)\nRET\n"
					// Go's complete MOVQ source aliases admit their GP/immediate
					// rows only in mode64; no mode32 or SIMD role is invented.
					if target.arch == "amd64" {
						x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					} else {
						goAssemblerOracleOutput(t, target.arch, source, "", false)
					}
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Query() uint32", target.arch, target.triple, api)
						if target.arch != "amd64" || !leaf.root {
							if err == nil || ir != "" {
								t.Error("alias supplied an illegal mode or missing subleaf input", api, err)
							}
							continue
						}
						if err != nil || strings.Count(ir, "asm sideeffect \"cpuid\"") != 1 {
							t.Error("original GP source alias lost its architectural leaf dependency", api, err)
							continue
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						}
					}
				})
			}
		}
	}
}
