package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestX86FourSourceIsolatedMinimumISAProfiles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, member := range x86FourSourceOracle {
			t.Run(arch+"/"+member.op, func(t *testing.T) {
				row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot, first: 2, dest: 6, mode: "plain"}
				ins := x86ScalarLaneInstruction(t, row.instruction())
				want := "+avx5124fmaps,+avx512f"
				if member.dot {
					want = "+avx5124vnniw,+avx512f"
				}
				if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}); got != want {
					t.Fatal("isolated four-source opcode borrowed a producer's feature or the sibling rare ISA", got, want)
				}
			})
		}
	}
}

func x86FourSourceNativeObjectListing(t *testing.T, llc, objdump, triple, level, ir string) string {
	t.Helper()
	directory := t.TempDir()
	input, object := filepath.Join(directory, "four-source.ll"), filepath.Join(directory, "four-source.o")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancel := runtimeOracleStageContext(t)
	output, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, llc,
		level, "-mtriple="+triple, "-filetype=obj", input, "-o", object))
	cancel()
	if err != nil {
		t.Fatalf("actual four-source machine object: %v\n%s", err, output)
	}
	stage, cancel = runtimeOracleStageContext(t)
	listing, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, objdump, "-d", object))
	cancel()
	if err != nil {
		t.Fatalf("independent LLVM22 four-source disassembly: %v\n%s", err, listing)
	}
	return strings.ToLower(string(listing))
}

// These are actual original-opcode objects, not native execution. In
// particular, ordinary public runners need not supply Xeon Phi 4FMAPS or
// 4VNNIW. Portable lane mathematics cannot certify original MXCSR, sequential
// exception priority or the mask-controlled complete m128 access.
func TestX86FourSourceLiveAndDeadRetainActualNativeOpcodes(t *testing.T) {
	x86FourSourceOriginalRuntimeUnchanged(t)
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("original rare-ISA objects require exact LLVM22 llc and llvm-objdump")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			functions := make(map[string]string)
			for index, member := range x86FourSourceOracle {
				for _, mode := range []string{"plain", "merge", "zero"} {
					if target.arch == "386" && mode != "plain" {
						continue
					}
					for _, dead := range []bool{false, true} {
						row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot,
							first: 2, dest: 6, mode: mode}
						name := fmt.Sprintf("NativeFour%d_%s_%t", index, mode, dead)
						body, declaration := x86FourSourceInitializedSource(row, target.arch, name, dead)
						source.WriteString(body)
						declarations.WriteString(declaration)
						functions[strings.ToLower(name)] = strings.ToLower(member.op)
					}
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original four-source source rejected before actual opcode observation", err)
					}
					if strings.Count(ir, " asm sideeffect ") != len(functions) || strings.Count(ir, "~{fpsr}") != len(functions)*4/6 {
						t.Fatal("complete original opcodes lost memory sideeffects or floating-only ambient MXCSR/exception effects")
					}
					for _, pipeline := range []struct{ name, level, body string }{
						{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir},
						{"IR_O2_backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							listing := x86FourSourceNativeObjectListing(t, llc, objdump, target.triple, pipeline.level, pipeline.body)
							sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <_?(nativefour[0-5]_(?:plain|merge|zero)_(?:false|true))>:\r?\n`).FindAllStringSubmatchIndex(listing, -1)
							if len(sections) != len(functions) {
								t.Fatal("actual object lost a complete live/dead original function", len(sections), len(functions))
							}
							seen := make(map[string]bool)
							for index, section := range sections {
								name := listing[section[2]:section[3]]
								opcode, found := functions[name]
								if !found || seen[name] {
									t.Fatal("unobserved or duplicate physical original function", name)
								}
								seen[name] = true
								end := len(listing)
								if index+1 < len(sections) {
									end = sections[index+1][0]
								}
								body := listing[section[1]:end]
								t.Run(name, func(t *testing.T) {
									pattern := regexp.MustCompile(`\b` + opcode + `\b`)
									if got := len(pattern.FindAllStringIndex(body, -1)); got != 1 {
										t.Fatal("this original live/dead function lost its single exact memory opcode", opcode, got)
									}
								})
							}
						})
					}
				})
			}
		})
	}
}
