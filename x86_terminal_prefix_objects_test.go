package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func x86TerminalPrefixReadSource() (string, string) {
	var source, declarations strings.Builder
	for index, family := range x86TerminalPrefixMechanismFixtures() {
		fmt.Fprintf(&source, "TEXT ·TerminalRead%d(SB),4,$0-8\nMOVQ p+0(FP),AX\nMOVQ (AX),CX\n%s\nRET\n", index, family.instruction)
		fmt.Fprintf(&declarations, "func TerminalRead%d(p *uint64)\n", index)
	}
	return source.String(), declarations.String()
}

func TestX86ArchitecturalTerminalPrefixReadFaultOrderObjects(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc and llvm-objdump required")
	}
	source, declarations := x86TerminalPrefixReadSource()
	const triple = "x86_64-unknown-linux-gnu"
	x86LEAActualTargetGoObject(t, "amd64", triple, source)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("original declared native-address prefix was not admitted", api, err)
			}
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend-O0", "-O0", ir},
				{"backend-O2", "-O2", ir},
				{"IR-O2-backend-O2", "-O2", x86UndefinedTrapOptimizedIR(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					listing := x86FourSourceNativeObjectListing(t, llc, objdump, triple, pipeline.level, pipeline.ir)
					sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <(terminalread[0-7])>:\r?\n`).FindAllStringSubmatchIndex(listing, -1)
					if len(sections) != 8 {
						t.Fatal("all eight terminal mechanisms must remain visible in the actual object", len(sections))
					}
					for index, section := range sections {
						name := listing[section[2]:section[3]]
						end := len(listing)
						if index+1 < len(sections) {
							end = sections[index+1][0]
						}
						body := listing[section[1]:end]
						t.Run(name, func(t *testing.T) {
							var reads [][]int
							for _, read := range regexp.MustCompile(`\bmovq\s+\(%(r[a-z0-9]+)\),\s*%[a-z0-9]+`).FindAllStringSubmatchIndex(body, -1) {
								base := body[read[2]:read[3]]
								if base != "rsp" && base != "rbp" {
									reads = append(reads, read)
								}
							}
							traps := regexp.MustCompile(`\bud2\b`).FindAllStringIndex(body, -1)
							if len(reads) != 1 || len(traps) != 1 || reads[0][1] >= traps[0][0] {
								t.Fatal("actual external qword read must survive before the architectural fault", name, body)
							}
							// Baseline AMD64 SSE2 scratch initialization is legal;
							// the faulting original terminal requires no AVX ISA.
							if strings.Contains(body, "%ymm") || strings.Contains(body, "%zmm") || strings.Contains(body, "\tv") {
								t.Fatal("extra AVX ISA cannot precede the ordinary x86 fault counterpart", name, body)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86ArchitecturalTerminalDoesNotAddUnexecutedNativeFeatures(t *testing.T) {
	for _, family := range x86TerminalPrefixMechanismFixtures() {
		t.Run(family.name, func(t *testing.T) {
			terminal := x86ScalarLaneInstruction(t, family.instruction)
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", Func{Instrs: []Instr{terminal}}); got != "" {
				t.Fatal("architectural #UD does not execute the source vector/non-temporal opcode", family.name, got)
			}
			ordinary := x86ScalarLaneInstruction(t, "RDRANDQ AX")
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", Func{Instrs: []Instr{ordinary, terminal}}); got != "+rdrnd" {
				t.Fatal("terminal feature projection changed an ordinary preceding instruction", family.name, got)
			}
		})
	}
}
