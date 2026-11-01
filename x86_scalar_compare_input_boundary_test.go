package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarCompareMemoryRoutesExistingTypedProof(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, operation := range x86ScalarCompareNames(arch) {
			ins := x86PureGPUnknownInstruction(t, x86ScalarCompareInstruction(operation, "(SI)", "$0"))
			for _, raw := range []bool{false, true} {
				ins.x86Encoded = raw
				if !x86TypedFPResultNeedsProof(Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, arch) {
					t.Fatal("dead named/raw memory read bypassed the existing whole-input proof", arch, operation, raw)
				}
			}
		}
		for _, instruction := range []string{"CMPL AX,$128", "TESTL CX,BX", "LEAL (SI),BX"} {
			ins := x86PureGPUnknownInstruction(t, instruction)
			if x86TypedFPResultNeedsProof(Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, arch) {
				t.Fatal("faulting-read routing absorbed nontrapping GP scratch or address calculation", arch, instruction)
			}
		}
	}
}

func TestX86ScalarCompareRowsCannotSupplyNumericalInputs(t *testing.T) {
	for _, item := range []struct{ operation, removed string }{
		{"CMPL AX,$128", "MOVQ a+16(FP),AX\n"},
		{"CMPL CX,BX", "MOVQ c+32(FP),CX\n"},
		{"TESTL 0(SI),BX", "MOVQ memory+0(FP),SI\n"},
	} {
		source, declaration := x86ScalarCompareInitializedFunction("CompareMissing", item.operation, "amd64")
		if strings.Count(source, item.removed) != 1 {
			t.Fatal("negative failed to remove one original numerical/address source")
		}
		source = strings.Replace(source, item.removed, "", 1)
		for _, api := range []string{"text", "module", "Go"} {
			if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("source compare transport supplied missing numerical/address input", item.operation, api, err)
			}
		}
	}
	for _, operation := range []string{"CMPL 0(SI),$128", "TESTL 0(SI),BX"} {
		for _, api := range []string{"text", "module", "Go"} {
			source := "TEXT ·CompareVoid(SB),4,$0-0\n" + operation + "\nRET\n"
			if ir, err := x86ScalarFPBitViewAPI(t, source, "func CompareVoid()", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("dead Void hid an unknown faulting scalar memory read", operation, api, err)
			}
		}
	}
	for _, operation := range []string{"CMPL AX,$128", "TESTL CX,BX"} {
		for _, api := range []string{"text", "module", "Go"} {
			source := "TEXT ·CompareBool(SB),4,$0-1\n" + operation + "\nSETEQ AL\nMOVB AL,ret+0(FP)\nRET\n"
			if ir, err := x86ScalarFPBitViewAPI(t, source, "func CompareBool() bool", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("observable comparison status manufactured an unknown numerical input", operation, api, err)
			}
		}
	}
}

func TestX86ScalarCompareDeadScratchIsNotNumericalEvidence(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, operation := range []string{"CMPL AX,$128", "TESTL CX,BX"} {
		for _, api := range []string{"text", "module", "Go"} {
			// Unknown scratch may flow through a nontrapping GP instruction
			// when no result, memory address or control decision observes it.
			// Object success here establishes no NUM bytes or status values.
			source := "TEXT ·CompareDead(SB),4,$0-0\n" + operation + "\nRET\n"
			ir, err := x86ScalarFPBitViewAPI(t, source, "func CompareDead()", "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil || ir == "" {
				t.Fatal("ordinary nontrapping dead GP scratch lost its existing contract", operation, api, err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, level)
			}
		}
	}
}

func TestX86ScalarCompareDeadMemoryKeepsExactVolatileRead(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		word, move := goWordSize(arch), "Q"
		if word == 4 {
			move = "L"
		}
		var source, declarations strings.Builder
		for index, operation := range x86ScalarCompareNames(arch) {
			for _, live := range []bool{false, true} {
				name := fmt.Sprintf("CompareMemory%d_%t", index, live)
				value, bytes := "$0", word
				declaration := fmt.Sprintf("func %s(memory *[8]byte)\n", name)
				seed, result := "", ""
				if live {
					value, bytes = "CX", 2*word+1
					declaration = fmt.Sprintf("func %s(memory *[8]byte,value uintptr) bool\n", name)
					seed = fmt.Sprintf("MOV%s value+%d(FP),CX\n", move, word)
					result = fmt.Sprintf("SETEQ AL\nMOVB AL,ret+%d(FP)\n", 2*word)
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s memory+0(FP),AX\n%s%s\n%sRET\n",
					name, bytes, move, seed, x86ScalarCompareInstruction(operation, "(AX)", value), result)
				declarations.WriteString(declaration)
			}
		}
		// Sixteen AMD64 / twelve I386 complete functions per assembler and
		// compiler batch. Source syntax is independently checked with Go.
		x86Legacy127OriginalListing(t, arch, source.String(), true)
		for _, target := range x86Legacy127Targets(arch) {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, target, api)
				if err != nil || ir == "" {
					t.Fatal("known-address comparison lost its original dead/live read", arch, target, api, err)
				}
				optimized := x86DwordProductIROptimize(t, ir)
				for _, bits := range []int{8, 16, 32, 64} {
					if arch == "386" && bits == 64 {
						continue
					}
					read := fmt.Sprint("load volatile i", bits)
					if strings.Count(ir, read) != 4 || !strings.Contains(optimized, read) {
						t.Fatal("dead flags/test-zero erased or widened an exact faulting memory read", arch, bits, target, api)
					}
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target, ir, level)
				}
			}
		}
	}
}

func TestX86ScalarComparePublicMemoryInputsWholeFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := goWordSize(arch), "Q"
		if word == 4 {
			move = "L"
		}
		for _, operation := range x86ScalarCompareNames(arch) {
			for _, kind := range []string{"unknown-address", "unknown-partner", "live-unknown-partner"} {
				t.Run(arch+"/"+operation+"/"+kind, func(t *testing.T) {
					bytes, seed, tail, address := 0, "", "", "(SI)"
					declaration := "func CompareInput()"
					if kind != "unknown-address" {
						bytes, address = word, "(AX)"
						seed = fmt.Sprintf("MOV%s memory+0(FP),AX\n", move)
						declaration = "func CompareInput(memory *[8]byte)"
					}
					if kind == "live-unknown-partner" {
						bytes = word + 1
						tail = fmt.Sprintf("SETEQ AL\nMOVB AL,ret+%d(FP)\n", word)
						declaration += " bool"
					}
					instruction := x86ScalarCompareInstruction(operation, address, "CX")
					source := fmt.Sprintf("TEXT ·CompareInput(SB),4,$0-%d\n%s%s\n%sRET\n", bytes, seed, instruction, tail)
					for _, api := range []string{"text", "module", "Go"} {
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, x86Legacy127Targets(arch)[0], api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Errorf("%s missing address/NUM reached a public dead/live memory compare: %v", api, err)
						}
					}
				})
			}
		}
	}
}
