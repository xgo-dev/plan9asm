package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Go's non-shared 386 yaddl/Yi32 relocation row is common to all seven
// binary arithmetic/logical stems. The address is a value, never a cell load.
func x86StaticRelocationRMWFixture(memory bool) (string, string) {
	var source, declarations strings.Builder
	source.WriteString("DATA ·cell+0(SB)/8,$0x1234\nGLOBL ·cell(SB),8,$16\n" +
		"DATA ·sink+0(SB)/4,$0x12345678\nGLOBL ·sink(SB),16,$4\n")
	for index, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR"} {
		name := fmt.Sprintf("relocation%d", index)
		fmt.Fprintf(&declarations, "func %s(seed uint32) uint32\n", name)
		destination, load := "AX", ""
		if memory {
			destination, load = "·sink(SB)", "MOVL ·sink(SB),AX\n"
		}
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVL seed+0(FP),AX\nCLC\n%sL $·cell+8(SB),%s\n%sMOVL AX,ret+4(FP)\nRET\n",
			name, stem, destination, load)
	}
	return source.String(), declarations.String()
}

func TestX86StaticRelocationInitializedCompleteRMWFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86AddressMemoryTargets("386") {
		for _, memory := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/memory=%t", target, memory), func(t *testing.T) {
				source, declarations := x86StaticRelocationRMWFixture(memory)
				x86LEAActualTargetGoObject(t, "386", target, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", target, api)
					if err != nil {
						t.Fatal("initialized complete relocation/RMW family", api, err)
					}
					if !strings.Contains(ir, "ptrtoint ptr") || strings.Contains(ir, "load i32, ptr @cell") ||
						strings.Contains(ir, "load volatile i32, ptr @cell") {
						t.Fatal("address relocation became a numerical source-memory read")
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target, text, level)
						}
					}
				}
			})
		}
	}
}

func TestX86StaticRelocationRMWCannotInventSourceStorage(t *testing.T) {
	for _, mutation := range []struct{ name, before, after string }{
		{"unbound-address", "DATA ·cell+0(SB)/8,$0x1234\nGLOBL ·cell(SB),8,$16\n", ""},
		{"missing-destination", "DATA ·sink+0(SB)/4,$0x12345678\nGLOBL ·sink(SB),16,$4\n", ""},
		{"short-destination", "DATA ·sink+0(SB)/4,$0x12345678\nGLOBL ·sink(SB),16,$4", "DATA ·sink+0(SB)/2,$1\nGLOBL ·sink(SB),16,$2"},
		{"readonly-destination", "GLOBL ·sink(SB),16,$4", "GLOBL ·sink(SB),8,$4"},
		{"missing-carry", "CLC\n", ""},
		{"missing-result", "MOVL AX,ret+4(FP)\n", ""},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			source, declarations := x86StaticRelocationRMWFixture(true)
			changed := strings.ReplaceAll(source, mutation.before, mutation.after)
			if changed == source {
				t.Fatal("mutation did not change its exact original source")
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, changed, declarations, "386", "i386-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("relocation created missing storage/carry/result knowledge", api, err)
				}
			}
		})
	}
}

func TestX86StaticNumericRMWCompleteWidthFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		word, goType, move, suffixes := 4, "uint32", "MOVL", "BWL"
		if arch == "amd64" {
			word, goType, move, suffixes = 8, "uint64", "MOVQ", "BWLQ"
		}
		var source, declarations strings.Builder
		source.WriteString("DATA ·sink+0(SB)/8,$0x12345678\nGLOBL ·sink(SB),16,$8\n")
		count := 0
		for _, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "INC", "DEC", "NEG", "NOT"} {
			for _, suffix := range suffixes {
				for _, register := range []bool{false, true} {
					unary := stem == "INC" || stem == "DEC" || stem == "NEG" || stem == "NOT"
					if unary && register {
						continue
					}
					name := fmt.Sprintf("numeric%d", count)
					count++
					fmt.Fprintf(&declarations, "func %s(seed %s) %s\n", name, goType, goType)
					operands := "·sink(SB)"
					if !unary {
						input := "$5"
						if register {
							input = "AX"
						}
						operands = input + "," + operands
					}
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s seed+0(FP),AX\nCLC\n%s%c %s\n%s ·sink(SB),AX\n%s AX,ret+%d(FP)\nRET\n",
						name, word*2, move, stem, suffix, operands, move, move, word)
				}
			}
		}
		if count != 18*len(suffixes) {
			t.Fatal("incomplete independent eleven-stem immediate/register/width matrix", count)
		}
		for _, target := range x86AddressMemoryTargets(arch) {
			t.Run(target, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, arch, target, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, target, api)
					if err != nil {
						t.Fatal("complete mutable static numerical family", api, err)
					}
					if strings.Count(ir, "store volatile") < count || strings.Count(ir, "load volatile") < count {
						t.Fatal("static RMW lost its exact paired native access")
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target, text, level)
						}
					}
				}
			})
		}
	}
}
