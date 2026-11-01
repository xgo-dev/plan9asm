package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64NamedPCBranchRegression(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = `TEXT pcBitSkip(SB),$0-16
	MOVD value+0(FP), R0
	MOVD $0, R1
	TBZ $3, R0, 3(PC)
	ADD $1, R1
	ADD $2, R1
	MOVD R1, ret+8(FP)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{
		Name: "pcBitSkip", Args: []LLVMType{I64}, Ret: I64,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
		},
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
	if err != nil {
		t.Fatal(err)
	}
	const main = `#include <stdint.h>
#include <stdio.h>
extern uint64_t pcBitSkip(uint64_t);
int main(void) {
	for (uint64_t value = 0; value < 16; value++) {
		uint64_t want = value & 8 ? 3 : 0;
		uint64_t got = pcBitSkip(value);
		if (got != want) {
			fprintf(stderr, "TBZ 3(PC) value=%llu got=%llu want=%llu\n",
				(unsigned long long)value, (unsigned long long)got, (unsigned long long)want);
			return 1;
		}
	}
	return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "named_pc_branch", triple, ir, main, runner)
}

var arm64NamedPCBranchOps = []string{
	"B", "JMP", "BL", "CALL", "BEQ", "BNE", "BLO", "BHI", "BLT", "BGE", "BLE", "BGT",
	"BHS", "BLS", "BMI", "BPL", "BVS", "BVC", "BCC", "BCS", "CBZ", "CBNZ", "CBZW", "CBNZW", "TBZ", "TBNZ",
}

func arm64NamedPCBranchInstruction(op, target string) string {
	switch op {
	case "CBZ", "CBNZ", "CBZW", "CBNZW":
		return op + " R0, " + target
	case "TBZ", "TBNZ":
		return op + " $3, R0, " + target
	case "ADR", "ADRP":
		return op + " " + target + ", R3"
	default:
		return op + " " + target
	}
}

func arm64NamedPCBranchSig(name string) FuncSig {
	return FuncSig{
		Name: name, Args: []LLVMType{I64, I64}, Ret: I64,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}},
			Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
		},
	}
}

func TestARM64NamedPCBranchCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, op := range append(append([]string(nil), arm64NamedPCBranchOps...), "ADR", "ADRP") {
		for _, off := range []int{0, 1, 3, -1} {
			t.Run(fmt.Sprintf("%s/%d", op, off), func(t *testing.T) {
				source := "TEXT pcForms(SB),$0-24\nMOVD value+0(FP), R0\nMOVD $0, R1\nCMP $0, R0\n" +
					arm64NamedPCBranchInstruction(op, fmt.Sprintf("%d(PC)", off)) + "\nADD $1, R1\nADD $2, R1\nMOVD R1, ret+16(FP)\nRET\n"
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				sig := arm64NamedPCBranchSig("pcForms")
				for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc"} {
					ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, triple, "named-pc.ll", "named-pc.o", ir)
				}
			})
		}
	}
}

func TestARM64NamedPCBranchRejectsUnresolvedTargets(t *testing.T) {
	// Out-of-TEXT targets exercise plan9asm's own input-safety boundary.
	// Stock Go panics after its range diagnostic for every fixture below;
	// TestGoAssemblerKnownMalformedInputDefects records those tool defects
	// separately, without granting them ordinary Go rejection evidence.
	for _, op := range arm64NamedPCBranchOps {
		for _, target := range []string{"999(PC)", "-999(PC)", "9223372036854775807(PC)", "-9223372036854775808(PC)"} {
			t.Run(op+"/"+target, func(t *testing.T) {
				source := "TEXT pcInvalid(SB),$0-24\n" + arm64NamedPCBranchInstruction(op, target) + "\nRET\n"
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				sig := arm64NamedPCBranchSig("pcInvalid")
				_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{sig.Name: sig}})
				if err == nil || !strings.Contains(err.Error(), "outside TEXT") {
					t.Fatalf("%s %s was not rejected precisely: %v", op, target, err)
				}
			})
		}
	}
	for _, op := range []string{"TBZ", "TBNZ"} {
		for _, bit := range []int{-1, 64} {
			source := fmt.Sprintf("TEXT pcInvalid(SB),$0-24\n%s $%d, R0, 1(PC)\nRET\n", op, bit)
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := arm64NamedPCBranchSig("pcInvalid")
			if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{sig.Name: sig}}); err == nil {
				t.Fatalf("%s accepted invalid bit %d", op, bit)
			}
		}
	}
}

func TestARM64NamedPCNormalizationKeepsInstructionOrdinals(t *testing.T) {
	const source = `TEXT pcOrdinals(SB),$0-0
	MOVD $0, R0
	B 3(PC)
__arm64_pc_target_7:
	PCDATA $0, $0
	MOVD $0x123456789abcdef, R0
	done:
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	fn, err := normalizeARM64NamedPCRelative(file.Funcs[0])
	if err != nil {
		t.Fatal(err)
	}
	var target string
	for _, ins := range fn.Instrs {
		if ins.Op == "B" {
			target = ins.Args[0].Ident
		}
	}
	for i, ins := range fn.Instrs {
		if ins.Op == OpLABEL && ins.Args[0].Sym == target {
			if target == "__arm64_pc_target_7" {
				t.Fatal("relative target collided with an existing source label")
			}
			if i+1 >= len(fn.Instrs) || fn.Instrs[i+1].Op != OpRET {
				t.Fatalf("3(PC) did not target RET across metadata/expanded MOVD: %+v", fn.Instrs)
			}
			return
		}
	}
	t.Fatal("exact relative target label missing")
}
