package plan9asm

import (
	"strings"
	"testing"
)

func TestARMStatusReadUsesSourceNZCV(t *testing.T) {
	const source = "TEXT flags(SB),$0-4\n MOVW value+0(FP),R0\n CMP R0,R0\n MOVW CPSR,R0\n RET\n"
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Name: "flags", Args: []LLVMType{I32}, Ret: I32,
		Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}},
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf"} {
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{"flags": sig}})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"mrs $0, cpsr", ", 268435455", "load i1, ptr %flags_n", "load i1, ptr %flags_z", "load i1, ptr %flags_c", "load i1, ptr %flags_v"} {
			if !strings.Contains(ir, want) {
				t.Fatalf("CPSR read did not preserve source NZCV/non-NZCV status separation: missing %q", want)
			}
		}
		compileLLVMToObject(t, llc, triple, "source-status.ll", "source-status.o", ir)
	}
}
