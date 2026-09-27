package plan9asm

import (
	"strings"
	"testing"
)

const armReverseSubtractCarryForms = `TEXT reverseSubtractCarry(SB),$0-0
	RSC $255, R0, R1
	RSC.S $255, R0, R1
	RSC $255, R0
	RSC.S $255, R0
	RSC R0, R1, R2
	RSC.S R0, R1, R2
	RSC R0, R1
	RSC.S R0, R1
	RSC R0>>28, R1, R2
	RSC R0<<28, R1, R2
	RSC R0->28, R1, R2
	RSC R0@>28, R1, R2
	RSC.S R0>>28, R1, R2
	RSC.S R0<<28, R1, R2
	RSC.S R0->28, R1, R2
	RSC.S R0@>28, R1, R2
	RSC R0<<28, R1
	RSC R0>>28, R1
	RSC R0->28, R1
	RSC R0@>28, R1
	RSC.S R0<<28, R1
	RSC.S R0>>28, R1
	RSC.S R0->28, R1
	RSC.S R0@>28, R1
	RSC R0<<R1, R2, R3
	RSC R0>>R1, R2, R3
	RSC R0->R1, R2, R3
	RSC R0@>R1, R2, R3
	RSC.S R0<<R1, R2, R3
	RSC.S R0>>R1, R2, R3
	RSC.S R0->R1, R2, R3
	RSC.S R0@>R1, R2, R3
	RSC R0<<R1, R2
	RSC R0>>R1, R2
	RSC R0->R1, R2
	RSC R0@>R1, R2
	RSC.S R0<<R1, R2
	RSC.S R0>>R1, R2
	RSC.S R0->R1, R2
	RSC.S R0@>R1, R2
	RET
`

func TestTranslateARMReverseSubtractCarryCompleteFormats(t *testing.T) {
	requireARMGoAssemblerResult(t, armReverseSubtractCarryForms, true)
	ll := translateARMForTest(t, armReverseSubtractCarryForms, map[string]FuncSig{
		"example.reverseSubtractCarry": {Name: "example.reverseSubtractCarry", Ret: Void},
	})
	for _, want := range []string{
		"call i32 @llvm.fshr.i32", "sub i32", "load i1", "xor i1", "icmp ult i64",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("RSC lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-rsc.ll", "arm-rsc.o", ll)
}

func TestTranslateARMReverseSubtractCarryRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"RSC R0", "RSC (R0), R1"} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARMGoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "armv7-unknown-linux-gnueabihf",
			Goarch:       "arm",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM RSC optab", instruction)
		}
	}
}
