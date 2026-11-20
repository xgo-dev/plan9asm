package plan9asm

import (
	"strings"
	"testing"
)

const armSignedMultiplyForms = `TEXT signedMultiplyForms(SB),$0-0
	MULAWT R1, R2, R3, R4
	MULAWB R1, R2, R3, R4
	MULS R1, R2, R3, R4
	MMULA R1, R2, R3, R4
	MMULS R1, R2, R3, R4
	MULABB R1, R2, R3, R4
	MULL R1, R2, (R4, R3)
	MULL.S R1, R2, (R4, R3)
	MMUL R1, R2, R3
	MULBB R1, R2, R3
	MULWB R1, R2, R3
	MULWT R1, R2, R3
	RET
`

func TestTranslateARMSignedMultiplyCompleteFormats(t *testing.T) {
	requireARMGoAssemblerResult(t, armSignedMultiplyForms, true)
	ll := translateARMForTest(t, armSignedMultiplyForms, map[string]FuncSig{
		"example.signedMultiplyForms": {Name: "example.signedMultiplyForms", Ret: Void},
	})
	for _, want := range []string{
		"sext i16", "sext i32", "mul i64", "ashr i64", "add i32", "sub i32", "icmp eq i64", "icmp slt i64",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM signed multiply lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-signed-multiply.ll", "arm-signed-multiply.o", ll)
}

func TestTranslateARMSignedMultiplyRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"MMUL R0, R1", "MULBB (R0), R1, R2", "MULL R0, R1, R2"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM signed-multiply optab", instruction)
		}
	}
}
