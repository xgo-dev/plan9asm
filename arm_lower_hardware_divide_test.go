package plan9asm

import (
	"strings"
	"testing"
)

const armHardwareDivideForms = `TEXT hardwareDivide(SB),$0-0
	DIVHW R0, R1, R2
	DIVUHW R0, R1, R2
	DIVHW R0, R1
	DIVUHW R0, R1
	RET
`

func TestTranslateARMHardwareDivideCompleteFormats(t *testing.T) {
	requireARMGoAssemblerResult(t, armHardwareDivideForms, true)
	ll := translateARMForTest(t, armHardwareDivideForms, map[string]FuncSig{
		"example.hardwareDivide": {Name: "example.hardwareDivide", Ret: Void},
	})
	for _, want := range []string{"sdiv i32", "udiv i32", "icmp eq i32", "select i1"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM hardware divide lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-hardware-divide.ll", "arm-hardware-divide.o", ll)
}

func TestTranslateARMHardwareDivideRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"DIVHW R0", "DIVUHW (R0), R1"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM hardware-divide optab", instruction)
		}
	}
}
