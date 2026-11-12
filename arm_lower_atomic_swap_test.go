package plan9asm

import (
	"strings"
	"testing"
)

const armAtomicSwapForms = `TEXT atomicSwapForms(SB),$0-0
	SWPW R3, (R7), R9
	SWPBU R4, (R2), R8
	RET
`

func TestTranslateARMAtomicSwapCompleteFormats(t *testing.T) {
	requireARMGoAssemblerResult(t, armAtomicSwapForms, true)
	ll := translateARMForTest(t, armAtomicSwapForms, map[string]FuncSig{
		"example.atomicSwapForms": {Name: "example.atomicSwapForms", Ret: Void},
	})
	for _, want := range []string{"atomicrmw xchg ptr", "i32", "i8", "zext i8"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM atomic swap lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-atomic-swap.ll", "arm-atomic-swap.o", ll)
}

func TestTranslateARMAtomicSwapRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"SWPW R0, 4(R1), R2", "SWPBU R0, (R1)"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM atomic-swap optab", instruction)
		}
	}
}
