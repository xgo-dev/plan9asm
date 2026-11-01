package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMCoprocessorWriteCompleteFormat(t *testing.T) {
	const source = "TEXT coprocessorWrite(SB),$0-0\n\tMCR.S 4, 6, R1, C2, C3, 7\n\tRET\n"
	requireARMGoAssemblerResult(t, source, true)
	ll := translateARMForTest(t, source, map[string]FuncSig{
		"example.coprocessorWrite": {Name: "example.coprocessorWrite", Ret: Void},
	})
	if !strings.Contains(ll, `asm sideeffect "mcr p4, #6, $0, c2, c3, #7"`) {
		t.Fatalf("ARM MCR lowering omitted coprocessor write:\n%s", ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-mcr.ll", "arm-mcr.o", ll)
}

func TestTranslateARMCoprocessorWriteRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"MCR.S 4, 6, R1, C2, C3", "MCR.S 4, 6, (R1), C2, C3, 7"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM MCR optab", instruction)
		}
	}
}
