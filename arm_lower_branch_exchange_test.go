package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMBranchExchangeCompleteFormat(t *testing.T) {
	const source = "TEXT branchExchange(SB),$0-0\n\tBX (R0)\n"
	requireARMGoAssemblerResult(t, source, true)
	ll := translateARMForTest(t, source, map[string]FuncSig{
		"example.branchExchange": {Name: "example.branchExchange", Ret: Void},
	})
	if !strings.Contains(ll, `asm sideeffect "bx $0"`) {
		t.Fatalf("ARM BX lowering omitted indirect branch exchange:\n%s", ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-bx.ll", "arm-bx.o", ll)
}

func TestTranslateARMBranchExchangeRejectsFormsOutsideGoOptab(t *testing.T) {
	const source = "TEXT bad(SB),$0-0\n\tBX R0\n"
	requireARMGoAssemblerResult(t, source, false)
	file, err := Parse(ArchARM, source)
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatal("Translate accepted BX R0 outside Go 1.27's ARM BX optab")
	}
}
