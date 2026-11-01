package plan9asm

import (
	"strings"
	"testing"
)

const armBitfieldForms = `TEXT bitfieldForms(SB),$0-0
	BFX $16, $8, R1, R2
	BFX $29, $2, R8
	BFXU $16, $8, R1, R2
	BFXU $29, $2, R8
	BFC $29, $2, R8
	BFI $29, $2, R8
	BFI $16, $8, R1, R2
	RET
`

func TestTranslateARMBitfieldCompleteFormats(t *testing.T) {
	requireARMGoAssemblerResult(t, armBitfieldForms, true)
	ll := translateARMForTest(t, armBitfieldForms, map[string]FuncSig{
		"example.bitfieldForms": {Name: "example.bitfieldForms", Ret: Void},
	})
	for _, want := range []string{"ashr i32", "lshr i32", "shl i32", "and i32", "or i32"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM bitfield lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-bitfield.ll", "arm-bitfield.o", ll)
}

func TestTranslateARMBitfieldRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"BFX $0, $0, R1, R2",
		"BFXU $16, $17, R1, R2",
		"BFC $8, $0, R1, R2",
		"BFI $8, $0, (R1), R2",
	} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM bitfield optab", instruction)
		}
	}
}
