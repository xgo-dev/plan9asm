package plan9asm

import (
	"strings"
	"testing"
)

const armReverseBitsForms = `TEXT reverseBits(SB),$0-0
	REV R1, R2
	REV16 R2, R3
	REVSH R3, R4
	RBIT R4, R5
	RET
`

func TestTranslateARMReverseBitsCompleteFormats(t *testing.T) {
	requireARMGoAssemblerResult(t, armReverseBitsForms, true)
	ll := translateARMForTest(t, armReverseBitsForms, map[string]FuncSig{
		"example.reverseBits": {Name: "example.reverseBits", Ret: Void},
	})
	for _, want := range []string{
		"call i32 @llvm.bswap.i32", "call i32 @llvm.bitreverse.i32", "sext i16", "and i32", "shl i32", "lshr i32",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM reverse-bit/byte lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-reverse-bits.ll", "arm-reverse-bits.o", ll)
}

func TestTranslateARMReverseBitsRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"REV (R0), R1", "RBIT R0, R1, R2"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM reverse-bit/byte optab", instruction)
		}
	}
}
