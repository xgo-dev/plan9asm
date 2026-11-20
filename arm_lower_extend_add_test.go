package plan9asm

import (
	"strings"
	"testing"
)

const armExtendAddForms = `TEXT extendAddForms(SB),$0-0
	XTAB R2@>0, R8
	XTAB R2@>8, R8
	XTAB R2@>16, R8
	XTAB R2@>24, R8
	XTAB R2@>0, R4, R8
	XTAB R2@>8, R4, R8
	XTAB R2@>16, R4, R8
	XTAB R2@>24, R4, R8
	XTAH R3@>0, R9
	XTAH R3@>8, R9
	XTAH R3@>16, R9
	XTAH R3@>24, R9
	XTAH R3@>0, R4, R9
	XTAH R3@>8, R4, R9
	XTAH R3@>16, R4, R9
	XTAH R3@>24, R4, R9
	XTABU R4@>0, R7
	XTABU R4@>8, R7
	XTABU R4@>16, R7
	XTABU R4@>24, R7
	XTABU R4@>0, R0, R7
	XTABU R4@>8, R0, R7
	XTABU R4@>16, R0, R7
	XTABU R4@>24, R0, R7
	XTAHU R5@>0, R1
	XTAHU R5@>8, R1
	XTAHU R5@>16, R1
	XTAHU R5@>24, R1
	XTAHU R5@>0, R9, R1
	XTAHU R5@>8, R9, R1
	XTAHU R5@>16, R9, R1
	XTAHU R5@>24, R9, R1
	RET
`

func TestTranslateARMExtendAddCompleteFormats(t *testing.T) {
	requireARMGoAssemblerResult(t, armExtendAddForms, true)
	ll := translateARMForTest(t, armExtendAddForms, map[string]FuncSig{
		"example.extendAddForms": {Name: "example.extendAddForms", Ret: Void},
	})
	for _, want := range []string{
		"call i32 @llvm.fshr.i32", "trunc i32", "sext i8", "sext i16", "zext i8", "zext i16", "add i32",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM extend-and-add lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-extend-add.ll", "arm-extend-add.o", ll)
}

func TestTranslateARMExtendAddRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"XTAB R0<<8, R1", "XTAHU R0@>4, R1", "XTABU R0@>8, (R1)"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM extend-and-add optab", instruction)
		}
	}
}
