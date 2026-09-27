package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64GeneralExtractCompleteFormats(t *testing.T) {
	const source = `TEXT extractComplete(SB),$0-0
	EXTR $0, R1, R2, R3
	EXTR $63, R4, R5, R6
	EXTR $17, ZR, R7, R8
	EXTRW $0, R9, R10, R11
	EXTRW $31, R12, R13, R14
	EXTRW $7, R15, ZR, ZR
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"extractComplete": {Name: "extractComplete", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"lshr i64", "shl i64", "or i64", "lshr i32", "shl i32", "or i32", "zext i32"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 EXTR lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-extract-complete.ll", "arm64-extract-complete.o", ll)
}

func TestTranslateARM64GeneralExtractRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"EXTR R0, R1, R2, R3",
		"EXTR $64, R1, R2, R3",
		"EXTR $1, RSP, R2, R3",
		"EXTR $1, R1, R2, RSP",
		"EXTR.P $1, R1, R2, R3",
		"EXTRW $32, R1, R2, R3",
		"EXTRW $1, (R1), R2, R3",
	} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: arm64LinuxGNUTriple,
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 EXTR optab", instruction)
		}
	}
}
