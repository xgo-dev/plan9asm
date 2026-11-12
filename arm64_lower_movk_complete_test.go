package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64MOVKCompleteFormats(t *testing.T) {
	const source = `TEXT movkComplete(SB),$0-0
	MOVK $1, R1
	MOVK $(1<<12), R0
	MOVK $(2<<16), R2
	MOVK $(3<<32), R3
	MOVK $(4<<48), R4
	MOVK $5, ZR
	MOVKW $6, R5
	MOVKW $(7<<16), R6
	MOVKW $8, ZR
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
		Sigs:         map[string]FuncSig{"movkComplete": {Name: "movkComplete", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"and i64", "or i64", "and i32", "or i32", "zext i32"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 MOVK lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-movk-complete.ll", "arm64-movk-complete.o", ll)
}

func TestTranslateARM64MOVKRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"MOVK $0, R0",
		"MOVK $0x10001, R0",
		"MOVK $1, RSP",
		"MOVK $1, 8(R0)",
		"MOVK.P $1, R0",
		"MOVKW $(1<<32), R0",
		"MOVKW $-1, R0",
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 MOVK optab", instruction)
		}
	}
}
