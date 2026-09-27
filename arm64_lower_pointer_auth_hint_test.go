package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64PointerAuthHintCompleteForms(t *testing.T) {
	const source = `TEXT pointerAuthHints(SB),$0-0
	BTI C
	BTI J
	BTI JC
	PACIASP
	PACIBSP
	AUTIASP
	AUTIBSP
	AUTIA1716
	AUTIB1716
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
		Sigs:         map[string]FuncSig{"pointerAuthHints": {Name: "pointerAuthHints", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, immediate := range []string{"hint #34", "hint #36", "hint #38", "hint #25", "hint #27", "hint #29", "hint #31", "hint #12", "hint #14"} {
		if !strings.Contains(ll, immediate) {
			t.Fatalf("ARM64 pointer-auth hint lowering omitted %q:\n%s", immediate, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-pointer-auth-hints.ll", "arm64-pointer-auth-hints.o", ll)
}

func TestTranslateARM64PointerAuthHintRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"BTI",
		"BTI BAD",
		"BTI C, J",
		"BTI.P C",
		"PACIASP R0",
		"AUTIA1716.P",
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 pointer-auth hint optab", instruction)
		}
	}
}
