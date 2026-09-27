package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64YieldCompleteGoAssemblerForms(t *testing.T) {
	source := "TEXT yieldform(SB),$0-0\n\tYIELD\n\tRET\n"
	requireARM64GoAssemblerResult(t, source, true)

	for _, triple := range []string{
		"arm64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"yieldform": {Name: "yieldform", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, `asm sideeffect "yield"`) {
				t.Fatalf("ARM64 YIELD was silently discarded for %s:\n%s", triple, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-yield.ll", "arm64-yield.o", ll)
		})
	}
}

func TestTranslateARM64HintFamilyCompleteGoAssemblerForms(t *testing.T) {
	source := `
TEXT hintforms(SB),$0-0
	HINT $0
	HINT $6
	HINT $127
	HINT $128
	HINT $-1
	HINT $0x1122334455667788
	YIELD
	WFE
	WFI
	SEV
	SEVL
	WORD $0xd503203f
	WORD $0xd503205f
	WORD $0xd503207f
	WORD $0xd503209f
	WORD $0xd50320bf
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"arm64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"hintforms": {Name: "hintforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"hint #0"`, `"hint #6"`, `"hint #127"`, `"yield"`, `"wfe"`, `"wfi"`, `"sev"`, `"sevl"`} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 hint family omitted %s for %s:\n%s", want, triple, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-hints.ll", "arm64-hints.o", ll)
		})
	}
}

func TestTranslateARM64HintRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{"HINT", "HINT R0", "HINT $1, $2", "HINT.P $1", "WFE $0", "WFI R0", "SEV $1", "SEVL.P"} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's hint forms", instruction)
		}
	}
}

func TestTranslateARM64YieldRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{"YIELD $0", "YIELD R0", "YIELD.P"} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's YIELD forms", instruction)
		}
	}
}

func TestTranslateARM64NOPMatchesGoAssemblerForms(t *testing.T) {
	source := `
TEXT nopform(SB),$0-0
	NOP
	NOP $0
	NOP $4294967295
	NOP $4294967296
	NOP R0
	NOP ZR
	NOP V0
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"nopform": {Name: "nopform", Ret: Void}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, instruction := range []string{
		"NOP $0x1122334455667788",
		"NOP F0",
		"NOP RSP",
		"NOP R0, R1",
		"NOP.P",
	} {
		badSource := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, badSource, false)
		badFile, err := Parse(ArchARM64, badSource)
		if err != nil {
			continue
		}
		if _, err := Translate(badFile, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's NOP forms", instruction)
		}
	}
}
