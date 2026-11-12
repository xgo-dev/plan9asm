package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64CLREXCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 accepts CLREX with no operand or with one C_VCON immediate.
	// The encoder uses the low four immediate bits, so values outside 0..15
	// remain valid spellings even though the immediate does not affect our
	// exclusive-monitor model.
	source := `
TEXT clrexforms(SB),NOSPLIT,$0-0
	CLREX
	CLREX $0
	CLREX $15
	CLREX $255
	RET
`
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-arm64", triple: "arm64-apple-darwin"},
		{name: "linux-arm64", triple: "aarch64-unknown-linux-gnu"},
		{name: "windows-arm64", triple: "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"clrexforms": {Name: "clrexforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			// One initialization plus one clear for every CLREX instruction.
			if got := strings.Count(ll, "store i1 false, ptr %exclusive_valid"); got != 5 {
				t.Fatalf("exclusive monitor clear count = %d, want 5\n%s", got, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "clrex-"+target.name+".ll", "clrex-"+target.name+".o", ll)
		})
	}
}

func TestTranslateARM64CLREXRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"CLREX R0",
		"CLREX $1, $2",
		"CLREX.Z",
	} {
		file, err := Parse(ArchARM64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's CLREX forms", instruction)
		}
	}
}
