package plan9asm

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestTranslateARM64TLBICompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT tlbiforms(SB),$0-0\n")
	names := arm64TLBIOperationNames()
	for _, name := range names {
		operation := arm64TLBIOperations[name]
		if operation.hasOperand {
			fmt.Fprintf(&source, "\tTLBI %s, R0\n", name)
		} else {
			fmt.Fprintf(&source, "\tTLBI %s\n", name)
		}
	}
	source.WriteString("\tRET\n")
	asm := source.String()
	requireARM64GoAssemblerResult(t, asm, true)
	file, err := Parse(ArchARM64, asm)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"tlbiforms": {Name: "tlbiforms", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Count(ll, `asm sideeffect "sys #`), len(names); got != want {
		t.Fatalf("TLBI lowering emitted %d system operations, want %d:\n%s", got, want, ll)
	}
	for _, want := range []string{
		`asm sideeffect "sys #0, c8, c3, #0"`,
		`asm sideeffect "sys #0, c8, c3, #1, $0"`,
		`asm sideeffect "sys #6, c8, c7, #5, $0"`,
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("TLBI lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-tlbi.ll", "arm64-tlbi.o", ll)
}

func TestTranslateARM64TLBIRejectsInvalidForms(t *testing.T) {
	for _, instruction := range []string{
		"TLBI PLDL1KEEP",
		"TLBI VMALLE1IS, R0",
		"TLBI VAE1IS",
		"TLBI VAE1IS, SP",
		"TLBI.P VMALLE1IS",
	} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted invalid TLBI form %q", instruction)
		}
	}
}

func TestTranslateARM64RawTLBIForms(t *testing.T) {
	const source = `TEXT rawtlbi(SB),$0-0
	WORD $0xd50883a1
	WORD $0xd5088341
	WORD $0xd5088741
	WORD $0xd508871f
	WORD $0xd508831f
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"rawtlbi": {Name: "rawtlbi", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(ll, `asm sideeffect "sys #`); got != 5 {
		t.Fatalf("raw TLBI lowering emitted %d system operations, want 5:\n%s", got, ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-raw-tlbi.ll", "arm64-raw-tlbi.o", ll)
}

func TestARM64TLBIOperationTableIsStable(t *testing.T) {
	names := arm64TLBIOperationNames()
	if len(names) != 78 {
		t.Fatalf("TLBI operation table has %d entries, want 78", len(names))
	}
	if !sort.StringsAreSorted(names) {
		t.Fatal("TLBI operation names are not sorted")
	}
}
