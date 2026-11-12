package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSMETileMemoryCompleteLLVM22EncodingFields(t *testing.T) {
	// LLVM 22's SME assembler emitted these words. Together they cover both
	// memory directions, all widths, H/V tiles, SP, register offsets, and
	// maximum tile/slice/predicate/row fields.
	cases := []struct {
		word      uint32
		bits      int
		tile      int
		index     int
		row       int
		predicate int
		base      int
		offset    int
		vertical  bool
		store     bool
	}{
		{0xe01f0020, 8, 0, 0, 12, 0, 1, 31, false, false},
		{0xe002ffef, 8, 0, 15, 15, 7, 31, 2, true, false},
		{0xe0452c8f, 16, 1, 7, 13, 3, 4, 5, false, false},
		{0xe087d8cf, 32, 3, 3, 14, 6, 6, 7, true, false},
		{0xe0c97d0f, 64, 7, 1, 15, 7, 8, 9, false, false},
		{0xe03f0020, 8, 0, 0, 12, 0, 1, 31, false, true},
		{0xe022ffef, 8, 0, 15, 15, 7, 31, 2, true, true},
		{0xe0652c8f, 16, 1, 7, 13, 3, 4, 5, false, true},
		{0xe0a7d8cf, 32, 3, 3, 14, 6, 6, 7, true, true},
		{0xe0e97d0f, 64, 7, 1, 15, 7, 8, 9, false, true},
	}
	var source strings.Builder
	source.WriteString("TEXT rawSMETileMemoryForms(SB),$0-0\n")
	for _, want := range cases {
		got, ok := decodeARM64RawSMETileMemory(want.word)
		if !ok || got.bits != want.bits || got.tile != want.tile ||
			got.index != want.index || got.row != want.row ||
			got.predicate != want.predicate || got.base != want.base ||
			got.offset != want.offset || got.vertical != want.vertical ||
			got.store != want.store {
			t.Fatalf("SME tile memory word %#08x decoded as %+v, ok=%v", want.word, got, ok)
		}
		fmt.Fprintf(&source, "\tWORD $%#08x\n", want.word)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSMETileMemoryForms": {Name: "rawSMETileMemoryForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sme-tile-memory-forms.ll", "arm64-raw-sme-tile-memory-forms.o", ir)
		})
	}

	if _, ok := decodeARM64RawSMETileMemory(0xe01f0030); ok {
		t.Fatal("accepted SME tile memory encoding with reserved bit 4")
	}
}

func TestTranslateARM64RawSMETileMemoryGoHighwayRegression(t *testing.T) {
	const source = `
TEXT rawSMETileMemory(SB),$0-0
	MOVD $0, R12
	WORD $0xd503477f // SMSTART
	WORD $0x2518e3e0 // PTRUE P0.B
	WORD $0xe01f0020 // LD1B {ZA0H.B[W12, 0]}, P0/Z, [X1]
	WORD $0xe03f0000 // ST1B {ZA0H.B[W12, 0]}, P0, [X0]
	WORD $0xd503467f // SMSTOP
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSMETileMemory": {Name: "rawSMETileMemory", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sme-tile-memory.ll", "arm64-raw-sme-tile-memory.o", ir)
		})
	}
}
