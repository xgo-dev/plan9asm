package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARMRawSXTBRotationFamilyUsesSemanticLowering(t *testing.T) {
	const source = `TEXT rawSXTB(SB), $0-0
	WORD $0xe6af4074 // sxtb r4, r4
	WORD $0xe6af5474 // sxtb r5, r4, ror #8
	WORD $0xe6af6874 // sxtb r6, r4, ror #16
	WORD $0xe6af7c74 // sxtb r7, r4, ror #24
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawSXTB": {Name: "rawSXTB", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ir, "sext i8") != 4 || strings.Count(ir, "= call i32 @llvm.fshr.i32") != 3 {
		t.Fatalf("raw SXTB family did not retain rotate and signed-extension semantics:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-sxtb.ll", "arm-raw-sxtb.o", ir)
}

func TestARMRawSXTBDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for condition := 0; condition < 15; condition++ {
		for rotation := 0; rotation < 4; rotation++ {
			for source := 0; source < 16; source++ {
				for destination := 0; destination < 16; destination++ {
					word := uint32(condition)<<28 | 0x06af0070 | uint32(destination)<<12 | uint32(rotation)<<10 | uint32(source)
					got, ok := decodeARMRawSXTB(word)
					if !ok || got.condition != armConditionName(condition) || got.rotation != rotation*8 || got.source != source || got.destination != destination {
						t.Fatalf("decoded ARM SXTB %#08x as %+v, ok=%v", word, got, ok)
					}
					count++
				}
			}
		}
	}
	if count != 15*4*16*16 {
		t.Fatalf("covered %d SXTB encodings, want %d", count, 15*4*16*16)
	}
}

func TestARMRawSXTBRejectsReservedAndUnsafeForms(t *testing.T) {
	if _, ok := decodeARMRawSXTB(0xf6af0070); ok {
		t.Fatal("SXTB decoder accepted condition 0xf from the unconditional instruction space")
	}
	// 0xe6bf0070 is the official SXTH R0, R0 encoding, not a reserved
	// SXTB-adjacent slot. The 0x69 variant is absent from the architectural
	// signed/unsigned extend family (0x68, 0x6a-0x6c, and 0x6e-0x6f).
	for _, word := range []uint32{0xe69f0070, 0xe6af047f} {
		file, err := Parse(ArchARM, fmt.Sprintf("TEXT badSXTB(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"badSXTB": {Name: "badSXTB", Ret: Void}}}); err == nil {
			t.Fatalf("Translate accepted reserved/unsafe SXTB-adjacent encoding %#08x", word)
		}
	}
}
