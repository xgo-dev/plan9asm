package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64RawVRSHRNCompleteAdvancedSIMDFormats(t *testing.T) {
	// x/arch prints the architectural RSHRN/RSHRN2 encodings in Go syntax as
	// VRSHRN/VRSHRN2. Go 1.27's assembler table exposes VSHRN/VSHRN2 (the
	// non-rounding form), so these are deliberately exercised through WORD.
	const source = `TEXT ·rawVRSHRNForms(SB), $0-0
	WORD $0x0F0B8C01 // VRSHRN $5, V0.H8, V1.B8
	WORD $0x0F118C44 // VRSHRN $15, V2.S4, V4.H4
	WORD $0x0F218C57 // VRSHRN $31, V2.D2, V23.S2
	WORD $0x4F088C63 // VRSHRN2 $8, V3.H8, V3.B16
	WORD $0x4F148C85 // VRSHRN2 $12, V4.S4, V5.H8
	WORD $0x4F2C8CA6 // VRSHRN2 $20, V5.D2, V6.S4
	RET
`
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
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"rawVRSHRNForms": {Name: "rawVRSHRNForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{"ashr <", "add <", "trunc <", "insertelement <"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s VRSHRN IR omitted %q:\n%s", triple, want, ll)
			}
		}
		compileLLVMToObject(t, llc, triple, "arm64-raw-vrshrn.ll", "arm64-raw-vrshrn.o", ll)
	}
}

func TestARM64RawVRSHRNDecoderCoversEveryGoNarrowingFormat(t *testing.T) {
	// The raw decoder must retain all register fields and every immediate in
	// the same H8->B8, S4->H4, and D2->S2 rows used by Go's AVSHRN optab.
	for _, highHalf := range []bool{false, true} {
		for _, destinationBits := range []int{8, 16, 32} {
			for shift := 1; shift <= destinationBits; shift++ {
				encodedImmediate := uint32(2*destinationBits - shift)
				for source := 0; source < 32; source++ {
					for destination := 0; destination < 32; destination++ {
						word := uint32(0x0f008c00) | encodedImmediate<<16 | uint32(source<<5|destination)
						if highHalf {
							word |= 1 << 30
						}
						decoded, err := decodeARM64RawWordInstruction(Instr{
							Op:   OpWORD,
							Args: []Operand{{Kind: OpImm, Imm: int64(word)}},
						})
						if err != nil {
							t.Fatalf("decode VRSHRN high=%v destinationBits=%d shift=%d source=%d destination=%d word=%#08x: %v", highHalf, destinationBits, shift, source, destination, word, err)
						}
						wantOp := Op("VRSHRN")
						if highHalf {
							wantOp = "VRSHRN2"
						}
						if decoded.Op != wantOp || len(decoded.Args) != 3 || decoded.Args[0].Kind != OpImm || decoded.Args[0].Imm != int64(shift) {
							t.Fatalf("decode VRSHRN high=%v destinationBits=%d shift=%d source=%d destination=%d: %#v", highHalf, destinationBits, shift, source, destination, decoded)
						}
					}
				}
			}
		}
	}
}
