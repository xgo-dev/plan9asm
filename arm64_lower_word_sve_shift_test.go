package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEShiftCompleteGo127EncodingFamilies(t *testing.T) {
	forms := []struct {
		bases map[uint32]Op
		mode  arm64SVELSRMode
	}{
		{arm64SVEShiftWidePredicatedBases, arm64SVELSRWidePredicated},
		{arm64SVEShiftWideUnpredicatedBases, arm64SVELSRWideUnpredicated},
		{arm64SVEShiftVectorPredicatedBases, arm64SVELSRVectorPredicated},
		{arm64SVEShiftImmediatePredicatedBases, arm64SVELSRImmediatePredicated},
		{arm64SVEShiftImmediateUnpredicatedBases, arm64SVELSRImmediateUnpredicated},
	}

	var source strings.Builder
	source.WriteString("TEXT rawSVEShiftForms(SB),$0-0\n")
	for _, grammar := range forms {
		if len(grammar.bases) != 3 {
			t.Fatalf("SVE shift mode %d has %d operations, want ASR/LSL/LSR", grammar.mode, len(grammar.bases))
		}
		for base, op := range grammar.bases {
			for _, width := range []int{8, 16, 32, 64} {
				if (grammar.mode == arm64SVELSRWidePredicated || grammar.mode == arm64SVELSRWideUnpredicated) && width == 64 {
					continue
				}
				word := base
				if grammar.mode <= arm64SVELSRVectorPredicated {
					word |= uint32(map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[width]) << 22
				}
				shift := width / 2
				switch grammar.mode {
				case arm64SVELSRWidePredicated, arm64SVELSRVectorPredicated:
					word |= 24<<5 | 7<<10 | 8
				case arm64SVELSRWideUnpredicated:
					word |= 30<<16 | 24<<5 | 8
				case arm64SVELSRImmediatePredicated, arm64SVELSRImmediateUnpredicated:
					encodedShift := shift
					if op == "ZLSL" {
						encodedShift = width - shift
					}
					if grammar.mode == arm64SVELSRImmediatePredicated {
						word |= encodeARM64SVEShiftImmediateBits(width, encodedShift, 5) | 7<<10 | 8
					} else {
						word |= encodeARM64SVEShiftImmediateBits(width, encodedShift, 16) | 24<<5 | 8
					}
				}
				decoded, ok := decodeARM64RawSVEShift(word)
				if !ok || decoded.op != op || decoded.mode != grammar.mode || decoded.elementBits != width || decoded.destination != 8 {
					t.Fatalf("%s width %d mode %d word %#08x decoded as %+v, ok=%v", op, width, grammar.mode, word, decoded, ok)
				}
				if grammar.mode == arm64SVELSRImmediatePredicated || grammar.mode == arm64SVELSRImmediateUnpredicated {
					if decoded.shift != shift {
						t.Fatalf("%s word %#08x shift = %d, want %d", op, word, decoded.shift, shift)
					}
				}
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			}
		}
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
					"rawSVEShiftForms": {Name: "rawSVEShiftForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-shift-forms.ll", "arm64-raw-sve-shift-forms.o", ir)
		})
	}
}

func TestTranslateARM64RawSVEShiftGoHighwayRegression(t *testing.T) {
	const source = `
TEXT rawSVEShift(SB),$0-0
	WORD $0x046d9c42 // LSL Z2.S, Z2.S, #13
	WORD $0x04779d4a // LSL Z10.S, Z10.S, #23
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
					"rawSVEShift": {Name: "rawSVEShift", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-shift.ll", "arm64-raw-sve-shift.o", ir)
		})
	}
}
