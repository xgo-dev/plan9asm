package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func encodeARM64RawBitfield(opc uint32, width, immr, imms, source, destination int) uint32 {
	word := uint32(0x13000000) | opc<<29 | uint32(immr)<<16 | uint32(imms)<<10 | uint32(source)<<5 | uint32(destination)
	if width == 64 {
		word |= 1<<31 | 1<<22
	}
	return word
}

func TestTranslateARM64RawBitfieldCompleteFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawbitfieldforms(SB),$0-0\n")
	for _, opc := range []uint32{0, 1, 2} { // SBFM, BFM, UBFM.
		for _, width := range []int{32, 64} {
			for _, immediates := range [][2]int{{0, 0}, {0, width - 1}, {width - 1, 0}, {width - 1, width - 1}, {3, 17}, {width - 3, 11}} {
				fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawBitfield(opc, width, immediates[0], immediates[1], 1, 2))
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"rawbitfieldforms": {Name: "rawbitfieldforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-bitfield.ll", "arm64-raw-bitfield.o", ll)
		})
	}
}

func TestARM64RawBitfieldDecoderCoversEntireImmediateDomain(t *testing.T) {
	operations := []Op{"SBFM", "BFM", "UBFM"}
	for opc, operation := range operations {
		for _, width := range []int{32, 64} {
			for immr := 0; immr < width; immr++ {
				for imms := 0; imms < width; imms++ {
					word := encodeARM64RawBitfield(uint32(opc), width, immr, imms, 29, 30)
					got, ok := decodeARM64RawBitfield(word)
					if !ok {
						t.Fatalf("decoder rejected %s width=%d immr=%d imms=%d", operation, width, immr, imms)
					}
					if got.op != operation || got.width != width || got.immr != immr || got.imms != imms || got.source != 29 || got.destination != 30 {
						t.Fatalf("decoded word %#08x as %+v", word, got)
					}
				}
			}
		}
	}
}

func TestARM64RawBitfieldRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	source.WriteString("TEXT rawbitfield(SB),$0-24\n\tMOVD out+0(FP), R0\n\tMOVD input+8(FP), R1\n\tMOVD initial+16(FP), R2\n")
	words := []uint32{
		encodeARM64RawBitfield(2, 64, 61, 60, 1, 3), // LSL #3.
		encodeARM64RawBitfield(2, 64, 8, 63, 1, 4),  // LSR #8.
		encodeARM64RawBitfield(2, 64, 8, 15, 1, 5),  // UBFX #8, #8.
		encodeARM64RawBitfield(2, 64, 56, 7, 1, 6),  // UBFIZ #8, #8.
		encodeARM64RawBitfield(0, 64, 8, 63, 1, 7),  // ASR #8.
		encodeARM64RawBitfield(0, 64, 32, 39, 1, 8), // SBFX #32, #8.
	}
	for _, word := range words {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
	}
	source.WriteString("\tMOVD R2, R9\n\tMOVD R2, R10\n")
	fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawBitfield(1, 64, 0, 7, 1, 9))   // BFXIL #0, #8.
	fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawBitfield(1, 64, 56, 7, 1, 10)) // BFI #8, #8.
	for i, reg := range []int{3, 4, 5, 6, 7, 8, 9, 10} {
		fmt.Fprintf(&source, "\tMOVD R%d, %d(R0)\n", reg, i*8)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"rawbitfield": {
			Name: "rawbitfield", Args: []LLVMType{Ptr, I64, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawbitfield(uint64_t *, uint64_t, uint64_t);
int main(void) {
  uint64_t got[8] = {0};
  rawbitfield(got, UINT64_C(0xfedcba9876543210), UINT64_C(0x1111222233334444));
  const uint64_t want[8] = {
    UINT64_C(0xf6e5d4c3b2a19080), UINT64_C(0x00fedcba98765432), UINT64_C(0x32), UINT64_C(0x1000),
    UINT64_C(0xfffedcba98765432), UINT64_C(0xffffffffffffff98), UINT64_C(0x1111222233334410), UINT64_C(0x1111222233331044),
  };
  for (int i = 0; i < 8; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_bitfield", triple, ll, mainC, nil)
}

func TestARM64RawBitfieldDecoderRejectsReservedAndAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		encodeARM64RawBitfield(3, 64, 0, 0, 0, 0), // reserved opc.
		encodeARM64RawBitfield(2, 32, 32, 0, 0, 0),
		encodeARM64RawBitfield(2, 32, 0, 32, 0, 0),
		0x12000000, // logical immediate.
	} {
		if _, ok := decodeARM64RawBitfield(word); ok {
			t.Fatalf("bitfield decoder accepted reserved/adjacent encoding %#08x", word)
		}
	}
}
