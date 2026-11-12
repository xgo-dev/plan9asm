package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var arm64SVEPTruePatterns = []int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
}

func encodeARM64RawSVEPTrue(elementBits, pattern, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x2518e000 | size<<22 | uint32(pattern)<<5 | uint32(destination)
}

func TestTranslateARM64RawSVEPTrueCompleteFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawptrueforms(SB),$0-0\n")
	destination := 0
	for _, elementBits := range []int{8, 16, 32, 64} {
		for _, pattern := range arm64SVEPTruePatterns {
			fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawSVEPTrue(elementBits, pattern, destination%16))
			destination++
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
				Sigs:         map[string]FuncSig{"rawptrueforms": {Name: "rawptrueforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.ptrue.nxv16i1", "@llvm.aarch64.sve.ptrue.nxv8i1",
				"@llvm.aarch64.sve.ptrue.nxv4i1", "@llvm.aarch64.sve.ptrue.nxv2i1",
				"@llvm.aarch64.sve.convert.to.svbool.nxv2i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw PTRUE lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-ptrue.ll", "arm64-raw-sve-ptrue.o", ll)
		})
	}
}

func TestARM64RawSVEPTrueDecoderCoversArchitecturalDomain(t *testing.T) {
	for _, elementBits := range []int{8, 16, 32, 64} {
		for _, pattern := range arm64SVEPTruePatterns {
			for destination := 0; destination < 16; destination++ {
				word := encodeARM64RawSVEPTrue(elementBits, pattern, destination)
				got, ok := decodeARM64RawSVEPTrue(word)
				if !ok || got.elementBits != elementBits || got.pattern != pattern || got.destination != destination {
					t.Fatalf("decoded PTRUE word %#08x as %+v, ok=%v", word, got, ok)
				}
			}
		}
	}
}

func TestARM64RawSVEPTrueDecoderRejectsReservedAndAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2518e010, // PTRUES, which also updates flags.
		0x2519e000, // Neighboring opcode, not a pattern field.
		0x2518e400, // PFALSE.
	} {
		if _, ok := decodeARM64RawSVEPTrue(word); ok {
			t.Fatalf("PTRUE decoder accepted reserved/adjacent encoding %#08x", word)
		}
	}
}
