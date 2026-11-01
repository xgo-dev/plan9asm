package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVEDupGeneral(elementBits, source, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x05203800 | size<<22 | uint32(source)<<5 | uint32(destination)
}

func TestTranslateARM64RawSVEDupGeneralCompleteArchitecturalForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT sveDupGeneralRaw(SB), $0-0\n")
	for _, elementBits := range []int{8, 16, 32, 64} {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawSVEDupGeneral(elementBits, 15, elementBits/8))
	}
	source.WriteString("\tRET\n")

	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveDupGeneralRaw": {Name: "sveDupGeneralRaw", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve"`, "<vscale x 16 x i8>", "insertelement <vscale", "shufflevector <vscale"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("%s SVE DUP general IR omitted %q:\n%s", triple, want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-dup-general.ll", "arm64-sve-dup-general.o", ir)
		})
	}
}

func TestARM64RawSVEDupGeneralDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, elementBits := range []int{8, 16, 32, 64} {
		for source := 0; source < 32; source++ {
			for destination := 0; destination < 32; destination++ {
				word := encodeARM64RawSVEDupGeneral(elementBits, source, destination)
				got, ok := decodeARM64RawSVEDupGeneral(word)
				if !ok || got.elementBits != elementBits || got.source != source || got.destination != destination {
					t.Fatalf("decoded SVE DUP general %#08x as %+v, ok=%v", word, got, ok)
				}
				count++
			}
		}
	}
	if count != 4*32*32 {
		t.Fatalf("covered %d SVE DUP general encodings, want %d", count, 4*32*32)
	}
}

func TestARM64RawSVEDupGeneralDecoderRejectsAdjacentEncoding(t *testing.T) {
	for _, word := range []uint32{0x05203c00, 0x05203000} {
		if _, ok := decodeARM64RawSVEDupGeneral(word); ok {
			t.Fatalf("SVE DUP general decoder accepted adjacent encoding %#08x", word)
		}
	}
}
