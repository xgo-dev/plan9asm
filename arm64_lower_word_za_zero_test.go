package plan9asm

import (
	"strings"
	"testing"
)

func TestARM64RawZAZeroDecoderCompleteArchitectureFamily(t *testing.T) {
	for mask := 0; mask < 256; mask++ {
		word := uint32(0xc0080000 | mask)
		got, ok := decodeARM64RawZAZero(word)
		if !ok {
			t.Fatalf("decoder rejected %#08x", word)
		}
		if got != uint8(mask) {
			t.Fatalf("decode %#08x = %#02x, want %#02x", word, got, mask)
		}
	}
}

func TestTranslateARM64RawZAZeroCompleteArchitectureFamily(t *testing.T) {
	const source = `
TEXT rawZAZeroFamily(SB),$0-0
	WORD $0xc0080000 // ZERO {}
	WORD $0xc0080001 // ZERO {ZA0.D}
	WORD $0xc0080055 // ZERO {ZA0.H}
	WORD $0xc00800ff // ZERO {ZA}
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
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
					"rawZAZeroFamily": {Name: "rawZAZeroFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`asm sideeffect "zero {}"`,
				`asm sideeffect "zero {za0.d}"`,
				`asm sideeffect "zero {za0.d, za2.d, za4.d, za6.d}"`,
				`asm sideeffect "zero {za0.d, za1.d, za2.d, za3.d, za4.d, za5.d, za6.d, za7.d}"`,
				`"target-features"="+sme"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw ZA ZERO IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-za-zero.ll", "arm64-raw-za-zero.o", ir)
		})
	}
}

func TestARM64RawZAZeroDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0xc0080100,
		0xc0090001,
		0xc0040001,
		0xd5080001,
	} {
		if _, ok := decodeARM64RawZAZero(word); ok {
			t.Fatalf("ZA ZERO decoder accepted adjacent encoding %#08x", word)
		}
	}
}
