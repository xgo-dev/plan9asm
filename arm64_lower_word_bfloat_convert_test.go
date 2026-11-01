package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawBFloatConvertDecoderCompleteArchitectureFamily(t *testing.T) {
	formats := []struct {
		base   uint32
		vector bool
		high   bool
	}{
		{base: 0x1e634000},
		{base: 0x0ea16800, vector: true},
		{base: 0x4ea16800, vector: true, high: true},
	}

	count := 0
	for _, format := range formats {
		for source := 0; source < 32; source++ {
			for destination := 0; destination < 32; destination++ {
				word := format.base | uint32(source)<<5 | uint32(destination)
				form, ok := decodeARM64RawBFloatConvert(word)
				if !ok {
					t.Fatalf("decoder rejected %#08x", word)
				}
				if form.vector != format.vector || form.high != format.high ||
					form.source != source || form.destination != destination {
					t.Fatalf("decode %#08x = %+v", word, form)
				}
				count++
			}
		}
	}
	if count != 3072 {
		t.Fatalf("covered %d BFCVT/BFCVTN encodings, want 3072", count)
	}
}

func TestTranslateARM64RawBFloatConvertCompleteArchitectureFamily(t *testing.T) {
	formats := []struct {
		name string
		base uint32
	}{
		{name: "BFCVT H0, S1", base: 0x1e634000},
		{name: "BFCVTN V2.4H, V3.4S", base: 0x0ea16800},
		{name: "BFCVTN2 V4.8H, V5.4S", base: 0x4ea16800},
	}

	var source strings.Builder
	source.WriteString("TEXT rawBFloatConvertFamily(SB),$0-0\n")
	for index, format := range formats {
		word := format.base | uint32(index*2+1)<<5 | uint32(index*2)
		fmt.Fprintf(&source, "\tWORD $%#08x // %s\n", word, format.name)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	file, err := Parse(ArchARM64, source.String())
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
					"rawBFloatConvertFamily": {Name: "rawBFloatConvertFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"fptrunc float", "to bfloat",
				"fptrunc <4 x float>", "to <4 x bfloat>",
				"insertelement <2 x i64>", "i64 1",
				`"target-features"="+bf16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw BFCVT/BFCVTN IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-bfloat-convert.ll", "arm64-raw-bfloat-convert.o", ir)
		})
	}
}

func TestARM64RawBFloatConvertDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1e234000, // Different scalar floating type.
		0x2ea16800, // Reserved vector Q/op combination.
		0x0e216800, // Different vector conversion opcode.
		0x45218400, // SVE BFCVT.
	} {
		if _, ok := decodeARM64RawBFloatConvert(word); ok {
			t.Fatalf("BFCVT/BFCVTN decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
