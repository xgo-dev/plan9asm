package plan9asm

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestARM64RawScalarFloatImmediateDecoderCoversEveryEncoding(t *testing.T) {
	widths := []struct {
		bits int
		base uint32
	}{
		{bits: 16, base: 0x1ee01000},
		{bits: 32, base: 0x1e201000},
		{bits: 64, base: 0x1e601000},
	}

	count := 0
	for _, width := range widths {
		for immediate := 0; immediate < 256; immediate++ {
			for destination := 0; destination < 32; destination++ {
				word := width.base | uint32(immediate)<<13 | uint32(destination)
				form, ok := decodeARM64RawScalarFloatImmediate(word)
				if !ok {
					t.Fatalf("decoder rejected %#08x", word)
				}
				wantValue := arm64ExpandedFloatImmediate(byte(immediate))
				if form.bits != width.bits || form.value != wantValue || form.destination != destination {
					t.Fatalf("decode %#08x = %+v, want bits=%d value=%v destination=%d", word, form, width.bits, wantValue, destination)
				}
				count++
			}
		}
	}
	if count != 24576 {
		t.Fatalf("covered %d scalar float-immediate encodings, want 24576", count)
	}
}

func TestTranslateARM64RawScalarFloatImmediateCompleteArchitectureFamily(t *testing.T) {
	formats := []struct {
		name string
		base uint32
	}{
		{name: "H", base: 0x1ee01000},
		{name: "S", base: 0x1e201000},
		{name: "D", base: 0x1e601000},
	}

	var source strings.Builder
	source.WriteString("TEXT rawScalarFloatImmediateFamily(SB),$0-0\n")
	for destination, format := range formats {
		word := format.base | 0x70<<13 | uint32(destination)
		fmt.Fprintf(&source, "\tWORD $%#08x // FMOV %s%d, #1.0\n", word, format.name, destination)
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
					"rawScalarFloatImmediateFamily": {Name: "rawScalarFloatImmediateFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"bitcast half 0xH3C00", "bitcast float 1.000000e+00", "bitcast double 1.000000e+00",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw scalar float-immediate IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-scalar-float-immediate.ll", "arm64-raw-scalar-float-immediate.o", ir)
		})
	}
}

func TestARM64RawScalarFloatImmediateValueBoundaries(t *testing.T) {
	for _, immediate := range []byte{0x00, 0x0f, 0x70, 0x7f, 0x80, 0xff} {
		word := uint32(0x1e201000) | uint32(immediate)<<13
		form, ok := decodeARM64RawScalarFloatImmediate(word)
		if !ok {
			t.Fatalf("decoder rejected immediate %#02x", immediate)
		}
		if want := arm64ExpandedFloatImmediate(immediate); math.Float64bits(form.value) != math.Float64bits(want) {
			t.Fatalf("immediate %#02x value = %v, want %v", immediate, form.value, want)
		}
	}
}

func TestARM64RawScalarFloatImmediateDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1ea01000, // Reserved type=2 encoding.
		0x1ee00000, // FMOV between half registers.
		0x1e201800, // FDIV, a different instruction class.
		0x0f03f600, // Vector FMOV immediate.
	} {
		if _, ok := decodeARM64RawScalarFloatImmediate(word); ok {
			t.Fatalf("scalar float-immediate decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
