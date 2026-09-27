package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawVFPImmediate(condition, bits, destination, immediate int) uint32 {
	word := uint32(condition)<<28 | 0x0eb00a00
	word |= uint32(immediate>>4) << 16
	word |= uint32(immediate & 15)
	if bits == 32 {
		word |= uint32(destination&1) << 22
		word |= uint32(destination>>1) << 12
	} else {
		word |= 1 << 8
		word |= uint32(destination>>4) << 22
		word |= uint32(destination&15) << 12
	}
	return word
}

func TestARMRawVFPImmediateDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for condition := 0; condition < 15; condition++ {
		for _, width := range []int{32, 64} {
			for destination := 0; destination < 32; destination++ {
				for immediate := 0; immediate < 256; immediate++ {
					word := encodeARMRawVFPImmediate(condition, width, destination, immediate)
					got, ok := decodeARMRawVFPImmediate(word)
					if !ok {
						t.Fatalf("decodeARMRawVFPImmediate(%#08x) failed", word)
					}
					if got.bits != width || got.destination != destination || got.immediate != uint8(immediate) {
						t.Fatalf("decodeARMRawVFPImmediate(%#08x) = %+v", word, got)
					}
					count++
				}
			}
		}
	}
	if count != 15*2*32*256 {
		t.Fatalf("covered %d VFP immediate encodings", count)
	}
}

func TestARMRawVFPImmediateExpansion(t *testing.T) {
	for _, test := range []struct {
		immediate uint8
		bits      int
		want      uint64
	}{
		{immediate: 0x70, bits: 32, want: 0x3f800000},
		{immediate: 0x70, bits: 64, want: 0x3ff0000000000000},
		{immediate: 0xf0, bits: 32, want: 0xbf800000},
		{immediate: 0xf0, bits: 64, want: 0xbff0000000000000},
		{immediate: 0x00, bits: 32, want: 0x40000000},
		{immediate: 0x0f, bits: 64, want: 0x400f000000000000},
	} {
		if got := expandARMVFPImmediate(test.immediate, test.bits); got != test.want {
			t.Fatalf("expandARMVFPImmediate(%#x, %d) = %#x, want %#x", test.immediate, test.bits, got, test.want)
		}
	}
}

func TestTranslateARMRawVFPImmediateFamilyThroughLLVM22(t *testing.T) {
	words := []uint32{
		encodeARMRawVFPImmediate(14, 64, 0, 0x70),
		encodeARMRawVFPImmediate(14, 32, 30, 0x70),
		encodeARMRawVFPImmediate(14, 32, 31, 0xf0),
		encodeARMRawVFPImmediate(14, 64, 16, 0x00),
	}
	var source strings.Builder
	source.WriteString("TEXT rawVFPImmediate(SB), $0-0\n")
	for _, word := range words {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
	}
	source.WriteString("\tRET\n")
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"rawVFPImmediate": {Name: "rawVFPImmediate", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1065353216", "-4647714815446351872", "4611686018427387904", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw VFP immediate family omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-vfp-immediate.ll", "arm-vfp-immediate.o", ir)
}

func TestARMRawVFPImmediateRejectsReservedAndDifferentForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawVFPImmediate(15, 64, 0, 0x70),
		encodeARMRawVFPImmediate(14, 64, 0, 0x70) | 1<<6,
		0xeeb00b40, // VMOV.F64 D0,D0.
	} {
		if got, ok := decodeARMRawVFPImmediate(word); ok {
			t.Fatalf("decoded reserved/different form %#08x as %+v", word, got)
		}
	}
}
