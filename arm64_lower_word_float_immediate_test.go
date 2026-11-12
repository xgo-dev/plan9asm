package plan9asm

import (
	"math"
	"strings"
	"testing"
)

func TestTranslateARM64RawFloatImmediateCompleteArchitecturalFormats(t *testing.T) {
	const source = `
TEXT rawFloatImmediateFormats(SB),$0-0
	WORD $0x0f03fe00 // FMOV V0.4H, #1.0
	WORD $0x4f03fe01 // FMOV V1.8H, #1.0
	WORD $0x0f03f602 // FMOV V2.2S, #1.0
	WORD $0x4f03f603 // FMOV V3.4S, #1.0
	WORD $0x6f03f604 // FMOV V4.2D, #1.0
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawFloatImmediateFormats": {Name: "rawFloatImmediateFormats", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"<8 x i16>", "<4 x i32>", "<2 x i64>"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw float immediate IR omitted %q:\n%s", want, ir)
				}
			}
			if !strings.Contains(ir, `"target-features"="+fullfp16"`) {
				t.Fatalf("raw half float immediate omitted +fullfp16:\n%s", ir)
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-float-immediate.ll", "arm64-raw-float-immediate.o", ir)
		})
	}
}

func TestARM64RawFloatImmediateDecoderCoversEveryImmediate(t *testing.T) {
	forms := []struct {
		base        uint32
		arrangement arm64VectorArrangement
	}{
		{0x0f00fc00, arm64VectorArrangement{elementBits: 16, lanes: 4}},
		{0x4f00fc00, arm64VectorArrangement{elementBits: 16, lanes: 8}},
		{0x0f00f400, arm64VectorArrangement{elementBits: 32, lanes: 2}},
		{0x4f00f400, arm64VectorArrangement{elementBits: 32, lanes: 4}},
		{0x6f00f400, arm64VectorArrangement{elementBits: 64, lanes: 2}},
	}
	for _, form := range forms {
		for immediate := 0; immediate < 256; immediate++ {
			word := form.base |
				uint32(immediate>>5)<<16 |
				uint32(immediate&31)<<5 |
				31
			decoded, ok := decodeARM64RawFloatImmediate(word)
			if !ok || decoded.arrangement != form.arrangement || decoded.destination != 31 {
				t.Fatalf("decode %#08x = %#v, %v", word, decoded, ok)
			}
			value := arm64ExpandedFloatImmediate(byte(immediate))
			want := math.Float64bits(value)
			switch form.arrangement.elementBits {
			case 16:
				want = uint64(arm64Float16Bits(value))
			case 32:
				want = uint64(math.Float32bits(float32(value)))
			}
			if decoded.laneValue != want {
				t.Fatalf("decode %#08x lane value = %#x, want %#x", word, decoded.laneValue, want)
			}
		}
	}
}

func TestARM64RawFloatImmediateDecoderRejectsReservedAndAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2f03f600, // Reserved D1 encoding.
		0x0f03e400, // MOVI neighbor.
		0x0f03f000, // Different modified-immediate cmode.
	} {
		if form, ok := decodeARM64RawFloatImmediate(word); ok {
			t.Fatalf("decoder accepted adjacent/reserved encoding %#08x as %#v", word, form)
		}
	}
}
