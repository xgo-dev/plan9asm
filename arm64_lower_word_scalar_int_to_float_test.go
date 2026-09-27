package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawScalarIntToFloatDecoderCompleteGPRRegisterFamily(t *testing.T) {
	floatWidths := []struct {
		bits     int
		typeBits uint32
	}{
		{bits: 16, typeBits: 3},
		{bits: 32, typeBits: 0},
		{bits: 64, typeBits: 1},
	}

	count := 0
	for _, floatWidth := range floatWidths {
		for _, integerBits := range []int{32, 64} {
			for _, unsigned := range []bool{false, true} {
				for source := 0; source < 32; source++ {
					for destination := 0; destination < 32; destination++ {
						word := uint32(0x1e220000) |
							floatWidth.typeBits<<22 |
							uint32(source)<<5 |
							uint32(destination)
						if integerBits == 64 {
							word |= 1 << 31
						}
						if unsigned {
							word |= 1 << 16
						}
						form, ok := decodeARM64RawScalarIntToFloat(word)
						if !ok {
							t.Fatalf("decoder rejected %#08x", word)
						}
						if form.floatBits != floatWidth.bits || form.integerBits != integerBits ||
							form.unsigned != unsigned || form.source != source || form.destination != destination {
							t.Fatalf("decode %#08x = %+v", word, form)
						}
						count++
					}
				}
			}
		}
	}
	if count != 12288 {
		t.Fatalf("covered %d scalar integer-to-float encodings, want 12288", count)
	}
}

func TestTranslateARM64RawScalarIntToFloatCompleteGPRRegisterFamily(t *testing.T) {
	floatWidths := []struct {
		name     string
		typeBits uint32
	}{
		{name: "H", typeBits: 3},
		{name: "S", typeBits: 0},
		{name: "D", typeBits: 1},
	}

	var source strings.Builder
	source.WriteString("TEXT rawScalarIntToFloatFamily(SB),$0-0\n")
	destination := 0
	for _, floatWidth := range floatWidths {
		for _, integerBits := range []int{32, 64} {
			for _, unsigned := range []bool{false, true} {
				name := "SCVTF"
				sourceRegister := "W30"
				word := uint32(0x1e220000) |
					floatWidth.typeBits<<22 |
					uint32(30)<<5 |
					uint32(destination)
				if integerBits == 64 {
					word |= 1 << 31
					sourceRegister = "X30"
				}
				if unsigned {
					name = "UCVTF"
					word |= 1 << 16
				}
				fmt.Fprintf(&source, "\tWORD $%#08x // %s %s%d, %s\n", word, name, floatWidth.name, destination, sourceRegister)
				destination++
			}
		}
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
					"rawScalarIntToFloatFamily": {Name: "rawScalarIntToFloatFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"sitofp i32", "sitofp i64", "uitofp i32", "uitofp i64",
				"to half", "to float", "to double",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw scalar integer-to-float IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-scalar-int-to-float.ll", "arm64-raw-scalar-int-to-float.o", ir)
		})
	}
}

func TestARM64RawScalarIntToFloatDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1ea20000, // Reserved floating type=2 encoding.
		0x1e02fc20, // Fixed-point SCVTF, a separate encoding family.
		0x1e200000, // FCVTNS, the opposite conversion direction.
		0x4e21d800, // Advanced SIMD SCVTF.
	} {
		if _, ok := decodeARM64RawScalarIntToFloat(word); ok {
			t.Fatalf("scalar integer-to-float decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
