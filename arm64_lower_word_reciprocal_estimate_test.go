package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64RawReciprocalCompleteArchitectureFamily(t *testing.T) {
	forms := []struct {
		name   string
		base   uint32
		binary bool
	}{
		{"FRECPE H", 0x5ef9d800, false},
		{"FRECPE S", 0x5ea1d800, false},
		{"FRECPE D", 0x5ee1d800, false},
		{"FRECPE H4", 0x0ef9d800, false},
		{"FRECPE H8", 0x4ef9d800, false},
		{"FRECPE S2", 0x0ea1d800, false},
		{"FRECPE S4", 0x4ea1d800, false},
		{"FRECPE D2", 0x4ee1d800, false},
		{"FRECPX H", 0x5ef9f800, false},
		{"FRECPX S", 0x5ea1f800, false},
		{"FRECPX D", 0x5ee1f800, false},
		{"FRSQRTE H", 0x7ef9d800, false},
		{"FRSQRTE S", 0x7ea1d800, false},
		{"FRSQRTE D", 0x7ee1d800, false},
		{"FRSQRTE H4", 0x2ef9d800, false},
		{"FRSQRTE H8", 0x6ef9d800, false},
		{"FRSQRTE S2", 0x2ea1d800, false},
		{"FRSQRTE S4", 0x6ea1d800, false},
		{"FRSQRTE D2", 0x6ee1d800, false},
		{"FRECPS H", 0x5e403c00, true},
		{"FRECPS S", 0x5e20fc00, true},
		{"FRECPS D", 0x5e60fc00, true},
		{"FRECPS H4", 0x0e403c00, true},
		{"FRECPS H8", 0x4e403c00, true},
		{"FRECPS S2", 0x0e20fc00, true},
		{"FRECPS S4", 0x4e20fc00, true},
		{"FRECPS D2", 0x4e60fc00, true},
		{"FRSQRTS H", 0x5ec03c00, true},
		{"FRSQRTS S", 0x5ea0fc00, true},
		{"FRSQRTS D", 0x5ee0fc00, true},
		{"FRSQRTS H4", 0x0ec03c00, true},
		{"FRSQRTS H8", 0x4ec03c00, true},
		{"FRSQRTS S2", 0x0ea0fc00, true},
		{"FRSQRTS S4", 0x4ea0fc00, true},
		{"FRSQRTS D2", 0x4ee0fc00, true},
	}

	var source strings.Builder
	source.WriteString("TEXT reciprocalEstimateArchitectureForms(SB),$0-0\n")
	for _, form := range forms {
		word := form.base | 31<<5 | 30
		if form.binary {
			word |= 29 << 16
		}
		fmt.Fprintf(&source, "\tWORD $%#08x // %s\n", word, form.name)
	}
	source.WriteString("\tRET\n")

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"reciprocalEstimateArchitectureForms": {
						Name: "reciprocalEstimateArchitectureForms",
						Ret:  Void,
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.aarch64.neon.frecpe.f16",
				"@llvm.aarch64.neon.frecpe.f32",
				"@llvm.aarch64.neon.frecpe.f64",
				"@llvm.aarch64.neon.frecpe.v4f16",
				"@llvm.aarch64.neon.frecpe.v8f16",
				"@llvm.aarch64.neon.frecpe.v2f32",
				"@llvm.aarch64.neon.frecpe.v4f32",
				"@llvm.aarch64.neon.frecpe.v2f64",
				"@llvm.aarch64.neon.frecpx.f16",
				"@llvm.aarch64.neon.frecpx.f32",
				"@llvm.aarch64.neon.frecpx.f64",
				"@llvm.aarch64.neon.frsqrte.f16",
				"@llvm.aarch64.neon.frsqrte.f32",
				"@llvm.aarch64.neon.frsqrte.f64",
				"@llvm.aarch64.neon.frsqrte.v4f16",
				"@llvm.aarch64.neon.frsqrte.v8f16",
				"@llvm.aarch64.neon.frsqrte.v2f32",
				"@llvm.aarch64.neon.frsqrte.v4f32",
				"@llvm.aarch64.neon.frsqrte.v2f64",
				"@llvm.aarch64.neon.frecps.f16",
				"@llvm.aarch64.neon.frecps.v8f16",
				"@llvm.aarch64.neon.frecps.v4f32",
				"@llvm.aarch64.neon.frecps.v2f64",
				"@llvm.aarch64.neon.frsqrts.f16",
				"@llvm.aarch64.neon.frsqrts.v8f16",
				"@llvm.aarch64.neon.frsqrts.v4f32",
				"@llvm.aarch64.neon.frsqrts.v2f64",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw reciprocal estimate IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-reciprocal-estimate.ll", "arm64-reciprocal-estimate.o", ir)
		})
	}
}

func TestARM64RawReciprocalEstimateDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x5ea1dc00, // FRECPS.
		0x7ea1fc00, // FRSQRTS.
		0x0ee1d800, // Reserved vector D1.
		0x1ea1d800, // Scalar encoding with an invalid opcode class.
	} {
		if form, ok := decodeARM64RawReciprocalEstimate(word); ok {
			t.Fatalf("decoder accepted adjacent/reserved encoding %#08x as %#v", word, form)
		}
	}
}
