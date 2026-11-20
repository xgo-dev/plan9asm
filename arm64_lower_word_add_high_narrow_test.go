package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawAddHighNarrow(base uint32, size, first, second, destination int) uint32 {
	return base |
		uint32(size)<<22 |
		uint32(second)<<16 |
		uint32(first)<<5 |
		uint32(destination)
}

func TestTranslateARM64RawAddHighNarrowCompleteArchitectureFamily(t *testing.T) {
	families := []struct {
		name string
		base uint32
	}{
		{"ADDHN", 0x0e204000},
		{"ADDHN2", 0x4e204000},
		{"RADDHN", 0x2e204000},
		{"RADDHN2", 0x6e204000},
		{"SUBHN", 0x0e206000},
		{"SUBHN2", 0x4e206000},
		{"RSUBHN", 0x2e206000},
		{"RSUBHN2", 0x6e206000},
	}

	var source strings.Builder
	source.WriteString("TEXT addHighNarrowArchitectureForms(SB),$0-0\n")
	for _, family := range families {
		for size := 0; size < 3; size++ {
			for _, registers := range [][3]int{{0, 1, 2}, {31, 30, 29}} {
				word := encodeARM64RawAddHighNarrow(
					family.base,
					size,
					registers[0],
					registers[1],
					registers[2],
				)
				fmt.Fprintf(&source, "\tWORD $%#08x // %s size=%d\n", word, family.name, size)
			}
		}
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
					"addHighNarrowArchitectureForms": {
						Name: "addHighNarrowArchitectureForms",
						Ret:  Void,
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{" add <", " sub <", "lshr <", "trunc <", "insertelement <"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw add-high-narrow IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-add-high-narrow.ll", "arm64-add-high-narrow.o", ir)
		})
	}
}

func TestARM64RawAddHighNarrowDecoderRejectsReservedAndAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x0ee04000, // Reserved size=3.
		0x0e205000, // Different opcode in the same Advanced SIMD group.
		0x0e204400, // Different opcode in the same Advanced SIMD group.
		0x0e204000 | 1<<31,
	} {
		if form, ok := decodeARM64RawAddHighNarrow(word); ok {
			t.Fatalf("decoder accepted adjacent/reserved encoding %#08x as %#v", word, form)
		}
	}
}
