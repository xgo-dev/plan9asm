package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEContiguousHalfwordMemoryCompleteFamily(t *testing.T) {
	forms := []struct {
		name      string
		word      uint32
		intrinsic string
	}{
		{"LD1H H immediate", 0xa4a0a000, "ld1.nxv8i16"},
		{"LD1H S immediate", 0xa4c0a000, "ld1.nxv4i16"},
		{"LD1H D immediate", 0xa4e0a000, "ld1.nxv2i16"},
		{"LD1H H register", 0xa4a14000, "ld1.nxv8i16"},
		{"LD1H S register", 0xa4c14000, "ld1.nxv4i16"},
		{"LD1H D register", 0xa4e14000, "ld1.nxv2i16"},
		{"ST1H H immediate", 0xe4a0e000, "st1.nxv8i16"},
		{"ST1H S immediate", 0xe4c0e000, "st1.nxv4i16"},
		{"ST1H D immediate", 0xe4e0e000, "st1.nxv2i16"},
		{"ST1H H register", 0xe4a14000, "st1.nxv8i16"},
		{"ST1H S register", 0xe4c14000, "st1.nxv4i16"},
		{"ST1H D register", 0xe4e14000, "st1.nxv2i16"},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT sveHalfwordRaw(SB),$0-0\n")
			fmt.Fprintf(&source, "\tWORD $%#08x // %s\n", form.word, form.name)
			source.WriteString("\tRET\n")
			requireARM64SVEGoAssemblerResult(t, source.String(), true)

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
							"sveHalfwordRaw": {Name: "sveHalfwordRaw", Ret: Void},
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{
						"@llvm.aarch64.sve." + form.intrinsic,
						`"target-features"="+sve"`,
					} {
						if !strings.Contains(ir, want) {
							t.Fatalf("omitted %q:\n%s", want, ir)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-halfword-raw.ll", "arm64-sve-halfword-raw.o", ir)
				})
			}
		})
	}
}

func TestDecodeARM64RawSVEContiguousHalfwordMemoryBoundaries(t *testing.T) {
	for _, test := range []struct {
		word      uint32
		op        Op
		base      Reg
		index     Reg
		scale     int64
		offsetRaw string
		vector    Reg
	}{
		{0xa4a0a008, "ZLD1H", "R0", "", 0, "", "Z8.H"},
		{0xa4a8a008, "ZLD1H", "R0", "", 0, "-VL*8", "Z8.H"},
		{0xa4a7a008, "ZLD1H", "R0", "", 0, "VL*7", "Z8.H"},
		{0xa4a14008, "ZLD1H", "R0", "R1", 2, "", "Z8.H"},
		{0xe4e14008, "ZST1H", "R0", "R1", 2, "", "Z8.D"},
	} {
		ins, ok := decodeARM64RawSVEContiguousMemory(test.word)
		if !ok || ins.Op != test.op || len(ins.Args) != 3 {
			t.Fatalf("decode %#08x = %+v, %v", test.word, ins, ok)
		}
		memoryIndex, vectorIndex := 0, 2
		if test.op == "ZST1H" {
			memoryIndex, vectorIndex = 2, 0
		}
		memory := ins.Args[memoryIndex].Mem
		if memory.Base != test.base || memory.Index != test.index || memory.Scale != test.scale || memory.OffRaw != test.offsetRaw {
			t.Errorf("%#08x memory = %+v", test.word, memory)
		}
		if ins.Args[vectorIndex].Kind != OpRegList || ins.Args[vectorIndex].RegList[0] != test.vector {
			t.Errorf("%#08x vector = %+v", test.word, ins.Args[vectorIndex])
		}
	}

	for _, word := range []uint32{
		0xa480a000, // This is LD1SW, not LD1H.
		0xe480e000, // No byte-width ST1H variant.
		0xa4a0a000 | 1<<14,
	} {
		if ins, ok := decodeARM64RawSVEContiguousMemory(word); ok {
			t.Fatalf("decoded unrelated encoding %#08x as %+v", word, ins)
		}
	}
}
