package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEIntegerMinMaxCompleteDirectFamily(t *testing.T) {
	operations := []struct {
		name      string
		opcode    uint32
		intrinsic string
		immediate int64
	}{
		{"SMAX", 0, "smax", -128},
		{"UMAX", 1, "umax", 255},
		{"SMIN", 2, "smin", 127},
		{"UMIN", 3, "umin", 0},
	}
	widths := []struct {
		name   string
		bits   uint32
		suffix string
	}{
		{"B", 0, "nxv16i8"},
		{"H", 1, "nxv8i16"},
		{"S", 2, "nxv4i32"},
		{"D", 3, "nxv2i64"},
	}
	for _, operation := range operations {
		for _, width := range widths {
			for _, encoding := range []string{"predicated", "immediate"} {
				t.Run(operation.name+"/"+width.name+"/"+encoding, func(t *testing.T) {
					word := uint32(0x04080000) | width.bits<<22 | operation.opcode<<16 | 8<<5
					if encoding == "immediate" {
						word = uint32(0x2528c000) | width.bits<<22 | operation.opcode<<16 | uint32(uint8(operation.immediate))<<5
					}
					source := fmt.Sprintf("TEXT sveMinMaxRaw(SB),$0-0\n\tWORD $%#08x\n\tRET\n", word)
					requireARM64SVEGoAssemblerResult(t, source, true)
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
									"sveMinMaxRaw": {Name: "sveMinMaxRaw", Ret: Void},
								},
							})
							if err != nil {
								t.Fatal(err)
							}
							for _, want := range []string{
								"@llvm.aarch64.sve." + operation.intrinsic + "." + width.suffix,
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
							compileLLVMToObject(t, llc, triple, "arm64-sve-minmax-raw.ll", "arm64-sve-minmax-raw.o", ir)
						})
					}
				})
			}
		}
	}
}

func TestDecodeARM64RawSVEIntegerMinMaxRegistersAndBoundaries(t *testing.T) {
	predicated, ok := decodeARM64RawSVEIntegerMinMax(0x04ca0100)
	if !ok || predicated.Op != "ZSMIN" || len(predicated.Args) != 4 ||
		predicated.Args[0].Reg != "Z8.D" || predicated.Args[1].Reg != "Z0.D" ||
		predicated.Args[2].Reg != "P0.M" || predicated.Args[3].Reg != "Z0.D" {
		t.Fatalf("wrong predicated SMIN decode: %+v, %v", predicated, ok)
	}

	for _, test := range []struct {
		word uint32
		op   Op
		imm  int64
	}{
		{0x2528d000, "ZSMAX", -128},
		{0x252acfe0, "ZSMIN", 127},
		{0x2529dfe0, "ZUMAX", 255},
		{0x252bc000, "ZUMIN", 0},
	} {
		decoded, ok := decodeARM64RawSVEIntegerMinMax(test.word)
		if !ok || decoded.Op != test.op || len(decoded.Args) != 3 || decoded.Args[0].Kind != OpImm || decoded.Args[0].Imm != test.imm {
			t.Fatalf("wrong immediate min/max decode for %#08x: %+v, %v", test.word, decoded, ok)
		}
	}

	for _, word := range []uint32{
		0x04070100, // Before the predicated opcode range.
		0x040c0100, // After the predicated opcode range.
		0x2528e000, // Different immediate instruction class.
	} {
		if decoded, ok := decodeARM64RawSVEIntegerMinMax(word); ok {
			t.Fatalf("accepted unrelated encoding %#08x as %+v", word, decoded)
		}
	}
}
