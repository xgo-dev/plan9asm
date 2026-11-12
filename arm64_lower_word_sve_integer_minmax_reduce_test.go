package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEIntegerMinMaxReductionCompleteFamily(t *testing.T) {
	operations := []struct {
		name      string
		opcode    uint32
		intrinsic string
	}{
		{"SMAXV", 8, "smaxv"},
		{"UMAXV", 9, "umaxv"},
		{"SMINV", 10, "sminv"},
		{"UMINV", 11, "uminv"},
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
			t.Run(operation.name+"/"+width.name, func(t *testing.T) {
				word := uint32(0x04002000) | width.bits<<22 | operation.opcode<<16 | 1<<5
				source := fmt.Sprintf("TEXT sveMinMaxReduceRaw(SB),$0-0\n\tWORD $%#08x\n\tRET\n", word)
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
								"sveMinMaxReduceRaw": {Name: "sveMinMaxReduceRaw", Ret: Void},
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
						compileLLVMToObject(t, llc, triple, "arm64-sve-minmax-reduce-raw.ll", "arm64-sve-minmax-reduce-raw.o", ir)
					})
				}
			})
		}
	}
}

func TestDecodeARM64RawSVEIntegerMinMaxReductionRegistersAndBoundaries(t *testing.T) {
	for _, opcode := range []uint32{8, 9, 10, 11} {
		for size := uint32(0); size < 4; size++ {
			word := uint32(0x04002000) | size<<22 | opcode<<16 | 23<<5 | 5<<10 | 17
			decoded, ok := decodeARM64RawSVEIntegerMinMaxReduction(word)
			if !ok || len(decoded.Args) != 3 {
				t.Fatalf("failed to decode %#08x: %+v", word, decoded)
			}
			if !strings.HasPrefix(string(decoded.Args[0].Reg), "Z23.") || decoded.Args[1].Reg != "P5" || decoded.Args[2].Reg != "V17" {
				t.Fatalf("wrong register fields for %#08x: %+v", word, decoded.Args)
			}
		}
	}

	for _, word := range []uint32{
		0x04072000, // Before the reduction opcode range.
		0x040c2000, // After the reduction opcode range.
		0x04080000, // Predicated vector SMAX, not a reduction.
	} {
		if decoded, ok := decodeARM64RawSVEIntegerMinMaxReduction(word); ok {
			t.Fatalf("accepted unrelated encoding %#08x as %+v", word, decoded)
		}
	}
}
