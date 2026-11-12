package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEAddPairwiseLongCompleteFamily(t *testing.T) {
	operations := []struct {
		name      string
		unsigned  uint32
		intrinsic string
	}{
		{"SADALP", 0, "sadalp"},
		{"UADALP", 1, "uadalp"},
	}
	widths := []struct {
		name   string
		bits   uint32
		suffix string
	}{
		{"B-to-H", 1, "nxv8i16"},
		{"H-to-S", 2, "nxv4i32"},
		{"S-to-D", 3, "nxv2i64"},
	}

	for _, operation := range operations {
		for _, width := range widths {
			t.Run(operation.name+"/"+width.name, func(t *testing.T) {
				word := uint32(0x4404a000) | width.bits<<22 | operation.unsigned<<16 | 8<<5
				source := fmt.Sprintf("TEXT sveAddPairRaw(SB),$0-0\n\tWORD $%#08x\n\tRET\n", word)
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
								"sveAddPairRaw": {Name: "sveAddPairRaw", Ret: Void},
							},
						})
						if err != nil {
							t.Fatal(err)
						}
						for _, want := range []string{
							"@llvm.aarch64.sve." + operation.intrinsic + "." + width.suffix,
							`"target-features"="+sve,+sve2"`,
						} {
							if !strings.Contains(ir, want) {
								t.Fatalf("omitted %q:\n%s", want, ir)
							}
						}
						llc := findLLVM22Tool("llc")
						if llc == "" {
							t.Fatal("LLVM 22 llc not found")
						}
						compileLLVMToObject(t, llc, triple, "arm64-sve-add-pair-raw.ll", "arm64-sve-add-pair-raw.o", ir)
					})
				}
			})
		}
	}
}

func TestDecodeARM64RawSVEAddPairwiseLongRegistersAndBoundaries(t *testing.T) {
	for _, base := range []uint32{
		0x4444a000, 0x4484a000, 0x44c4a000,
		0x4445a000, 0x4485a000, 0x44c5a000,
	} {
		word := base | 23<<5 | 5<<10 | 17
		decoded, ok := decodeARM64RawSVEAddPairwiseLong(word)
		if !ok {
			t.Fatalf("failed to decode %#08x", word)
		}
		if !strings.HasPrefix(string(decoded.Args[0].Reg), "Z23.") || decoded.Args[1].Reg != "P5.M" || !strings.HasPrefix(string(decoded.Args[2].Reg), "Z17.") {
			t.Fatalf("wrong register fields for %#08x: %+v", word, decoded.Args)
		}
	}

	for _, word := range []uint32{
		0x4404a000, // Byte-width destination is reserved.
		0x4444e000, // Adjacent encoding with bit 14 set.
		0x4446a000, // Adjacent opcode with bit 17 set.
	} {
		if decoded, ok := decodeARM64RawSVEAddPairwiseLong(word); ok {
			t.Fatalf("accepted unrelated encoding %#08x as %+v", word, decoded)
		}
	}
}
