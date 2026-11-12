package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEUnpackCompleteFamily(t *testing.T) {
	operations := []struct {
		name      string
		opcode    uint32
		intrinsic string
	}{
		{"SUNPKLO", 0, "sunpklo"},
		{"SUNPKHI", 1, "sunpkhi"},
		{"UUNPKLO", 2, "uunpklo"},
		{"UUNPKHI", 3, "uunpkhi"},
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
				word := uint32(0x05303800) | width.bits<<22 | operation.opcode<<16 | 1<<5
				source := fmt.Sprintf("TEXT sveUnpackRaw(SB),$0-0\n\tWORD $%#08x\n\tRET\n", word)
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
								"sveUnpackRaw": {Name: "sveUnpackRaw", Ret: Void},
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
						compileLLVMToObject(t, llc, triple, "arm64-sve-unpack-raw.ll", "arm64-sve-unpack-raw.o", ir)
					})
				}
			})
		}
	}
}

func TestDecodeARM64RawSVEUnpackRegistersAndBoundaries(t *testing.T) {
	for _, base := range []uint32{
		0x05703800, 0x05b03800, 0x05f03800,
		0x05713800, 0x05b13800, 0x05f13800,
		0x05723800, 0x05b23800, 0x05f23800,
		0x05733800, 0x05b33800, 0x05f33800,
	} {
		word := base | 23<<5 | 17
		decoded, ok := decodeARM64RawSVEUnpack(word)
		if !ok {
			t.Fatalf("failed to decode %#08x", word)
		}
		if !strings.HasPrefix(string(decoded.Args[0].Reg), "Z23.") || !strings.HasPrefix(string(decoded.Args[1].Reg), "Z17.") {
			t.Fatalf("wrong register fields for %#08x: %+v", word, decoded.Args)
		}
	}

	for _, word := range []uint32{
		0x05303800, // Byte-width destination is reserved.
		0x05703c00, // Adjacent encoding with bit 10 set.
		0x05707800, // Adjacent encoding with bit 14 set.
	} {
		if decoded, ok := decodeARM64RawSVEUnpack(word); ok {
			t.Fatalf("accepted unrelated encoding %#08x as %+v", word, decoded)
		}
	}
}
