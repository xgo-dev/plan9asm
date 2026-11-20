package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEIntegerAddReductionCompleteFamily(t *testing.T) {
	forms := []struct {
		name      string
		word      uint32
		intrinsic string
		suffix    string
	}{
		{"SADDV B", 0x04002000, "saddv", "nxv16i8"},
		{"SADDV H", 0x04402000, "saddv", "nxv8i16"},
		{"SADDV S", 0x04802000, "saddv", "nxv4i32"},
		{"UADDV B", 0x04012000, "uaddv", "nxv16i8"},
		{"UADDV H", 0x04412000, "uaddv", "nxv8i16"},
		{"UADDV S", 0x04812000, "uaddv", "nxv4i32"},
		{"UADDV D", 0x04c12000, "uaddv", "nxv2i64"},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT sveIntegerAddRaw(SB),$0-0\n")
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
							"sveIntegerAddRaw": {Name: "sveIntegerAddRaw", Ret: Void},
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{
						"@llvm.aarch64.sve." + form.intrinsic + "." + form.suffix,
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
					compileLLVMToObject(t, llc, triple, "arm64-sve-integer-add-raw.ll", "arm64-sve-integer-add-raw.o", ir)
				})
			}
		})
	}
}

func TestDecodeARM64RawSVEIntegerAddReductionRegistersAndBoundaries(t *testing.T) {
	for _, base := range []uint32{
		0x04002000, 0x04402000, 0x04802000,
		0x04012000, 0x04412000, 0x04812000, 0x04c12000,
	} {
		word := base | 17 | 23<<5 | 5<<10
		if writes, known := arm64RawPoolGPWrites(word); !known || writes != 0 || !arm64RawPoolSVEIgnoresAddress(word, 17) {
			t.Fatalf("%#08x: scalar vector result was mistaken for a GP write", word)
		}
		reduction, ok := decodeARM64RawSVEIntegerAddReduction(word)
		if !ok {
			t.Fatalf("failed to decode %#08x", word)
		}
		if reduction.form.destination != 17 || reduction.form.source != 23 || reduction.form.predicate != 5 {
			t.Fatalf("wrong register fields for %#08x: %+v", word, reduction.form)
		}
		if reduction.destination != "V17" {
			t.Fatalf("wrong scalar destination for %#08x: %s", word, reduction.destination)
		}
	}

	for _, word := range []uint32{
		0x04c02000, // Signed D has no encoding.
		0x04022000, // Adjacent opcode after UADDV.
		0x04000000, // Reduction encoding requires bit 13.
		0x0400a000, // Adjacent encoding with bit 15 set.
	} {
		if _, ok := decodeARM64RawSVEIntegerAddReduction(word); ok {
			t.Fatalf("accepted unrelated encoding %#08x", word)
		}
	}
}
