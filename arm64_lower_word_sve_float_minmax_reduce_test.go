package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEFloatMinMaxReductionCompleteFamily(t *testing.T) {
	forms := []struct {
		name      string
		word      uint32
		intrinsic string
		suffix    string
	}{
		{"FMAXNMV H", 0x65442000, "fmaxnmv", "nxv8f16"},
		{"FMINNMV H", 0x65452000, "fminnmv", "nxv8f16"},
		{"FMAXV H", 0x65462000, "fmaxv", "nxv8f16"},
		{"FMINV H", 0x65472000, "fminv", "nxv8f16"},
		{"FMAXNMV S", 0x65842000, "fmaxnmv", "nxv4f32"},
		{"FMINNMV S", 0x65852000, "fminnmv", "nxv4f32"},
		{"FMAXV S", 0x65862000, "fmaxv", "nxv4f32"},
		{"FMINV S", 0x65872000, "fminv", "nxv4f32"},
		{"FMAXNMV D", 0x65c42000, "fmaxnmv", "nxv2f64"},
		{"FMINNMV D", 0x65c52000, "fminnmv", "nxv2f64"},
		{"FMAXV D", 0x65c62000, "fmaxv", "nxv2f64"},
		{"FMINV D", 0x65c72000, "fminv", "nxv2f64"},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT sveFloatMinMaxRaw(SB),$0-0\n")
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
							"sveFloatMinMaxRaw": {Name: "sveFloatMinMaxRaw", Ret: Void},
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					want := "@llvm.aarch64.sve." + form.intrinsic + "." + form.suffix
					for _, want := range []string{want, `"target-features"="+sve"`} {
						if !strings.Contains(ir, want) {
							t.Fatalf("omitted %q:\n%s", want, ir)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-float-minmax-raw.ll", "arm64-sve-float-minmax-raw.o", ir)
				})
			}
		})
	}
}

func TestDecodeARM64RawSVEFloatMinMaxReductionRegistersAndBoundaries(t *testing.T) {
	// The opcode and width are fixed by the SVE grammar; Zd, Zn, and Pg
	// remain independently variable across the complete family.
	for _, base := range []uint32{
		0x65442000, 0x65452000, 0x65462000, 0x65472000,
		0x65842000, 0x65852000, 0x65862000, 0x65872000,
		0x65c42000, 0x65c52000, 0x65c62000, 0x65c72000,
	} {
		word := base | 17 | 23<<5 | 5<<10
		reduction, ok := decodeARM64RawSVEFloatMinMaxReduction(word)
		if !ok {
			t.Fatalf("failed to decode %#08x", word)
		}
		if reduction.form.destination != 17 || reduction.form.first != 23 || reduction.form.predicate != 5 {
			t.Fatalf("wrong register fields for %#08x: %+v", word, reduction.form)
		}
		if reduction.destination != "V17" {
			t.Fatalf("wrong scalar destination for %#08x: %s", word, reduction.destination)
		}
	}

	for _, word := range []uint32{
		0x65042000, // Reserved byte-width variant.
		0x65832000, // Adjacent opcode before the family.
		0x65882000, // Adjacent opcode after the family.
		0x65870000, // Reduction encoding requires bit 13.
		0x6587a000, // Adjacent encoding with bit 15 set.
	} {
		if _, ok := decodeARM64RawSVEFloatMinMaxReduction(word); ok {
			t.Fatalf("accepted unrelated encoding %#08x", word)
		}
	}
}
