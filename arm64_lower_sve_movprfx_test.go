package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEMOVPRFXCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svemovprfxforms(SB),$0-0\n\tZMOVPRFX Z0, Z1\n")
	for index, width := range []string{"B", "H", "S", "D"} {
		fmt.Fprintf(&source, "\tZMOVPRFX Z%d.%s, P%d.M, Z%d.%s\n", index+2, width, index, index+6, width)
		fmt.Fprintf(&source, "\tZMOVPRFX Z%d.%s, P%d.Z, Z%d.%s\n", index+10, width, index+4, index+14, width)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svemovprfxforms": {Name: "svemovprfxforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"select <vscale x 16 x i1>",
				"select <vscale x 8 x i1>",
				"select <vscale x 4 x i1>",
				"select <vscale x 2 x i1>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE MOVPRFX lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-movprfx.ll", "arm64-sve-movprfx.o", ll)
		})
	}
}

func TestTranslateARM64RawSVEMOVPRFXCompleteFamily(t *testing.T) {
	// Go 1.27 has one bare-register and B/H/S/D predicated M/Z rows.
	// gocc emits the bare-register word 0x0420bc61.
	var source strings.Builder
	source.WriteString("TEXT rawSVEMOVPRFX(SB),$0-0\n")
	source.WriteString("\tWORD $0x0420bc61\n")
	for size := uint32(0); size < 4; size++ {
		for _, merging := range []bool{false, true} {
			word := uint32(0x04102000) | size<<22 | 3<<5 | 2<<10 | 1
			if merging {
				word |= 1 << 16
			}
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
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
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSVEMOVPRFX": {Name: "rawSVEMOVPRFX", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"select <vscale x 16 x i1>",
				"select <vscale x 8 x i1>",
				"select <vscale x 4 x i1>",
				"select <vscale x 2 x i1>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw MOVPRFX IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-movprfx.ll", "arm64-raw-sve-movprfx.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEMOVPRFXBoundaries(t *testing.T) {
	for _, test := range []struct {
		word uint32
		args []Reg
	}{
		{0x0420bc61, []Reg{"Z3", "Z1"}},
		{0x04102861, []Reg{"Z3.B", "P2.Z", "Z1.B"}},
		{0x04112861, []Reg{"Z3.B", "P2.M", "Z1.B"}},
	} {
		ins, ok := decodeARM64RawSVEMOVPRFX(test.word)
		if !ok || ins.Op != "ZMOVPRFX" || len(ins.Args) != len(test.args) {
			t.Fatalf("decode %#08x = %+v, %v", test.word, ins, ok)
		}
		for index, want := range test.args {
			if ins.Args[index].Kind != OpReg || ins.Args[index].Reg != want {
				t.Errorf("%#08x operand %d = %+v, want %s", test.word, index, ins.Args[index], want)
			}
		}
	}
	for _, word := range []uint32{
		0x0420bc61 ^ (1 << 10), // adjacent bare-vector opcode
		0x04102861 ^ (1 << 13), // adjacent predicated opcode
	} {
		if ins, ok := decodeARM64RawSVEMOVPRFX(word); ok {
			t.Errorf("decoded reserved MOVPRFX %#08x as %+v", word, ins)
		}
	}
}

func TestTranslateARM64SVEMOVPRFXRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZMOVPRFX Z0.B, P0.M, Z1.H",
		"ZMOVPRFX Z0.H, P0.Z, Z1.S",
		"ZMOVPRFX Z0.D, P8.M, Z1.D",
		"ZMOVPRFX Z0.D, P0, Z1.D",
		"ZMOVPRFX Z0.B, Z1.B",
		"ZMOVPRFX Z0, P0.M, Z1",
		"ZMOVPRFX.Z Z0, Z1",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvemovprfx(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvemovprfx": {Name: "badsvemovprfx", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE MOVPRFX forms", instruction)
			}
		})
	}
}
