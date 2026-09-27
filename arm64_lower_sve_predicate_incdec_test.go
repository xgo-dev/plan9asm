package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEPredicateIncDecCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svepredicateincdecforms(SB),$0-0\n")
	for widthIndex, width := range []string{"B", "H", "S", "D"} {
		predicate := 1 + widthIndex
		register := 5 + widthIndex
		fmt.Fprintf(&source, "\tPDECP P%d.%s, R%d\n", predicate, width, register)
		fmt.Fprintf(&source, "\tPINCP P%d.%s, R%d\n", predicate, width, register)
		for _, op := range []string{"PSQDECP", "PSQINCP", "PUQDECP", "PUQINCP"} {
			fmt.Fprintf(&source, "\t%s P%d.%s, R%d\n", op, predicate, width, register)
		}
		for _, op := range []string{"PSQDECPW", "PSQINCPW"} {
			fmt.Fprintf(&source, "\t%s R%d, P%d.%s, R%d\n", op, register, predicate, width, register)
		}
		for _, op := range []string{"PUQDECPW", "PUQINCPW"} {
			fmt.Fprintf(&source, "\t%s P%d.%s, R%d\n", op, predicate, width, register)
		}
	}
	source.WriteString("\tPDECP P14.S, ZR\n\tPSQDECP P14.S, ZR\n\tPUQINCPW P14.S, ZR\n\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEPredicateIncDecCompleteGo127Family(t *testing.T) {
	source := arm64SVEPredicateIncDecCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicateincdecforms": {Name: "svepredicateincdecforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.cntp.nxv16i1",
				"@llvm.aarch64.sve.cntp.nxv2i1",
				"@llvm.aarch64.sve.sqdecp.n64.nxv8i1",
				"@llvm.aarch64.sve.sqincp.n32.nxv4i1",
				"@llvm.aarch64.sve.uqdecp.n64.nxv2i1",
				"@llvm.aarch64.sve.uqincp.n32.nxv16i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate inc/dec lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-incdec.ll", "arm64-sve-predicate-incdec.o", ll)
		})
	}
}

func TestTranslateARM64RawSVEPredicateIncDecCompleteFamily(t *testing.T) {
	// Go 1.27 supplies ten predicate inc/dec rows with B/H/S/D widths.
	// lightning emits the PINCP B form at 0x252c8862.
	forms := []uint32{
		0x252d8800, 0x252c8800,
		0x252a8c00, 0x252a8800,
		0x25288c00, 0x25288800,
		0x252b8c00, 0x252b8800,
		0x25298c00, 0x25298800,
	}
	var source strings.Builder
	source.WriteString("TEXT rawSVEPredicateIncDec(SB),$0-0\n")
	for _, base := range forms {
		for size := uint32(0); size < 4; size++ {
			word := base | size<<22 | 3<<5 | 2
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
					"rawSVEPredicateIncDec": {Name: "rawSVEPredicateIncDec", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.cntp.nxv16i1",
				"@llvm.aarch64.sve.cntp.nxv2i1",
				"@llvm.aarch64.sve.sqdecp.n64.nxv8i1",
				"@llvm.aarch64.sve.sqincp.n32.nxv4i1",
				"@llvm.aarch64.sve.uqdecp.n64.nxv2i1",
				"@llvm.aarch64.sve.uqincp.n32.nxv16i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw predicate inc/dec IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-predicate-incdec.ll", "arm64-raw-sve-predicate-incdec.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEPredicateIncDecBoundaries(t *testing.T) {
	for _, test := range []struct {
		word uint32
		op   Op
		args []Reg
	}{
		{0x252c8862, "PINCP", []Reg{"P3.B", "R2"}},
		{0x25ed89ff, "PDECP", []Reg{"P15.D", "ZR"}},
		{0x25e88862, "PSQINCPW", []Reg{"R2", "P3.D", "R2"}},
	} {
		ins, ok := decodeARM64RawSVEPredicateIncDec(test.word)
		if !ok || ins.Op != test.op || len(ins.Args) != len(test.args) {
			t.Fatalf("decode %#08x = %+v, %v", test.word, ins, ok)
		}
		for index, want := range test.args {
			if ins.Args[index].Kind != OpReg || ins.Args[index].Reg != want {
				t.Errorf("%#08x operand %d = %+v, want %s", test.word, index, ins.Args[index], want)
			}
		}
	}
	for _, word := range []uint32{
		0x252c8862 | (1 << 9),
		0x252c8862 | (1 << 10),
		0x252c8862 ^ (1 << 15),
	} {
		if ins, ok := decodeARM64RawSVEPredicateIncDec(word); ok {
			t.Errorf("decoded reserved encoding %#08x as %+v", word, ins)
		}
	}
}

func TestTranslateARM64SVEPredicateIncDecRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PDECP P1.Q, R2",
		"PINCP P1.B, RSP",
		"PSQDECPW R1, P2.B, R3",
		"PUQINCPW R1, P2.B, R1",
		"PSQINCP P1.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicateincdec(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicateincdec": {Name: "badsvepredicateincdec", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE predicate inc/dec forms", instruction)
			}
		})
	}
}
