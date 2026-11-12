package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEPredicateBreakCompleteForms() string {
	return `TEXT svepredicatebreakforms(SB),$0-0
	PBRKA P15.B, P14.M, P13.B
	PBRKA P12.B, P11.Z, P10.B
	PBRKAS P9.B, P8.Z, P7.B
	PBRKB P6.B, P5.M, P4.B
	PBRKB P3.B, P2.Z, P1.B
	PBRKBS P0.B, P15.Z, P14.B
	PBRKN P13.B, P12.B, P11.Z, P13.B
	PBRKNS P10.B, P9.B, P8.Z, P10.B
	PBRKPA P7.B, P6.B, P5.Z, P4.B
	PBRKPAS P3.B, P2.B, P1.Z, P0.B
	PBRKPB P15.B, P14.B, P13.Z, P12.B
	PBRKPBS P11.B, P10.B, P9.Z, P8.B
	RET
`
}

func TestTranslateARM64SVEPredicateBreakCompleteGo127Family(t *testing.T) {
	source := arm64SVEPredicateBreakCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicatebreakforms": {Name: "svepredicatebreakforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.brka.nxv16i1",
				"@llvm.aarch64.sve.brka.z.nxv16i1",
				"@llvm.aarch64.sve.brkb.nxv16i1",
				"@llvm.aarch64.sve.brkb.z.nxv16i1",
				"@llvm.aarch64.sve.brkn.z.nxv16i1",
				"@llvm.aarch64.sve.brkpa.z.nxv16i1",
				"@llvm.aarch64.sve.brkpb.z.nxv16i1",
				"@llvm.aarch64.sve.ptest.any.nxv16i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate break lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-break.ll", "arm64-sve-predicate-break.o", ll)
		})
	}
}

func TestTranslateARM64RawSVEPredicateBreakCompleteFamily(t *testing.T) {
	// The first word occurs in lightning. The remaining words exercise every
	// row in Go 1.27's predicate-break instruction family, including M/Z.
	words := []uint32{
		0x25104000 | 2<<5 | 1<<10 | 3,
		0x25104000 | 2<<5 | 1<<10 | 3 | 1<<4,
		0x25504000 | 2<<5 | 1<<10 | 3,
		0x25904443,
		0x25904000 | 2<<5 | 1<<10 | 3 | 1<<4,
		0x25d04000 | 2<<5 | 1<<10 | 3,
		0x25184000 | 2<<5 | 1<<10 | 3,
		0x25584000 | 2<<5 | 1<<10 | 3,
		0x2500c000 | 4<<16 | 2<<5 | 1<<10 | 3,
		0x2540c000 | 4<<16 | 2<<5 | 1<<10 | 3,
		0x2500c010 | 4<<16 | 2<<5 | 1<<10 | 3,
		0x2540c010 | 4<<16 | 2<<5 | 1<<10 | 3,
	}
	var source strings.Builder
	source.WriteString("TEXT rawSVEPredicateBreak(SB),$0-0\n")
	for _, word := range words {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
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
					"rawSVEPredicateBreak": {Name: "rawSVEPredicateBreak", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.brka.nxv16i1",
				"@llvm.aarch64.sve.brka.z.nxv16i1",
				"@llvm.aarch64.sve.brkb.nxv16i1",
				"@llvm.aarch64.sve.brkb.z.nxv16i1",
				"@llvm.aarch64.sve.brkn.z.nxv16i1",
				"@llvm.aarch64.sve.brkpa.z.nxv16i1",
				"@llvm.aarch64.sve.brkpb.z.nxv16i1",
				"@llvm.aarch64.sve.ptest.any.nxv16i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw predicate-break IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-predicate-break.ll", "arm64-raw-sve-predicate-break.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEPredicateBreakBoundaries(t *testing.T) {
	for _, test := range []struct {
		word uint32
		op   Op
		args []Reg
	}{
		{
			word: 0x25904443, // lightning: BRKB P3.B, P1/Z, P2.B
			op:   "PBRKB",
			args: []Reg{"P2.B", "P1.Z", "P3.B"},
		},
		{
			word: 0x25107dff, // BRKA with high predicates and merging
			op:   "PBRKA",
			args: []Reg{"P15.B", "P15.M", "P15.B"},
		},
		{
			word: 0x250ffdef, // BRKPA with high first and second predicates
			op:   "PBRKPA",
			args: []Reg{"P15.B", "P15.B", "P15.Z", "P15.B"},
		},
	} {
		ins, ok := decodeARM64RawSVEPredicateBreak(test.word)
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
		0x25904443 | (1 << 9),  // reserved register bit
		0x25904443 ^ (1 << 20), // adjacent encoding class
		0x25d04443 | (1 << 4),  // flag-setting form has no merge mode
	} {
		if ins, ok := decodeARM64RawSVEPredicateBreak(word); ok {
			t.Errorf("decoded reserved encoding %#08x as %+v", word, ins)
		}
	}
}

func TestTranslateARM64SVEPredicateBreakRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PBRKA P1.H, P2.M, P3.B",
		"PBRKAS P1.B, P2.M, P3.B",
		"PBRKN P1.B, P2.B, P3.Z, P4.B",
		"PBRKPA P1.B, P2.B, P3.M, P4.B",
		"PBRKPB P1.B, P2.B, P16.Z, P4.B",
		"PBRKPBS P1.B, P2.B, P3.Z",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicatebreak(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicatebreak": {Name: "badsvepredicatebreak", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE predicate break forms", instruction)
			}
		})
	}
}
