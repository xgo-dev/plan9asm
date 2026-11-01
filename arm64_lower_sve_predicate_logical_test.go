package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEPredicateLogicalCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svepredicatelogicalforms(SB),$0-0\n")
	for index, op := range []string{"PAND", "PANDS", "PBIC", "PBICS", "PEOR", "PEORS", "PNAND", "PNANDS", "PNOR", "PNORS", "PORN", "PORNS", "PORR", "PORRS"} {
		predicate := index % 16
		source.WriteString(fmt.Sprintf("\t%s P15.B, P14.B, P%d.Z, P13.B\n", op, predicate))
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEPredicateLogicalCompleteGo127Family(t *testing.T) {
	source := arm64SVEPredicateLogicalCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicatelogicalforms": {Name: "svepredicatelogicalforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve"`, "@llvm.aarch64.sve.ptest.any.nxv", "@llvm.aarch64.sve.ptest.first.nxv", "@llvm.aarch64.sve.ptest.last.nxv"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate logical lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-logical.ll", "arm64-sve-predicate-logical.o", ll)
		})
	}
}

func TestTranslateARM64RawSVEPredicateLogicalCompleteFamily(t *testing.T) {
	// All fourteen Go 1.27 rows share the same four predicate register
	// fields. The ORRS word occurs in lightning.
	bases := []uint32{
		0x25004000, 0x25404000,
		0x25004010, 0x25404010,
		0x25004200, 0x25404200,
		0x25804210, 0x25c04210,
		0x25804200, 0x25c04200,
		0x25804010, 0x25c04010,
		0x25804000, 0x25c04000,
	}
	var source strings.Builder
	source.WriteString("TEXT rawSVEPredicateLogical(SB),$0-0\n")
	for _, base := range bases {
		word := base | 3<<16 | 1<<10 | 2<<5 | 2
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
					"rawSVEPredicateLogical": {Name: "rawSVEPredicateLogical", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.ptest.any.nxv",
				"@llvm.aarch64.sve.ptest.first.nxv",
				"@llvm.aarch64.sve.ptest.last.nxv",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw predicate logical IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-predicate-logical.ll", "arm64-raw-sve-predicate-logical.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEPredicateLogicalBoundaries(t *testing.T) {
	observed, ok := decodeARM64RawSVEPredicateLogical(0x25c34442)
	if !ok || observed.Op != "PORRS" || len(observed.Args) != 4 {
		t.Fatalf("decode lightning ORRS = %+v, %v", observed, ok)
	}
	for index, want := range []Reg{"P3.B", "P2.B", "P1.Z", "P2.B"} {
		if observed.Args[index].Kind != OpReg || observed.Args[index].Reg != want {
			t.Errorf("lightning ORRS operand %d = %+v, want %s", index, observed.Args[index], want)
		}
	}
	for _, word := range []uint32{
		0x25c34442 | (1 << 20),
		0x25c34442 ^ (1 << 14),
	} {
		if ins, ok := decodeARM64RawSVEPredicateLogical(word); ok {
			t.Errorf("decoded invalid predicate logical %#08x as %+v", word, ins)
		}
	}
}

func TestTranslateARM64SVEPredicateLogicalRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PAND P1.B, P2.H, P0.Z, P3.B",
		"PBIC P1.B, P2.B, P0.M, P3.B",
		"PEOR P1.B, P2.B, P16.Z, P3.B",
		"PNAND P1.B, P2.B, P0.Z, P3.H",
		"PORR P1, P2.B, P0.Z, P3.B",
		"PORRS P1.B, P2.B, P0.Z",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicatelogical(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicatelogical": {Name: "badsvepredicatelogical", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE predicate logical forms", instruction)
			}
		})
	}
}
