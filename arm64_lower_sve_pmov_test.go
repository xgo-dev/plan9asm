package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEPMOVCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svepmovforms(SB),$0-0\n")
	source.WriteString("\tZPMOV P0.B, Z0\n")
	source.WriteString("\tZPMOV Z1, P1.B\n")
	for _, spec := range []struct {
		letter    string
		maxLane   int
		predicate int
		vector    int
	}{
		{letter: "H", maxLane: 1, predicate: 2, vector: 2},
		{letter: "S", maxLane: 3, predicate: 3, vector: 3},
		{letter: "D", maxLane: 7, predicate: 4, vector: 4},
	} {
		for lane := 0; lane <= spec.maxLane; lane++ {
			fmt.Fprintf(&source, "\tZPMOV P%d.%s, Z%d[%d]\n", spec.predicate, spec.letter, spec.vector, lane)
			fmt.Fprintf(&source, "\tZPMOV Z%d[%d], P%d.%s\n", spec.vector+1, lane, spec.predicate+1, spec.letter)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestParseARM64SVEPMOVIndexedRegisters(t *testing.T) {
	file, err := Parse(ArchARM64, "TEXT parsepmov(SB),$0-0\n\tZPMOV P3.S, Z25[2]\n\tZPMOV Z27[1], P13.S\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, operand := range []Operand{file.Funcs[0].Instrs[1].Args[1], file.Funcs[0].Instrs[2].Args[0]} {
		if operand.Kind != OpReg {
			t.Fatalf("indexed Z register parsed as kind %v: %+v", operand.Kind, operand)
		}
	}
}

func TestTranslateARM64SVEPMOVCompleteGo127Family(t *testing.T) {
	source := arm64SVEPMOVCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepmovforms": {Name: "svepmovforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p1"`,
				"@llvm.aarch64.sve.pmov.to.pred.lane.zero.nxv16i8",
				"@llvm.aarch64.sve.pmov.to.pred.lane.nxv8i16",
				"@llvm.aarch64.sve.pmov.to.vector.lane.zeroing.nxv4i32",
				"@llvm.aarch64.sve.pmov.to.vector.lane.merging.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE PMOV lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-pmov.ll", "arm64-sve-pmov.o", ll)
		})
	}
}

func TestTranslateARM64SVEPMOVRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZPMOV P0.B, Z0[0]",
		"ZPMOV P0.H, Z0",
		"ZPMOV P0.H, Z0[2]",
		"ZPMOV P0.S, Z0[4]",
		"ZPMOV P0.D, Z0[8]",
		"ZPMOV Z0[2], P0.H",
		"ZPMOV Z0[4], P0.S",
		"ZPMOV Z0[8], P0.D",
		"ZPMOV P16.B, Z0",
		"ZPMOV Z32, P0.B",
		"ZPMOV.Z P0.B, Z0",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepmov(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepmov": {Name: "badsvepmov", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE PMOV forms", instruction)
			}
		})
	}
}
