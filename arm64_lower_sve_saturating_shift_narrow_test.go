package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var arm64SVESaturatingShiftNarrowOps = []string{
	"ZSQSHRNB", "ZSQSHRNT", "ZSQRSHRNB", "ZSQRSHRNT",
	"ZSQSHRUNB", "ZSQSHRUNT", "ZSQRSHRUNB", "ZSQRSHRUNT",
	"ZUQSHRNB", "ZUQSHRNT", "ZUQRSHRNB", "ZUQRSHRNT",
}

func arm64SVESaturatingShiftNarrowCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svesaturatingshiftnarrowforms(SB),$0-0\n")
	for _, op := range arm64SVESaturatingShiftNarrowOps {
		for _, form := range []struct {
			source, destination string
			max                 int
		}{{"H", "B", 8}, {"S", "H", 16}, {"D", "S", 32}} {
			for _, shift := range []int{1, form.max} {
				fmt.Fprintf(&source, "\t%s $%d, Z1.%s, Z2.%s\n", op, shift, form.source, form.destination)
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVESaturatingShiftNarrowCompleteGo127Family(t *testing.T) {
	source := arm64SVESaturatingShiftNarrowCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svesaturatingshiftnarrowforms": {Name: "svesaturatingshiftnarrowforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, intrinsic := range []string{
				"sqshrnb", "sqshrnt", "sqrshrnb", "sqrshrnt",
				"sqshrunb", "sqshrunt", "sqrshrunb", "sqrshrunt",
				"uqshrnb", "uqshrnt", "uqrshrnb", "uqrshrnt",
			} {
				if want := "@llvm.aarch64.sve." + intrinsic + ".nxv"; !strings.Contains(ll, want) {
					t.Fatalf("%s SVE saturating-shift-narrow lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			if want := `"target-features"="+sve,+sve2"`; !strings.Contains(ll, want) {
				t.Fatalf("%s SVE saturating-shift-narrow lowering omitted %q:\n%s", triple, want, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-saturating-shift-narrow.ll", "arm64-sve-saturating-shift-narrow.o", ll)
		})
	}
}

func TestTranslateARM64SVESaturatingShiftNarrowRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSQSHRNB $0, Z1.H, Z2.B",
		"ZSQRSHRNT $1, Z1.S, Z2.B",
		"ZSQSHRUNB $1, Z1.Q, Z2.D",
		"ZSQRSHRUNT $1, Z1.D",
		"ZUQSHRNB.Z $1, Z1.H, Z2.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_", "$", "imm").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvesaturatingshiftnarrow(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvesaturatingshiftnarrow": {Name: "badsvesaturatingshiftnarrow", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE saturating-shift-narrow forms", instruction)
			}
		})
	}
}

func TestTranslateARM64SVESaturatingShiftNarrowRejectsGoAcceptedUnencodableShifts(t *testing.T) {
	for _, instruction := range []string{
		"ZSQSHRNT $9, Z1.H, Z2.B",
		"ZSQRSHRUNB $17, Z1.S, Z2.H",
		"ZUQRSHRNT $33, Z1.D, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_", "$", "imm").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvesaturatingshiftnarrowrange(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvesaturatingshiftnarrowrange": {Name: "badsvesaturatingshiftnarrowrange", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted Go-assembler form %q that LLVM 22 cannot encode", instruction)
			}
		})
	}
}
