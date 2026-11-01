package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var arm64SVEPredicateWhileConditions = []string{"GE", "GT", "HI", "HS", "LE", "LO", "LS", "LT"}

func arm64SVEPredicateWhileCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svepredicatewhileforms(SB),$0-0\n")
	for conditionIndex, condition := range arm64SVEPredicateWhileConditions {
		for widthIndex, width := range []string{"B", "H", "S", "D"} {
			destination := (conditionIndex + widthIndex) % 15
			pairDestination := 2 * ((conditionIndex + widthIndex) % 8)
			fmt.Fprintf(&source, "\tPWHILE%s R1, R2, P%d.%s\n", condition, destination, width)
			fmt.Fprintf(&source, "\tPWHILE%s R3, R4, [P%d.%s, P%d.%s]\n", condition, pairDestination, width, pairDestination+1, width)
			fmt.Fprintf(&source, "\tPWHILE%s VLx2, R5, R6, PN%d.%s\n", condition, 8+(conditionIndex+widthIndex)%8, width)
			fmt.Fprintf(&source, "\tPWHILE%s VLx4, R7, R8, PN%d.%s\n", condition, 8+(conditionIndex+widthIndex+1)%8, width)
			fmt.Fprintf(&source, "\tPWHILE%sW R9, R10, P%d.%s\n", condition, destination, width)
		}
	}
	for _, width := range []string{"B", "H", "S", "D"} {
		fmt.Fprintf(&source, "\tPWHILERW R11, R12, P13.%s\n", width)
		fmt.Fprintf(&source, "\tPWHILEWR R13, R14, P15.%s\n", width)
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEPredicateWhileCompleteGo127Family(t *testing.T) {
	source := arm64SVEPredicateWhileCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicatewhileforms": {Name: "svepredicatewhileforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2,+sve2p1"`,
				"@llvm.aarch64.sve.whilege.nxv16i1.i64",
				"@llvm.aarch64.sve.whilelt.nxv2i1.i32",
				"@llvm.aarch64.sve.whilehi.x2.nxv4i1",
				"@llvm.aarch64.sve.whilels.c64",
				"@llvm.aarch64.sve.whilerw.b.nxv16i1.p0",
				"@llvm.aarch64.sve.whilewr.d.nxv2i1.p0",
				"@llvm.aarch64.sve.ptest.any.nxv16i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate while lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-while.ll", "arm64-sve-predicate-while.o", ll)
		})
	}
}

func TestTranslateARM64SVEPredicateWhileRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PWHILELT R1, R2, P3.Q",
		"PWHILEGE R1, R2, [P3.B, P4.H]",
		"PWHILEGE R1, R2, [P3.B, P4.B]",
		"PWHILEHI R1, R2, [P3.B, P5.B]",
		"PWHILELO VLx3, R1, R2, PN8.B",
		"PWHILELS VLx2, R1, R2, PN7.B",
		"PWHILELTW R1, R2",
		"PWHILERW R1, R2, P3.Q",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicatewhile(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicatewhile": {Name: "badsvepredicatewhile", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE predicate while forms", instruction)
			}
		})
	}
}
