package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEExtraShiftCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT sveextrashiftbase(SB),$0-0\n")
	for _, suffix := range []string{"B", "H", "S", "D"} {
		bits := map[string]int{"B": 8, "H": 16, "S": 32, "D": 64}[suffix]
		fmt.Fprintf(&source, "\tZASRD $%d, Z1.%s, P0.M, Z1.%s\n", bits-1, suffix, suffix)
		for _, op := range []string{"ZASRR", "ZLSLR", "ZLSRR"} {
			fmt.Fprintf(&source, "\t%s Z2.%s, Z3.%s, P1.M, Z3.%s\n", op, suffix, suffix, suffix)
		}
	}
	source.WriteString("\tRET\nTEXT sveextrashiftsve2(SB),$0-0\n")
	for _, suffix := range []string{"B", "H", "S", "D"} {
		bits := map[string]int{"B": 8, "H": 16, "S": 32, "D": 64}[suffix]
		for _, op := range []string{"ZSLI", "ZSQSHLU"} {
			if op == "ZSQSHLU" {
				fmt.Fprintf(&source, "\t%s $%d, Z4.%s, P2.M, Z4.%s\n", op, bits-1, suffix, suffix)
			} else {
				fmt.Fprintf(&source, "\t%s $%d, Z4.%s, Z5.%s\n", op, bits-1, suffix, suffix)
			}
		}
		for _, op := range []string{"ZSRI", "ZSRSRA", "ZSSRA", "ZURSRA", "ZUSRA"} {
			fmt.Fprintf(&source, "\t%s $%d, Z6.%s, Z7.%s\n", op, bits-1, suffix, suffix)
		}
		for _, op := range []string{"ZSRSHR", "ZURSHR"} {
			fmt.Fprintf(&source, "\t%s $%d, Z8.%s, P3.M, Z8.%s\n", op, bits-1, suffix, suffix)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"sveextrashiftbase": {Name: "sveextrashiftbase", Ret: Void},
		"sveextrashiftsve2": {Name: "sveextrashiftsve2", Ret: Void},
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve"`, `"target-features"="+sve,+sve2"`, "@llvm.aarch64.sve.asrd.", "@llvm.aarch64.sve.sli.", "@llvm.aarch64.sve.ursra."} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE extra shift lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-extra-shift.ll", "arm64-sve-extra-shift.o", ll)
		})
	}
}

func TestTranslateARM64SVEExtraShiftRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZASRD $0, Z1.B, P0.M, Z1.B",
		"ZASRD $8, Z1.B, P0.M, Z1.B",
		"ZASRD $9, Z1.B, P0.M, Z1.B",
		"ZASRR Z1.B, Z2.B, P0.M, Z3.B",
		"ZSLI $8, Z1.B, Z2.B",
		"ZSRI $0, Z1.B, Z2.B",
		"ZSRI $8, Z1.B, Z2.B",
		"ZURSHR $64, Z1.D, P0.M, Z1.D",
		"ZSQSHLU $8, Z1.B, P0.M, Z1.B",
		"ZSRSHR $1, Z1.H, P0.M, Z2.H",
		"ZURSRA $1, Z1.H, Z2.S",
		"ZUSRA.Z $1, Z1.B, Z2.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveextrashift(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveextrashift": {Name: "badsveextrashift", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE shift forms", instruction)
			}
		})
	}
}
