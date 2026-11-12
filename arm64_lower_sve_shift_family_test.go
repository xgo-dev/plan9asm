package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEShiftNamedForms(op string) string {
	var source strings.Builder
	function := "sve" + strings.ToLower(op) + "forms"
	source.WriteString("TEXT " + function + "(SB),$0-0\n")
	for index, width := range []string{"B", "H", "S"} {
		predicate := string(rune('0' + index))
		source.WriteString("\t" + op + " Z1.D, Z2." + width + ", P" + predicate + ".M, Z2." + width + "\n")
		source.WriteString("\t" + op + " Z3.D, Z4." + width + ", Z5." + width + "\n")
	}
	for index, width := range []string{"B", "H", "S", "D"} {
		predicate := string(rune('4' + index))
		maximum := map[string]string{"B": "7", "H": "15", "S": "31", "D": "63"}[width]
		minimum := "1"
		if op == "ZLSL" {
			minimum = "0"
		}
		source.WriteString("\t" + op + " Z6." + width + ", Z7." + width + ", P" + predicate + ".M, Z7." + width + "\n")
		source.WriteString("\t" + op + " $" + maximum + ", Z8." + width + ", P" + predicate + ".M, Z8." + width + "\n")
		source.WriteString("\t" + op + " $" + minimum + ", Z9." + width + ", Z10." + width + "\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEShiftCompleteASRLSLGo127Forms(t *testing.T) {
	for _, op := range []string{"ZASR", "ZLSL"} {
		t.Run(op, func(t *testing.T) {
			source := arm64SVEShiftNamedForms(op)
			requireARM64SVEGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "sve" + strings.ToLower(op) + "forms"
			intrinsic := strings.ToLower(strings.TrimPrefix(op, "Z"))
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"="+sve"`, "@llvm.aarch64.sve." + intrinsic + ".nxv", "@llvm.aarch64.sve." + intrinsic + ".wide.nxv", "@llvm.aarch64.sve.ptrue"} {
						if !strings.Contains(ll, want) {
							t.Fatalf("%s SVE shift lowering for %s omitted %q:\n%s", triple, op, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-shift.ll", "arm64-sve-shift.o", ll)
				})
			}
		})
	}
}

func TestTranslateARM64SVEShiftRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZASR $0, Z1.S, Z2.S",
		"ZLSL $32, Z1.S, Z2.S",
		"ZASR Z1.H, Z2.H, Z3.H",
		"ZLSL Z1.S, Z2.H, P0.M, Z2.H",
		"ZASR $1, Z1.S, P0.M, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveshift(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveshift": {Name: "badsveshift", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE shift forms", instruction)
			}
		})
	}
}
