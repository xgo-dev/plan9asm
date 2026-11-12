package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEFloatAddSubForms(op string) string {
	var source strings.Builder
	function := "sve" + strings.ToLower(op) + "forms"
	source.WriteString("TEXT " + function + "(SB),$0-0\n")
	for index, width := range []string{"H", "S", "D"} {
		predicate := string(rune('0' + index))
		if op != "ZFSUBR" {
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", Z3." + width + "\n")
		}
		source.WriteString("\t" + op + " Z4." + width + ", Z5." + width + ", P" + predicate + ".M, Z5." + width + "\n")
		for _, immediate := range []string{"0.5", "1.0"} {
			source.WriteString("\t" + op + " $(" + immediate + "), Z6." + width + ", P" + predicate + ".M, Z6." + width + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEFloatAddSubCompleteGo127Family(t *testing.T) {
	for _, op := range []string{"ZFADD", "ZFSUB", "ZFSUBR"} {
		t.Run(op, func(t *testing.T) {
			source := arm64SVEFloatAddSubForms(op)
			requireARM64SVEGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "sve" + strings.ToLower(op) + "forms"
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					operation := "fadd"
					if op != "ZFADD" {
						operation = "fsub"
					}
					for _, want := range []string{`"target-features"="+sve"`, " " + operation + " <vscale x ", " select <vscale x ", "bitcast <vscale x"} {
						if !strings.Contains(ll, want) {
							t.Fatalf("%s SVE float add/sub lowering for %s omitted %q:\n%s", triple, op, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-float-add-sub.ll", "arm64-sve-float-add-sub.o", ll)
				})
			}
		})
	}
}

func TestTranslateARM64SVEFloatAddSubRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFADD Z1.B, Z2.B, Z3.B",
		"ZFSUBR Z1.S, Z2.S, Z3.S",
		"ZFSUB Z1.S, Z2.D, Z3.S",
		"ZFADD Z1.S, Z2.S, P0.M, Z3.S",
		"ZFSUB $(2.0), Z1.D, P0.M, Z1.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloataddsub(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloataddsub": {Name: "badsvefloataddsub", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE floating add/sub forms", instruction)
			}
		})
	}
}
