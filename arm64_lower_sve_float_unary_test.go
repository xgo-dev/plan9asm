package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEFloatUnaryCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svefloatunaryforms(SB),$0-0\n")
	for _, op := range []string{"ZFABS", "ZFNEG", "ZFRECPX", "ZFRINTA", "ZFRINTI", "ZFRINTM", "ZFRINTN", "ZFRINTP", "ZFRINTX", "ZFRINTZ", "ZFSQRT"} {
		for index, width := range []string{"H", "S", "D"} {
			predicate := string(rune('0' + index))
			for _, mode := range []string{"M", "Z"} {
				source.WriteString("\t" + op + " Z1." + width + ", P" + predicate + "." + mode + ", Z2." + width + "\n")
			}
		}
	}
	for _, op := range []string{"ZFRINT32X", "ZFRINT32Z", "ZFRINT64X", "ZFRINT64Z"} {
		for index, width := range []string{"S", "D"} {
			predicate := string(rune('0' + index))
			for _, mode := range []string{"M", "Z"} {
				source.WriteString("\t" + op + " Z3." + width + ", P" + predicate + "." + mode + ", Z4." + width + "\n")
			}
		}
	}
	for _, op := range []string{"ZFRECPE", "ZFRSQRTE"} {
		for _, width := range []string{"H", "S", "D"} {
			source.WriteString("\t" + op + " Z5." + width + ", Z6." + width + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEFloatUnaryCompleteGo127Family(t *testing.T) {
	source := arm64SVEFloatUnaryCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatunaryforms": {Name: "svefloatunaryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+fptoint,+sve"`, "@llvm.aarch64.sve.fabs.nxv", "@llvm.fptosi.sat.nxv2i64.nxv2f64", "@llvm.aarch64.sve.frecpe.x.nxv", "@llvm.aarch64.sve.frsqrte.x.nxv", "@llvm.aarch64.sve.fsqrt.nxv"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating unary lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-unary.ll", "arm64-sve-float-unary.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatUnaryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFABS Z1.B, P0.M, Z2.B",
		"ZFNEG Z1.S, P0, Z2.S",
		"ZFSQRT Z1.S, P8.M, Z2.S",
		"ZFRECPX Z1.S, P0.M, Z2.D",
		"ZFRINT32X Z1.H, P0.M, Z2.H",
		"ZFRINT64Z Z1.S, P0.M, Z2.D",
		"ZFRECPE Z1.S, P0.M, Z2.S",
		"ZFRSQRTE Z1.S, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatunary(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatunary": {Name: "badsvefloatunary", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE floating unary forms", instruction)
			}
		})
	}
}
