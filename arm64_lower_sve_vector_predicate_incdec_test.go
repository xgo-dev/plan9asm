package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEVectorPredicateIncDecCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svevectorpredicateincdec(SB),$0-0\n")
	for opIndex, op := range []string{"ZDECP", "ZINCP", "ZSQDECP", "ZSQINCP", "ZUQDECP", "ZUQINCP"} {
		for widthIndex, suffix := range []string{"H", "S", "D"} {
			reg := (opIndex*3 + widthIndex) % 32
			fmt.Fprintf(&source, "\t%s P%d.%s, Z%d.%s\n", op, (opIndex+widthIndex)%16, suffix, reg, suffix)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svevectorpredicateincdec": {Name: "svevectorpredicateincdec", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"sub <vscale x 8 x i16>", "add <vscale x 2 x i64>",
				"@llvm.aarch64.sve.sqdecp.nxv8i16",
				"@llvm.aarch64.sve.sqincp.nxv8i16",
				"@llvm.aarch64.sve.uqdecp.nxv4i32",
				"@llvm.aarch64.sve.uqincp.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE vector predicate inc/dec lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-vector-predicate-incdec.ll", "arm64-sve-vector-predicate-incdec.o", ll)
		})
	}
}

func TestTranslateARM64SVEVectorPredicateIncDecRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZDECP P0.B, Z1.B",
		"ZDECP P0.B, Z1.H",
		"ZINCP P0, Z1.B",
		"ZSQDECP P16.B, Z1.B",
		"ZSQINCP P0.Q, Z1.Q",
		"ZUQDECP P0.B, R1",
		"ZUQINCP.Z P0.B, Z1.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvevectorpredicateincdec(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvevectorpredicateincdec": {Name: "badsvevectorpredicateincdec", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector predicate inc/dec forms", instruction)
			}
		})
	}
}
