package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEHalvingAddSubCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svehalvingaddsubforms(SB),$0-0\n")
	for _, op := range []string{"ZSHADD", "ZSRHADD", "ZUHADD", "ZURHADD", "ZSHSUB", "ZSHSUBR", "ZUHSUB", "ZUHSUBR"} {
		for predicate, width := range []string{"B", "H", "S", "D"} {
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", P" + string(rune('0'+predicate)) + ".M, Z2." + width + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEHalvingAddSubCompleteGo127Family(t *testing.T) {
	source := arm64SVEHalvingAddSubCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svehalvingaddsubforms": {Name: "svehalvingaddsubforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.shadd.nxv16i8",
				"@llvm.aarch64.sve.srhadd.nxv8i16",
				"@llvm.aarch64.sve.uhadd.nxv4i32",
				"@llvm.aarch64.sve.urhadd.nxv2i64",
				"@llvm.aarch64.sve.shsub.nxv16i8",
				"@llvm.aarch64.sve.shsubr.nxv8i16",
				"@llvm.aarch64.sve.uhsub.nxv4i32",
				"@llvm.aarch64.sve.uhsubr.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE halving add/sub lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-halving-add-sub.ll", "arm64-sve-halving-add-sub.o", ll)
		})
	}
}

func TestTranslateARM64SVEHalvingAddSubRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSHADD Z1.B, Z2.H, P0.M, Z2.H",
		"ZSRHADD Z1.S, Z2.S, P0, Z2.S",
		"ZUHADD Z1.D, Z2.D, P8.M, Z2.D",
		"ZURHADD Z1.H, Z2.H, P0.M, Z3.H",
		"ZSHSUB Z1.Q, Z2.Q, P0.M, Z2.Q",
		"ZSHSUBR Z1.S, Z2.H, P0.M, Z2.H",
		"ZUHSUB Z1.S, Z2.S, P0.Z, Z2.S",
		"ZUHSUBR.Z Z1.D, Z2.D, P0.M, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvehalvingaddsub(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvehalvingaddsub": {Name: "badsvehalvingaddsub", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE halving add/sub forms", instruction)
			}
		})
	}
}
