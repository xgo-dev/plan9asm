package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEUnpackCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveunpackforms(SB),$0-0\n")
	for _, op := range []string{"ZSUNPKHI", "ZSUNPKLO", "ZUUNPKHI", "ZUUNPKLO"} {
		for _, widths := range [][2]string{{"B", "H"}, {"H", "S"}, {"S", "D"}} {
			source.WriteString("\t" + op + " Z1." + widths[0] + ", Z2." + widths[1] + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEUnpackCompleteGo127Family(t *testing.T) {
	source := arm64SVEUnpackCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveunpackforms": {Name: "sveunpackforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.sunpkhi.nxv8i16",
				"@llvm.aarch64.sve.sunpklo.nxv4i32",
				"@llvm.aarch64.sve.uunpkhi.nxv2i64",
				"@llvm.aarch64.sve.uunpklo.nxv8i16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE unpack lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-unpack.ll", "arm64-sve-unpack.o", ll)
		})
	}
}

func TestTranslateARM64SVEUnpackRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSUNPKHI Z1.B, Z2.B",
		"ZSUNPKLO Z1.S, Z2.S",
		"ZUUNPKHI Z1.H, Z2.D",
		"ZUUNPKLO Z1.D, Z2.Q",
		"ZSUNPKHI Z1.B",
		"ZUUNPKLO.Z Z1.S, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveunpack(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveunpack": {Name: "badsveunpack", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE unpack forms", instruction)
			}
		})
	}
}
