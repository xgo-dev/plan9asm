package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVERevdCompleteGo127Family(t *testing.T) {
	source := "TEXT sverevdforms(SB),$0-0\n\tZREVD Z1.Q, P0.M, Z2.Q\n\tZREVD Z3.Q, P7.Z, Z4.Q\n\tRET\n"
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sverevdforms": {Name: "sverevdforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve,+sve2p1,+sve2p2"`, "@llvm.aarch64.sve.revd.nxv2i64", "zeroinitializer"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE REVD lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-revd.ll", "arm64-sve-revd.o", ll)
		})
	}
}

func TestTranslateARM64SVERevdRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZREVD Z1.D, P0.M, Z2.D",
		"ZREVD Z1.Q, P0, Z2.Q",
		"ZREVD Z1.Q, P8.M, Z2.Q",
		"ZREVD Z1.Q, P0.M",
		"ZREVD.Z Z1.Q, P0.M, Z2.Q",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsverevd(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsverevd": {Name: "badsverevd", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE REVD forms", instruction)
			}
		})
	}
}
