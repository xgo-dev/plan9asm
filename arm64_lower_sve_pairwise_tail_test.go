package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEPairwiseTailCompleteGo127Family(t *testing.T) {
	const source = `
TEXT svepairwise(SB),$0-0
	ZADDP Z1.B, Z2.B, P0.M, Z2.B
	ZADDP Z3.H, Z4.H, P1.M, Z4.H
	ZADDP Z5.S, Z6.S, P2.M, Z6.S
	ZADDP Z7.D, Z8.D, P3.M, Z8.D
	RET
TEXT svetail(SB),$0-0
	ZADDPT Z9.D, Z10.D, P4.M, Z10.D
	ZADDPT Z11.D, Z12.D, Z13.D
	ZSUBPT Z14.D, Z15.D, P5.M, Z15.D
	ZSUBPT Z16.D, Z17.D, Z18.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"svepairwise": {Name: "svepairwise", Ret: Void},
		"svetail":     {Name: "svetail", Ret: Void},
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				`"target-features"="+cpa,+sve"`,
				"@llvm.aarch64.sve.addp.nxv16i8",
				`asm sideeffect "addpt $0.d, $3/m, $0.d, $2.d"`,
				`asm sideeffect "addpt $0.d, $1.d, $2.d"`,
				`asm sideeffect "subpt $0.d, $3/m, $0.d, $2.d"`,
				`asm sideeffect "subpt $0.d, $1.d, $2.d"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE pairwise/tail lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-pairwise-tail.ll", "arm64-sve-pairwise-tail.o", ll)
		})
	}
}

func TestTranslateARM64SVEPairwiseTailRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZADDP Z1.B, Z2.B, P0.M, Z3.B",
		"ZADDP Z1.B, Z2.H, P0.M, Z2.H",
		"ZADDP Z1.B, Z2.B, P0.Z, Z2.B",
		"ZADDPT Z1.S, Z2.S, Z3.S",
		"ZADDPT Z1.D, Z2.D, P0.M, Z3.D",
		"ZSUBPT Z1.D, Z2.D, P0.Z, Z2.D",
		"ZSUBPT.Z Z1.D, Z2.D, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepairwisetail(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepairwisetail": {Name: "badsvepairwisetail", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE pairwise/tail forms", instruction)
			}
		})
	}
}
