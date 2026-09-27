package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEPMULLPairCompleteGo127Family(t *testing.T) {
	const source = `
TEXT svepmullpair(SB),$0-0
	ZPMULL Z1.D, Z2.D, [Z4.Q-Z5.Q]
	ZPMULL Z30.D, Z31.D, [Z30.Q-Z31.Q]
	RET
TEXT svepmlalpair(SB),$0-0
	ZPMLAL Z6.D, Z7.D, [Z8.Q-Z9.Q]
	ZPMLAL Z28.D, Z29.D, [Z30.Q-Z31.Q]
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"svepmullpair": {Name: "svepmullpair", Ret: Void},
		"svepmlalpair": {Name: "svepmlalpair", Ret: Void},
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve-aes2"`,
				"@llvm.aarch64.sve.pmull.pair.x2",
				"@llvm.aarch64.sve.pmlal.pair.x2",
				"extractvalue { <vscale x 2 x i64>, <vscale x 2 x i64> }",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE PMULL/PMLAL pair lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-pmull-pair.ll", "arm64-sve-pmull-pair.o", ll)
		})
	}
}

func TestTranslateARM64SVEPMULLPairRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZPMULL Z1.S, Z2.S, [Z4.Q-Z5.Q]",
		"ZPMULL Z1.D, Z2.D, [Z5.Q-Z6.Q]",
		"ZPMULL Z1.D, Z2.D, [Z4.Q-Z7.Q]",
		"ZPMULL Z1.D, Z2.D, [Z4.Q, Z5.Q]",
		"ZPMLAL Z1.D, Z2.D, [Z4.D-Z5.D]",
		"ZPMLAL Z1.D, Z2.D",
		"ZPMLAL.Z Z1.D, Z2.D, [Z4.Q-Z5.Q]",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_", "[", "", "]", "").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepmullpair(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepmullpair": {Name: "badsvepmullpair", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE PMULL/PMLAL pair forms", instruction)
			}
		})
	}
}
