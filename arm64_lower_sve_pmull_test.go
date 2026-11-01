package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEPMULLBottomTopCompleteGo127Family(t *testing.T) {
	const source = `
TEXT svepmulllow(SB),$0-0
	ZPMULLB Z1.B, Z2.B, Z3.H
	ZPMULLB Z4.S, Z5.S, Z6.D
	ZPMULLT Z7.B, Z8.B, Z9.H
	ZPMULLT Z10.S, Z11.S, Z12.D
	RET
TEXT svepmullq(SB),$0-0
	ZPMULLB Z13.D, Z14.D, Z15.Q
	ZPMULLT Z16.D, Z17.D, Z18.Q
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"svepmulllow": {Name: "svepmulllow", Ret: Void},
		"svepmullq":   {Name: "svepmullq", Ret: Void},
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				`"target-features"="+sve,+sve2,+sve2-aes"`,
				"@llvm.aarch64.sve.pmullb.pair.nxv16i8",
				"@llvm.aarch64.sve.pmullb.pair.nxv4i32",
				"@llvm.aarch64.sve.pmullb.pair.nxv2i64",
				"@llvm.aarch64.sve.pmullt.pair.nxv16i8",
				"@llvm.aarch64.sve.pmullt.pair.nxv4i32",
				"@llvm.aarch64.sve.pmullt.pair.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE PMULLB/T lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-pmull.ll", "arm64-sve-pmull.o", ll)
		})
	}
}

func TestTranslateARM64SVEPMULLBottomTopRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZPMULLB Z1.H, Z2.H, Z3.S",
		"ZPMULLB Z1.B, Z2.B, Z3.D",
		"ZPMULLB Z1.D, Z2.D, Z3.D",
		"ZPMULLT Z1.Q, Z2.Q, Z3.Q",
		"ZPMULLT Z1.S, Z2.S",
		"ZPMULLB.Z Z1.B, Z2.B, Z3.H",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepmull(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepmull": {Name: "badsvepmull", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE PMULLB/T forms", instruction)
			}
		})
	}
}
