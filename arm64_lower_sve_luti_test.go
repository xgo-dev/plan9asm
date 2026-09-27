package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVELUTICompleteGo127Family(t *testing.T) {
	const source = `TEXT sveluti(SB),$0-0
	ZLUTI2 Z31[0], [Z0.B], Z1.B
	ZLUTI2 Z6[3], [Z23.B], Z13.B
	ZLUTI2 Z0[7], [Z31.H], Z30.H
	ZLUTI4 Z31[1], [Z2.B], Z10.B
	ZLUTI4 Z6[3], [Z23.H], Z13.H
	ZLUTI4 Z30[3], [Z31.H, Z0.H], Z13.H
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveluti": {Name: "sveluti", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+lut,+sve,+sve2"`,
				"@llvm.aarch64.sve.luti2.lane.nxv16i8",
				"@llvm.aarch64.sve.luti2.lane.nxv8i16",
				"@llvm.aarch64.sve.luti4.lane.nxv16i8",
				"@llvm.aarch64.sve.luti4.lane.nxv8i16",
				"@llvm.aarch64.sve.luti4.lane.x2.nxv8i16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s ZLUTI lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-luti.ll", "arm64-sve-luti.o", ll)
		})
	}
}

func TestTranslateARM64SVELUTIRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLUTI2 Z1[4], [Z2.B], Z3.B",
		"ZLUTI2 Z1[8], [Z2.H], Z3.H",
		"ZLUTI2 Z1[1], [Z2.S], Z3.S",
		"ZLUTI2 Z1[1], [Z2.B], Z3.H",
		"ZLUTI4 Z1[2], [Z2.B], Z3.B",
		"ZLUTI4 Z1[4], [Z2.H], Z3.H",
		"ZLUTI4 Z1[4], [Z2.H, Z3.H], Z4.H",
		"ZLUTI4 Z1[1], [Z2.B, Z3.B], Z4.B",
		"ZLUTI4 Z1[1], [Z2.H, Z4.H], Z5.H",
		"ZLUTI4 Z1[1], [Z2.H, Z3.H, Z4.H], Z5.H",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveluti(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveluti": {Name: "badsveluti", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZLUTI2/ZLUTI4 forms", instruction)
			}
		})
	}
}
