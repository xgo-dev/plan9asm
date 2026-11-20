package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVESpliceCompleteGo127Family(t *testing.T) {
	source := "TEXT svespliceforms(SB),$0-0\n" +
		"\tZSPLICE Z2.B, Z1.B, P0, Z1.B\n" +
		"\tZSPLICE Z4.H, Z3.H, P1, Z3.H\n" +
		"\tZSPLICE Z6.S, Z5.S, P2, Z5.S\n" +
		"\tZSPLICE Z8.D, Z7.D, P15, Z7.D\n" +
		"\tZSPLICE [Z9.B, Z10.B], P0, Z11.B\n" +
		"\tZSPLICE [Z12.H, Z13.H], P1, Z14.H\n" +
		"\tZSPLICE [Z15.S, Z16.S], P2, Z17.S\n" +
		"\tZSPLICE [Z30.D, Z31.D], P7, Z18.D\n" +
		"\tRET\n"
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svespliceforms": {Name: "svespliceforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.splice.nxv16i8",
				"@llvm.aarch64.sve.splice.nxv8i16",
				"@llvm.aarch64.sve.splice.nxv4i32",
				"@llvm.aarch64.sve.splice.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE SPLICE lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-splice.ll", "arm64-sve-splice.o", ll)
		})
	}
}

func TestTranslateARM64SVESpliceRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSPLICE Z2.B, Z1.B, P0, Z3.B",
		"ZSPLICE Z2.B, Z1.H, P0, Z1.H",
		"ZSPLICE Z2.B, Z1.B, P16, Z1.B",
		"ZSPLICE Z2.B, Z1.B, P0.M, Z1.B",
		"ZSPLICE [Z1.B], P0, Z3.B",
		"ZSPLICE [Z1.B, Z3.B], P0, Z4.B",
		"ZSPLICE [Z31.B, Z0.B], P0, Z4.B",
		"ZSPLICE [Z1.B, Z2.H], P0, Z4.B",
		"ZSPLICE [Z1.B, Z2.B], P0, Z4.H",
		"ZSPLICE.Z Z2.B, Z1.B, P0, Z1.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvesplice(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvesplice": {Name: "badsvesplice", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE SPLICE forms", instruction)
			}
		})
	}
}
