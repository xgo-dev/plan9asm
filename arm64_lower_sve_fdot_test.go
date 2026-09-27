package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEFDOTCompleteGo127Family(t *testing.T) {
	const source = `TEXT svefdot(SB),$0-0
	ZFDOT Z8.B, Z9.B, Z10.H
	ZFDOT Z11.B, Z12.B, Z13.S
	ZFDOT Z14.H, Z15.H, Z16.S
	ZFDOT Z0.B[0], Z17.B, Z18.H
	ZFDOT Z7.B[7], Z19.B, Z20.H
	ZFDOT Z0.B[0], Z21.B, Z22.S
	ZFDOT Z7.B[3], Z23.B, Z24.S
	ZFDOT Z0.H[0], Z25.H, Z26.S
	ZFDOT Z7.H[3], Z27.H, Z28.S
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefdot": {Name: "svefdot", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+f16f32dot,+fp8,+ssve-fp8dot2,+ssve-fp8dot4,+sve,+sve2,+sve2p1,+sve2p2"`,
				"@llvm.aarch64.sve.fp8.fdot.nxv8f16",
				"@llvm.aarch64.sve.fp8.fdot.nxv4f32",
				"@llvm.aarch64.sve.fp8.fdot.lane.nxv8f16",
				"@llvm.aarch64.sve.fp8.fdot.lane.nxv4f32",
				"@llvm.aarch64.sve.fdot.x2.nxv4f32",
				"@llvm.aarch64.sve.fdot.lane.x2.nxv4f32",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s ZFDOT lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-fdot.ll", "arm64-sve-fdot.o", ll)
		})
	}
}

func TestTranslateARM64SVEFDOTRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFDOT Z1.S, Z2.S, Z3.D",
		"ZFDOT Z1.B, Z2.H, Z3.S",
		"ZFDOT Z8.B[0], Z2.B, Z3.H",
		"ZFDOT Z7.B[8], Z2.B, Z3.H",
		"ZFDOT Z7.B[4], Z2.B, Z3.S",
		"ZFDOT Z7.H[4], Z2.H, Z3.S",
		"ZFDOT Z7.H[3], Z2.H, Z3.H",
		"ZFDOT.Z Z1.B, Z2.B, Z3.H",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefdot(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefdot": {Name: "badsvefdot", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZFDOT forms", instruction)
			}
		})
	}
}
