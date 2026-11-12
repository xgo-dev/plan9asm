package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEMatrixMultiplyCompleteGo127Family(t *testing.T) {
	const source = `
TEXT svematrixint(SB),$0-0
	ZSMMLA Z1.B, Z2.B, Z3.S
	ZUMMLA Z4.B, Z5.B, Z6.S
	ZUSMMLA Z7.B, Z8.B, Z9.S
	RET
TEXT svematrixbfloat(SB),$0-0
	ZBFMMLA Z10.H, Z11.H, Z12.H
	ZBFMMLA Z13.H, Z14.H, Z15.S
	RET
TEXT svematrixfloat(SB),$0-0
	ZFMMLA Z16.B, Z17.B, Z18.H
	ZFMMLA Z19.B, Z20.B, Z21.S
	ZFMMLA Z22.H, Z23.H, Z24.H
	ZFMMLA Z25.H, Z26.H, Z27.S
	ZFMMLA Z28.S, Z29.S, Z30.S
	ZFMMLA Z31.D, Z0.D, Z1.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"svematrixint":    {Name: "svematrixint", Ret: Void},
		"svematrixbfloat": {Name: "svematrixbfloat", Ret: Void},
		"svematrixfloat":  {Name: "svematrixfloat", Ret: Void},
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+i8mm,+sve"`,
				`"target-features"="+bf16,+sve,+sve-b16mm"`,
				`"target-features"="+f16mm,+f32mm,+f64mm,+f8f16mm,+f8f32mm,+fp8,+sve,+sve-f16f32mm,+sve2,+sve2p2"`,
				"@llvm.aarch64.sve.smmla.",
				"@llvm.aarch64.sve.bfmmla",
				`asm sideeffect "bfmmla $0.h, $2.h, $3.h"`,
				`asm sideeffect "fmmla $0.h, $2.b, $3.b"`,
				`asm sideeffect "fmmla $0.s, $2.b, $3.b"`,
				`asm sideeffect "fmmla $0.h, $2.h, $3.h"`,
				"@llvm.aarch64.sve.fmmla.nxv4f32.nxv8f16",
				"@llvm.aarch64.sve.fmmla.nxv2f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE matrix-multiply lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-matrix-multiply.ll", "arm64-sve-matrix-multiply.o", ll)
		})
	}
}

func TestTranslateARM64SVEMatrixMultiplyRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSMMLA Z1.H, Z2.H, Z3.S",
		"ZUMMLA Z1.B, Z2.B, Z3.H",
		"ZUSMMLA Z1.B, Z2.S, Z3.S",
		"ZBFMMLA Z1.S, Z2.S, Z3.S",
		"ZBFMMLA Z1.H, Z2.H, Z3.D",
		"ZFMMLA Z1.B, Z2.B, Z3.D",
		"ZFMMLA Z1.S, Z2.S, Z3.D",
		"ZFMMLA.Z Z1.S, Z2.S, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvematrixmultiply(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvematrixmultiply": {Name: "badsvematrixmultiply", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE matrix-multiply forms", instruction)
			}
		})
	}
}
