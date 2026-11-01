package plan9asm

import "testing"

const arm64RawSVEFloatForms = `TEXT svefloatwords(SB),$0-0
	WORD $0x65800020 // FADD Z0.S, Z1.S, Z0.S
	WORD $0x65850484 // FSUB Z4.S, Z4.S, Z5.S
	WORD $0x65810821 // FMUL Z1.S, Z1.S, Z1.S
	WORD $0x65808080 // FADD Z0.S, P0/M, Z0.S, Z4.S
	WORD $0x65a400a3 // FMLA Z3.S, P0/M, Z5.S, Z4.S
	WORD $0x65a48203 // FMAD Z3.S, P0/M, Z16.S, Z4.S
	WORD $0x65802063 // FADDV S3, P0, Z3.S
	WORD $0x65982020 // FADDA S0, P0, S0, Z1.S
	WORD $0x65400020 // FADD Z0.H, Z1.H, Z0.H
	WORD $0x65c50484 // FSUB Z4.D, Z4.D, Z5.D
	WORD $0x65c10821 // FMUL Z1.D, Z1.D, Z1.D
	WORD $0x65c18480 // FSUB Z0.D, P1/M, Z0.D, Z4.D
	WORD $0x65428861 // FMUL Z1.H, P2/M, Z1.H, Z3.H
	WORD $0x65e400a3 // FMLA Z3.D, P0/M, Z5.D, Z4.D
	WORD $0x65c02463 // FADDV D3, P1, Z3.D
	WORD $0x65d82820 // FADDA D0, P2, D0, Z1.D
	RET
`

func TestTranslateARM64RawSVEFloatForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawSVEFloatForms, true)
	file, err := Parse(ArchARM64, arm64RawSVEFloatForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"svefloatwords": {Name: "svefloatwords", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float.ll", "arm64-sve-float.o", ir)
		})
	}
}
