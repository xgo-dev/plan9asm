package plan9asm

import "testing"

const arm64RawSVELDST1WForms = `TEXT sveldst1wwords(SB),$0-0
	WORD $0xa54b4003 // LD1W {Z3.S}, P0/Z, [X0, X11, LSL #2]
	WORD $0xa540a003 // LD1W {Z3.S}, P0/Z, [X0, #0, MUL VL]
	WORD $0xe54b4003 // ST1W {Z3.S}, P0, [X0, X11, LSL #2]
	WORD $0xe540e003 // ST1W {Z3.S}, P0, [X0, #0, MUL VL]
	RET
`

func TestTranslateARM64RawSVELDST1WForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawSVELDST1WForms, true)
	file, err := Parse(ArchARM64, arm64RawSVELDST1WForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"sveldst1wwords": {Name: "sveldst1wwords", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-ldst1w.ll", "arm64-sve-ldst1w.o", ir)
		})
	}
}
