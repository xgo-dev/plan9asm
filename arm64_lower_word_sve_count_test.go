package plan9asm

import "testing"

const arm64RawSVECntForms = `TEXT svecntwords(SB),$0-0
	WORD $0x0420e3ea // CNTB X10
	WORD $0x0460e3ea // CNTH X10
	WORD $0x04a0e3ea // CNTW X10
	WORD $0x04e0e3ea // CNTD X10
	RET
`

func TestTranslateARM64RawSVECntForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawSVECntForms, true)
	file, err := Parse(ArchARM64, arm64RawSVECntForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"svecntwords": {Name: "svecntwords", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-count.ll", "arm64-sve-count.o", ir)
		})
	}
}
