package plan9asm

import "testing"

const arm64RawVectorFMOVImmediate = `TEXT vfmovraw(SB),$0-0
	WORD $0x4f00f785 // FMOV V5.S4, #7.00
	RET
`

func TestTranslateARM64RawVectorFMOVImmediate(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawVectorFMOVImmediate, true)
	file, err := Parse(ArchARM64, arm64RawVectorFMOVImmediate)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"vfmovraw": {Name: "vfmovraw", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vfmov.ll", "arm64-vfmov.o", ir)
		})
	}
}
