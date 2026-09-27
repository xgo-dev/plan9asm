package plan9asm

import "testing"

const arm64RawVUSUBLForms = `TEXT vusublwords(SB),$0-0
	WORD $0x2E302094 // USUBL V20.8H, V4.8B, V16.8B
	WORD $0x6E302098 // USUBL2 V24.8H, V4.16B, V16.16B
	WORD $0x2E602000 // USUBL V0.4S, V0.4H, V0.4H
	WORD $0x6E602000 // USUBL2 V0.4S, V0.8H, V0.8H
	WORD $0x2EA02000 // USUBL V0.2D, V0.2S, V0.2S
	WORD $0x6EA02000 // USUBL2 V0.2D, V0.4S, V0.4S
	RET
`

func TestTranslateARM64RawVUSUBLForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawVUSUBLForms, true)
	file, err := Parse(ArchARM64, arm64RawVUSUBLForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"vusublwords": {Name: "vusublwords", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vusubl.ll", "arm64-vusubl.o", ir)
		})
	}
}
