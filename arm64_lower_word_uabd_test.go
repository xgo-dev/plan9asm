package plan9asm

import "testing"

const arm64RawVUABDForms = `TEXT vuabdwords(SB),$0-0
	WORD $0x2E207400 // UABD V0.8B, V0.8B, V0.8B
	WORD $0x6E30749D // UABD V29.16B, V4.16B, V16.16B
	WORD $0x2E607400 // UABD V0.4H, V0.4H, V0.4H
	WORD $0x2EA07400 // UABD V0.2S, V0.2S, V0.2S
	WORD $0x6EA07400 // UABD V0.4S, V0.4S, V0.4S
	RET
`

func TestTranslateARM64RawVUABDForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawVUABDForms, true)
	file, err := Parse(ArchARM64, arm64RawVUABDForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"vuabdwords": {Name: "vuabdwords", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vuabd.ll", "arm64-vuabd.o", ir)
		})
	}
}
