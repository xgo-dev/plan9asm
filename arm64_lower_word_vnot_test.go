package plan9asm

import "testing"

const arm64RawVMVNForms = `TEXT vmvnraw(SB),$0-0
	WORD $0x2E2058E5 // VMVN V7.B8, V5.B8
	WORD $0x6E205A7E // VMVN V19.B16, V30.B16
	RET
`

func TestTranslateARM64RawVMVNGoAliasForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawVMVNForms, true)
	file, err := Parse(ArchARM64, arm64RawVMVNForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"vmvnraw": {Name: "vmvnraw", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vnot.ll", "arm64-vnot.o", ir)
		})
	}
}
