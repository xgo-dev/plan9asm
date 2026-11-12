package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64RawSVEWhileLOForms(t *testing.T) {
	const source = `TEXT whilelowords(SB),$0-0
	WORD $0x25211d00
	WORD $0x25611d00
	WORD $0x25a11d00
	WORD $0x25e11d00
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"whilelowords": {Name: "whilelowords", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, line := range strings.Split(ll, "\n") {
		if strings.Contains(line, " = call ") && strings.Contains(line, "@llvm.aarch64.sve.whilelo.") {
			got++
		}
	}
	if want := 4; got != want {
		t.Fatalf("raw WHILELO lowering emitted %d intrinsics, want %d:\n%s", got, want, ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-whilelo.ll", "arm64-whilelo.o", ll)
}
