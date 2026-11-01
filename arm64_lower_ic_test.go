package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64RawICIVAU(t *testing.T) {
	const source = `TEXT icivau(SB),$0-0
	WORD $0xd50b7520
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
		Sigs:         map[string]FuncSig{"icivau": {Name: "icivau", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, `asm sideeffect "ic ivau, $0"`) {
		t.Fatalf("raw IC IVAU was not lowered:\n%s", ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-ic.ll", "arm64-ic.o", ll)
}
