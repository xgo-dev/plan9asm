package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64RawSVELD1BRegisterOffsetForms(t *testing.T) {
	const source = `TEXT ld1bwords(SB),$0-0
	WORD $0xa4024400
	WORD $0xa42b4000
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
		Sigs:         map[string]FuncSig{"ld1bwords": {Name: "ld1bwords", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	loads := 0
	for _, line := range strings.Split(ll, "\n") {
		if strings.Contains(line, " = call ") && strings.Contains(line, "@llvm.aarch64.sve.ld1.nxv") {
			loads++
		}
	}
	if loads != 2 {
		t.Fatalf("raw LD1B lowering omitted predicated zeroing loads:\n%s", ll)
	}
	if !strings.Contains(ll, `zext <vscale x 8 x i8>`) {
		t.Fatalf("raw LD1B H arrangement was not zero-extended:\n%s", ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-ld1b.ll", "arm64-ld1b.o", ll)
}
