package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64OfficialNoopAndEnd(t *testing.T) {
	const source = `TEXT officialNoopEnd(SB),$0-0
	NOOP
	RET
	END
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"officialNoopEnd": {Name: "officialNoopEnd", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "hint #0") {
		t.Fatalf("ARM64 NOOP did not retain its architectural hint encoding:\n%s", ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-official-noop-end.ll", "arm64-official-noop-end.o", ll)
}
