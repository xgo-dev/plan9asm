package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMRawLDREXDDecoderFormat(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·rawLDREXD(SB),NOSPLIT,$0-0
	WORD $0xe1bd0f9f // LDREXD [SP], R1, R0
	WORD $0xe1a90f98 // STREXD [R9], R9, R8, R0
	WORD $0xf57ff01f // CLREX
	RET
`, map[string]FuncSig{"example.rawLDREXD": {Name: "example.rawLDREXD", Ret: Void}})
	for _, want := range []string{"load atomic i64", "cmpxchg ptr", "store i32", "exclusive_valid", `asm sideeffect "clrex"`} {
		if !strings.Contains(ll, want) {
			t.Fatalf("raw LDREXD lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-ldrexd.ll", "arm-raw-ldrexd.o", ll)
}
