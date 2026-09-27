package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMRawSingleRegisterConversionCompleteFamily(t *testing.T) {
	// These words cover both directions, signed and unsigned integer modes,
	// even/odd single-register halves, and the S0/S31 register boundaries.
	const source = `TEXT rawConversions(SB), $0-0
	WORD $0xeef80aee // vcvt.f32.s32 s1, s29
	WORD $0xeeb81a4f // vcvt.f32.u32 s2, s30
	WORD $0xeefd1aef // vcvt.s32.f32 s3, s31
	WORD $0xeebc2ac0 // vcvt.u32.f32 s4, s0
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawConversions": {Name: "rawConversions", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sitofp i32", "uitofp i32", "fptosi float", "fptoui float", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw VCVT family IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-vcvt.ll", "arm-raw-vcvt.o", ir)
}
