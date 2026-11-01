package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMLegacySplitFloat64FrameWords(t *testing.T) {
	file, err := Parse(ArchARM, `
TEXT splitdouble(SB),NOSPLIT,$0
	MOVW x_lo+0(FP), R0
	MOVW x_hi+4(FP), R1
	AND $((1<<31)-1), R1
	MOVW R0, ret_lo+8(FP)
	MOVW R1, ret_hi+12(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		Sigs: map[string]FuncSig{
			"splitdouble": {
				Name: "splitdouble",
				Args: []LLVMType{LLVMType("double")},
				Ret:  LLVMType("double"),
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: LLVMType("double"), Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bitcast double", "lshr i64", "bitcast i64", "store double"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("legacy split float64 IR missing %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-split-float64.ll", "arm-split-float64.o", ll)
}
