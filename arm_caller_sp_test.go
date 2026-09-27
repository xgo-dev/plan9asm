package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMCallerSPPseudoAddress(t *testing.T) {
	src := `TEXT callerSP(SB),NOSPLIT,$8-0
	MOVW $sp-4(FP), R7
	RET
`
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm",
		TargetTriple: "armv5te-unknown-linux-gnueabi",
		Sigs: map[string]FuncSig{
			"callerSP": {Name: "callerSP", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "store i32 0, ptr %reg_R7") {
		t.Fatalf("caller-SP context placeholder was not written to R7:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv5te-unknown-linux-gnueabi", "arm-caller-sp.ll", "arm-caller-sp.o", ir)
}

func TestTranslateARMCallerSPPseudoAddressRejectsOtherOffsets(t *testing.T) {
	src := "TEXT callerSP(SB),NOSPLIT,$8-0\n\tMOVW $sp-8(FP), R7\n\tRET\n"
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch:       "arm",
		TargetTriple: "armv5te-unknown-linux-gnueabi",
		Sigs: map[string]FuncSig{
			"callerSP": {Name: "callerSP", Ret: Void},
		},
	}); err == nil {
		t.Fatal("Translate unexpectedly accepted an unknown caller-SP offset")
	}
}
