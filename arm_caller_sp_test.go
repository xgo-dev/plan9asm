package plan9asm

import (
	"errors"
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
	_, err = Translate(file, Options{
		Goarch:       "arm",
		TargetTriple: "armv5te-unknown-linux-gnueabi",
		Sigs: map[string]FuncSig{
			"callerSP": {Name: "callerSP", Ret: Void},
		},
	})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("caller-SP address without typed backing must retain context failure: %v", err)
	}
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
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("unknown caller-SP offset must retain context failure: %v", err)
	}
}
