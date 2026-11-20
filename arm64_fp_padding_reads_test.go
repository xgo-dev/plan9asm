package plan9asm

import (
	"strings"
	"testing"
)

func TestARM64FPPaddingReadNeedsCompleteTypedBitUseProof(t *testing.T) {
	pkg := mustGoPackage(t, "example.invalid/padbits", "package padbits\nfunc Narrow(rhs int16) (res uint64)\n")
	for _, body := range []string{
		"MOVD rhs+0(FP),R2\nMOVH R2,R0\n",
		"MOVD rhs+0(FP),R2\nVDUP R2,V0.S2\nVSHL $16,V0.S2,V1.S2\nVSSHR $16,V1.S2,V1.S2\nVMOV V1.S[0],R0\n",
	} {
		source := "TEXT ·Narrow(SB),4,$0-16\n" + body + "MOVD R0,res+8(FP)\nRET\n"
		translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOOS: "linux", GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
			ResolveSym: testResolveSym(pkg.Path),
		})
		if err != nil {
			t.Fatalf("typed source discards every padding bit: %v", err)
		}
		translated.Module.Dispose()
	}
}

func TestARM64FPPaddingReadCannotInferPermissionFromSparseFrame(t *testing.T) {
	const source = "TEXT narrow(SB),4,$0-16\nMOVD rhs+0(FP),R2\nMOVH R2,R0\nMOVD R0,res+8(FP)\nRET\n"
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"narrow": {
			Name: "narrow", Args: []LLVMType{I16}, Ret: I64,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I16, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "has no slot") {
		t.Fatalf("manual sparse slots supplied padding permissions: %v", err)
	}
}
