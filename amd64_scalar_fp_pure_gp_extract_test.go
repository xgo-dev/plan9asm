package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// PEXTRD deliberately activates the lowering-only result observer. An ordinary
// GP return alone does not establish that this callback was actually invoked.
func TestX86LoweredPureGPUnknownPEXTRDExactScratchUpdate(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		tail := ""
		if overwrite {
			tail = "MOVQ $0,DI\nCMPL AX,AX\n"
		}
		source := `TEXT ·view(SB),4,$0-4
VPXORQ Z1,Z1,Z1
ADDQ $64,DI
VPTERNLOGD $255,Z0,Z0,Z1
PEXTRD $0,X1,AX
` + tail + `MOVL AX,ret+0(FP)
RET
`
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			if _, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
				t.Fatalf("independent result lost after unobserved ADDQ: overwrite=%t API=%s: %v", overwrite, api, err)
			}
		}
	}
	// Keep the declaration-only query strict. It must not inherit a private
	// lowering fallback simply because the emitted LLVM counterpart is safe.
	_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value() uint32",
		"ADDQ $64,DI\nMOVL $37,AX\nMOVL AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret0+0(FP)\nRET")
	for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
		err := check(file.Funcs[0], sig, "amd64")
		if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "ADDQ $64,DI") {
			t.Fatal("unpaired observer acquired lowering-only permission", err)
		}
	}
}

func TestX86LoweredPureGPUnknownPEXTRDCompleteExistingFamilies(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		var source, declarations strings.Builder
		for index, row := range x86PureGPUnknownCases(target.arch) {
			fmt.Fprintf(&declarations, "func pureExtract%d() uint32\n", index)
			fmt.Fprintf(&source, "TEXT ·pureExtract%d(SB),4,$0-4\nMOVL $1,AX\nCMPL AX,AX\n%s\nMOVL $37,AX\nMOVL AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n", index, row.body)
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
			if err != nil {
				t.Fatal(target.triple, api, err)
			}
			compileLLVMToObject(t, llc, target.triple, "pure-extract.ll", "pure-extract.o", ir)
		}
	}
}

func TestX86LoweredPureGPUnknownPEXTRDObservableBoundaries(t *testing.T) {
	for _, body := range []string{
		"MOVL DI,X0",
		"MOVL DI,ret+0(FP)",
		"MOVL (DI),AX",
		"MOVL DI,(AX)",
		"JE finish\nfinish:",
		"SETCS ret+0(FP)",
	} {
		source := "TEXT ·view(SB),4,$0-4\nMOVL $37,AX\nMOVL AX,X0\nADDQ $64,DI\n" + body + "\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n"
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			if _, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("observable unknown value or flags accepted", body, api, err)
			}
		}
	}
}
