package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64WritableFPParameterSource = `
TEXT writablefpparameter(SB),$0-16
	MOVD value+0(FP), R0
	ADD $1, R0
	MOVD R0, value+0(FP)
	MOVD value+0(FP), R1
	MOVD R1, result+8(FP)
	RET
`

func arm64WritableFPParameterSignature() FuncSig {
	return FuncSig{
		Name: "writablefpparameter", Args: []LLVMType{I64}, Ret: I64,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
		},
	}
}

func TestTranslateARM64WritableFPParameterSlot(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64WritableFPParameterSource, true)
	file, err := Parse(ArchARM64, arm64WritableFPParameterSource)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"writablefpparameter": arm64WritableFPParameterSignature()},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "%fp_param_0 = alloca i64") || !strings.Contains(ir, "store i64 %arg0, ptr %fp_param_0") {
				t.Fatalf("writable FP parameter slot was not materialized for %s:\n%s", triple, ir)
			}
			compileLLVMToObject(t, llc, triple, "arm64-writable-fp-parameter.ll", "arm64-writable-fp-parameter.o", ir)
		})
	}
}

func TestARM64WritableFPParameterRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	file, err := Parse(ArchARM64, arm64WritableFPParameterSource)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{"writablefpparameter": arm64WritableFPParameterSignature()},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern uint64_t writablefpparameter(uint64_t);
int main(void) { return writablefpparameter(41) == 42 ? 0 : 1; }
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_writable_fp_parameter", triple, ir, mainC, nil)
}
