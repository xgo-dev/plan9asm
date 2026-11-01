package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestARM64ReadFPResultSlot(t *testing.T) {
	tests := []struct {
		name   string
		source string
		sig    FuncSig
	}{
		{
			name: "integer result",
			source: `TEXT readintresult(SB),$0-16
	MOVD value+0(FP), R0
	MOVD R0, ret+8(FP)
	MOVD ret+8(FP), R1
	ADD $1, R1
	MOVD R1, ret+8(FP)
	RET
`,
			sig: FuncSig{
				Name: "readintresult", Args: []LLVMType{I64}, Ret: I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
		},
		{
			name: "complex128 result components",
			source: `TEXT readcomplexresult(SB),$0-48
	MOVD a_real+0(FP), R0
	MOVD a_imag+8(FP), R1
	MOVD b_real+16(FP), R2
	MOVD b_imag+24(FP), R3
	MOVD R0, ret+32(FP)
	MOVD R1, ret+40(FP)
	FMOVD ret+32(FP), F0
	FMOVD F0, ret+32(FP)
	MOVD ret+32(FP), R4
	MOVD ret+40(FP), R5
	EOR R2, R4
	EOR R3, R5
	MOVD R4, ret+32(FP)
	MOVD R5, ret+40(FP)
	RET
`,
			sig: FuncSig{
				Name: "readcomplexresult",
				Args: []LLVMType{"{ double, double }", "{ double, double }"},
				Ret:  LLVMType("{ double, double }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: LLVMType("double"), Index: 0, Field: 0},
						{Offset: 8, Type: LLVMType("double"), Index: 0, Field: 1},
						{Offset: 16, Type: LLVMType("double"), Index: 1, Field: 0},
						{Offset: 24, Type: LLVMType("double"), Index: 1, Field: 1},
					},
					Results: []FrameSlot{
						{Offset: 32, Type: LLVMType("double"), Index: 0, Field: -1},
						{Offset: 40, Type: LLVMType("double"), Index: 1, Field: -1},
					},
				},
			},
		},
		{
			name: "vector-width result read",
			source: `TEXT readvectorresult(SB),$0-32
	FMOVQ value+0(FP), F0
	FMOVQ F0, ret+16(FP)
	FMOVQ ret+16(FP), F1
	FMOVQ F1, ret+16(FP)
	RET
`,
			sig: FuncSig{
				Name: "readvectorresult", Args: []LLVMType{"[2 x i64]"}, Ret: LLVMType("{ i64, i64 }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I64, Index: 0, Field: 0, Fields: []int{0}},
						{Offset: 8, Type: I64, Index: 0, Field: 1, Fields: []int{1}},
					},
					Results: []FrameSlot{
						{Offset: 16, Type: I64, Index: 0, Field: -1},
						{Offset: 24, Type: I64, Index: 1, Field: -1},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireARM64GoAssemblerResult(t, test.source, true)
			file, err := Parse(ArchARM64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{test.sig.Name: test.sig},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "load "+string(test.sig.Frame.Results[0].Type)+", ptr %fp_ret_0") {
				t.Fatalf("missing FP result read:\n%s", ir)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-fp-result-read.ll", "arm64-fp-result-read.o", ir)
		})
	}
}

func TestARM64ReadFPResultSlotRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT readintresult(SB),$0-16
	MOVD value+0(FP), R0
	MOVD R0, ret+8(FP)
	MOVD ret+8(FP), R1
	ADD $1, R1
	MOVD R1, ret+8(FP)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm64",
		TargetTriple: "aarch64-apple-darwin",
		Sigs: map[string]FuncSig{
			"readintresult": {
				Name: "readintresult", Args: []LLVMType{I64}, Ret: I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern uint64_t readintresult(uint64_t value);
int main(void) {
	return readintresult(41) == 42 ? 0 : 1;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_fp_result_read", "aarch64-apple-darwin", ir, mainC, nil)
}
