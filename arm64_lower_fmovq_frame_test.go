package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64FMOVQCompleteFPFrameForms(t *testing.T) {
	tests := []struct {
		name   string
		source string
		sig    FuncSig
		loads  int
		stores int
	}{
		{
			name: "two uint64 lanes",
			source: `TEXT fmovqwords(SB),$0-32
	FMOVQ value+0(FP), F0
	FMOVQ F0, ret+16(FP)
	RET
`,
			sig: FuncSig{
				Name: "fmovqwords", Args: []LLVMType{"[2 x i64]"}, Ret: LLVMType("{ i64, i64 }"),
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
			loads: 2, stores: 2,
		},
		{
			name: "four float32 lanes",
			source: `TEXT fmovqfloats(SB),$0-32
	FMOVQ value+0(FP), F1
	FMOVQ F1, ret+16(FP)
	RET
`,
			sig: FuncSig{
				Name: "fmovqfloats", Args: []LLVMType{"[4 x float]"}, Ret: LLVMType("{ float, float, float, float }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: LLVMType("float"), Index: 0, Field: 0, Fields: []int{0}},
						{Offset: 4, Type: LLVMType("float"), Index: 0, Field: 1, Fields: []int{1}},
						{Offset: 8, Type: LLVMType("float"), Index: 0, Field: 2, Fields: []int{2}},
						{Offset: 12, Type: LLVMType("float"), Index: 0, Field: 3, Fields: []int{3}},
					},
					Results: []FrameSlot{
						{Offset: 16, Type: LLVMType("float"), Index: 0, Field: -1},
						{Offset: 20, Type: LLVMType("float"), Index: 1, Field: -1},
						{Offset: 24, Type: LLVMType("float"), Index: 2, Field: -1},
						{Offset: 28, Type: LLVMType("float"), Index: 3, Field: -1},
					},
				},
			},
			loads: 4, stores: 4,
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
			if got := strings.Count(ir, "extractvalue"); got < test.loads {
				t.Fatalf("FMOVQ frame load emitted %d extractvalue operations, want at least %d:\n%s", got, test.loads, ir)
			}
			if got := strings.Count(ir, "store "); got < test.stores {
				t.Fatalf("FMOVQ frame store emitted %d stores, want at least %d:\n%s", got, test.stores, ir)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-fmovq-frame.ll", "arm64-fmovq-frame.o", ir)
		})
	}
}
