package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

const arm64BorrowedTailOriginalSource = `TEXT caller(SB),4,$24-8
	MOVD out+0(FP), R4
	MOVD $7, R3
	MOVD R3, 8(RSP)
	MOVD R4, 16(RSP)
	B helper(SB)
TEXT helper(SB),4,$0-0
	MOVD vector+0(FP), R3
	MOVD out+8(FP), R4
	MOVD R3, (R4)
	RET
`

// An ordinary typed LLVM call/return does not implement the native source
// helper's borrowed SP and missing caller-frame epilogue. The native Go
// observation oracle retains the original slots and safely measures -48.
func TestARM64BorrowedTailFrameRequiresNativeStackContract(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64BorrowedTailOriginalSource, true)
	file, err := Parse(ArchARM64, arm64BorrowedTailOriginalSource)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		_, err := Translate(file, Options{
			Goarch: "arm64", TargetTriple: triple,
			Sigs: map[string]FuncSig{
				"caller": {
					Name: "caller", Args: []LLVMType{Ptr}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1, Name: "out"},
					}},
				},
				"helper": {
					Name: "helper", Args: []LLVMType{I64, I64}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: I64, Index: 0, Field: -1, Name: "vector"},
						{Offset: 8, Type: I64, Index: 1, Field: -1, Name: "out"},
					}},
				},
			},
		})
		if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "symbol branch has no implicit Go frame epilogue") {
			t.Fatalf("%s: native borrowed-frame continuation must remain Context: %v", triple, err)
		}
	}
}
