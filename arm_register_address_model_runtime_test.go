package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Pure integer/flag IR can run on the host without dereferencing truncated ARM
// pointers. This is a semantic model test, separate from the ARM Go/C oracle.
func TestARMRegisterAddressFlagsModelRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang not found")
	}
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, offset := range []int64{0, 255, -255, 4097, -4097} {
		for _, condition := range []string{"", ".EQ", ".NE"} {
			name := fmt.Sprintf("register_address_flags_%d", len(sigs))
			fmt.Fprintf(&source, "TEXT %s(SB),$0-12\nMOVW input+0(FP),R0\nMOVW $0x13579bdf,R11\nMOVW $0x89abcdef,R1\nCMP R3,R3\nMOVW%s.S $%d(R0),R1\nMOVW $0,R2\nORR.MI $8,R2\nORR.EQ $4,R2\nORR.CS $2,R2\nORR.VS $1,R2\nMOVW R1,result+4(FP)\nMOVW R2,result+8(FP)\nRET\n", name, condition, offset)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{I32}, Ret: I64, Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 4, Type: I64, Index: 0, Field: -1}},
			}}
			fmt.Fprintf(&declarations, "extern uint64_t %s(uint32_t);\n", name)
			for _, input := range []uint32{0, 1, 0xffffffff, 0x7fffffff, 0x80000000} {
				want := armRegisterAddressExpected(input, 0x13579bdf, offset, true, condition != ".NE", "R0", "R1")
				packed := uint64(want[1])<<32 | uint64(want[0])
				fmt.Fprintf(&checks, "if(%s(UINT32_C(%d))!=UINT64_C(%d)) { fprintf(stderr,\"%s input=%d value/NZCV model failed\\n\"); return 1; }\n", name, input, packed, name, input)
			}
		}
	}
	requireARMGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n" + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTest(t, llc, clang, "register_address_flags", ir, main)
}
