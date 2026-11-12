package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86X87ConditionalOriginalRuntimeSourcePortableBoundary(t *testing.T) {
	source := x86X87ENVLiteral(t, "amd64_lower_x87_conditional_move_test.go", "TestAMD64X87ConditionalMoveRuntimeConditions")
	// Actual Go syntax/object acceptance is independent of a native pointer
	// extent, caller write envelope, or a portable numerical proof.
	goAssemblerOracleOutput(t, "amd64", "#include \"textflag.h\"\n"+source, "", true)
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, source, "func x87conditionalmovesemantics(data *byte)",
					"amd64", triple, api, X87Software)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" ||
					!strings.Contains(err.Error(), "logical x87 value stack is not balanced at RET") {
					t.Fatal("original x87 source acquired an unobserved empty stack at RET", err)
				}
			})
		}
	}
}

func TestX86X87ConditionalBalancedOriginalSourceObjects(t *testing.T) {
	source := x86X87ENVLiteral(t, "amd64_lower_x87_conditional_move_test.go", "TestAMD64X87ConditionalMoveRuntimeConditions")
	balanced := strings.Replace(source, "\tRET\n", "\tFINIT\n\tRET\n", 1)
	if balanced == source || strings.Count(source, "\tRET\n") != 1 {
		t.Fatal("original x87 conditional fixture lost its unique RET")
	}
	goAssemblerOracleOutput(t, "amd64", "#include \"textflag.h\"\n"+balanced, "", true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, balanced, "func x87conditionalmovesemantics(data *byte)",
					"amd64", triple, api, X87Software)
				if err != nil || ir == "" {
					t.Fatal("independently balanced original source rejected", err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					compileLLVMToObject(t, llc, triple, "x87-balanced.ll", "x87-balanced.o", text)
				}
			})
		}
	}
}
