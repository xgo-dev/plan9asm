package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86IndirectMemoryBranchTargetWidth(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []struct {
		arch, triple, move, word string
		bytes                    int
	}{
		{"386", "i386-unknown-linux-gnu", "MOVL", "i32", 4},
		{"amd64", "x86_64-unknown-linux-gnu", "MOVQ", "i64", 8},
	} {
		rows := []string{"CALL (AX)", "CALL (AX)(CX*2)", "CALL *foo(SB)", "JMP (AX)", "JMP (AX)(CX*2)"}
		for _, instruction := range rows {
			t.Run(target.arch+"/"+instruction, func(t *testing.T) {
				source := fmt.Sprintf("GLOBL foo(SB),16,$16\nTEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $1,CX\n%s\n",
					target.bytes, target.move, instruction)
				if strings.HasPrefix(instruction, "CALL") {
					source += "RET\n"
				}
				requireX86GoAssemblerResult(t, target.arch, source, true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *uintptr)", target.arch, target.triple, api)
						if err != nil {
							t.Fatal(err)
						}
						// Local GP slots are always i64. Only the branch-table
						// access must match the original addressing mode.
						want := 0
						if target.arch == "386" {
							want = 1
						}
						if got := strings.Count(ir, "load i32, ptr"); got != want {
							t.Fatalf("want %d four-byte branch-target reads, got %d:\n%s", want, got, ir)
						}
						x86ResultInitializationObject(t, llc, target.triple, ir, "branch")
					})
				}
			})
		}
	}
}
