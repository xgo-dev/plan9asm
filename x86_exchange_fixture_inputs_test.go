package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Preserve every discovering XADD/XCHG instruction. This separate complete
// source defines its actual GP inputs before each row, since an exchange may
// otherwise overwrite the register which a later row uses as an address.
func x86InitializedExchangeFixture(t *testing.T, original string, file *File, arch, name string) x86OriginalGPInitializedFormat {
	t.Helper()
	if len(file.Funcs) != 1 {
		t.Fatal("exchange counterpart requires its complete original function")
	}
	data, _, found := strings.Cut(original, "TEXT ")
	if !found {
		t.Fatal("exchange counterpart lost its original DATA/TEXT boundary")
	}
	move, word := "MOVQ", 8
	registers := []string{"AX", "BX", "CX", "DX", "R11", "R12"}
	if arch == "386" {
		move, word = "MOVL", 4
		registers = []string{"AX", "BX", "CX", "DX", "BP", "SI", "DI"}
	}
	var source strings.Builder
	source.WriteString(data)
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", name, word)
	for _, instruction := range file.Funcs[0].Instrs[1:] {
		if instruction.Op == OpRET {
			continue
		}
		if !strings.HasPrefix(string(instruction.Op), "XADD") && !strings.HasPrefix(string(instruction.Op), "XCHG") {
			t.Fatal("foreign instruction in original exchange family", instruction.Raw)
		}
		for _, register := range registers {
			fmt.Fprintf(&source, "%s $1,%s\n", move, register)
		}
		for _, operand := range instruction.Args {
			if operand.Kind == OpMem && operand.Mem.Base == BX {
				fmt.Fprintf(&source, "%s p+0(FP),BX\n", move)
			}
		}
		source.WriteString(instruction.Raw + "\n")
	}
	source.WriteString("RET\n")
	return x86OriginalGPInitializedFormat{source.String(), "func " + name + "(p *[64]byte)"}
}
