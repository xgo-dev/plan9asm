package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalCacheLineOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	operations := []string{"CLFLUSH", "CLFLUSHOPT", "CLWB"}
	for index, op := range operations {
		name := fmt.Sprintf("Value%d", index)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\nMOVQ a+0(FP),AX\n", name)
		assembly.WriteString("LEAQ 127(SP),BX\nXORQ CX,CX\nSTC\n")
		fmt.Fprintf(&assembly, "%s (BX)\nSETCS CL\nXORQ CX,AX\nMOVQ AX,ret+8(FP)\nRET\n", op)
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalCacheLineNeedsReachableAddress(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, body string
		accept     bool
	}{
		{"uninitialized byte", "CLFLUSH 127(SP)", true},
		{"unaligned exact address", "LEAQ 123(SP),BX\nCLFLUSHOPT (BX)", true},
		{"preserve carry", "STC\nCLWB 127(SP)\nSETCS CL", true},
		{"before frame", "CLFLUSH -1(SP)", false},
		{"after frame", "CLFLUSHOPT 128(SP)", false},
		{"unknown address", "CLWB (BX)", false},
		{"no old value becomes known", "CLFLUSH 72(SP)\nMOVQ 72(SP),AX", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$128-16\nMOVQ a+0(FP),AX\nXORQ CX,CX\n" +
				row.body + "\nMOVQ AX,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private cache instruction source, accept=%t: %v", row.accept, err)
			}
		})
	}
}
