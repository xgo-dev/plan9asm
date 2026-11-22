package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalAccumulatorSignExtendOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	for index, row := range x86AccumulatorSignExtendOracle {
		name := fmt.Sprintf("Value%d", index)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\n", name)
		assembly.WriteString("MOVQ a+0(FP),AX\nMOVQ AX,DX\nXORQ CX,CX\n")
		assembly.WriteString("LEAQ 63(SP),BX\nMOVQ AX,(BX)\nSTC\n")
		fmt.Fprintf(&assembly, "%s\nSETCS CL\nMOVQ (BX),R8\nXORQ R8,%s\nXORQ CX,%s\nMOVQ %s,ret+8(FP)\nRET\n",
			row.op, row.destination, row.destination, row.destination)
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(x86AccumulatorSignExtendOracle))
}

func TestGoAMD64FixedLocalAccumulatorSignExtendImplicitBytes(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, body string
		accept     bool
	}{
		{"CBW needs one byte", "MOVB R11,AL\nCBW\nMOVWQZX AX,AX", true},
		{"CWDE needs one word", "MOVW R11,AX\nCWDE", true},
		{"CDQE consumes signed low dword", "MOVL R11,AX\nCDQE", true},
		{"CWD preserves flags", "MOVW R11,AX\nMOVQ R11,DX\nSTC\nCWD\nSETCS CL\nMOVQ DX,AX", true},
		{"CDQ zeroes upper EDX", "MOVL R11,AX\nCDQ\nMOVQ DX,AX", true},
		{"CQO consumes native word", "MOVQ R11,AX\nCQO\nMOVQ DX,AX", true},
		{"undefined input byte", "CBW\nMOVWQZX AX,AX", false},
		{"missing high input byte", "MOVB R11,AL\nCWDE", false},
		{"CWD upper result bytes remain unknown", "MOVW R11,AX\nCWD\nMOVQ DX,AX", false},
		{"private address is not signed data", "LEAQ 64(SP),AX\nCQO\nMOVQ DX,AX", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$128-16\nMOVQ a+0(FP),R11\nXORQ CX,CX\n" +
				row.body + "\nMOVQ AX,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private sign-extension source, accept=%t: %v", row.accept, err)
			}
		})
	}
}
