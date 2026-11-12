package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86FloatingCompareIntegerImmediateClassBeforeEmission(t *testing.T) {
	for _, opcode := range x86FloatCompareOpcodes() {
		row, index := opcode+" X0,X1,$0.0", 2
		if strings.HasPrefix(opcode, "V") {
			row, index = opcode+" $0.0,X0,X1,X2", 0
		}
		goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, unresolved := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/unresolved=%t", opcode, unresolved), func(t *testing.T) {
				ins := file.Funcs[0].Instrs[1]
				ins.Args = append([]Operand(nil), ins.Args...)
				if unresolved {
					ins.Args[index] = Operand{Kind: OpImm, ImmRaw: "$UNRESOLVED_PREDICATE"}
				}
				ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
				before := output.Len()
				if known, term, err := ctx.lowerFloatingCompare(ins.Op, ins); !known || term || err == nil || output.Len() != before {
					t.Fatalf("floating/symbolic predicate acquired integer comparison or emitted IR: %t/%t/%v", known, term, err)
				}
			})
		}
	}
}
