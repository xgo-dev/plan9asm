package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86ExtensionBareSymbolsDoNotBecomeNativeStorage(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ExtensionNativeOracle {
			if arch == "386" && row.amd64Only {
				continue
			}
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row.op+" broken,AX\nRET\n", "", false)
				ins := Instr{Op: Op(row.op), Raw: row.op + " broken,AX",
					Args: []Operand{{Kind: OpSym, Sym: "broken"}, {Kind: OpReg, Reg: AX}}}
				if _, known, err := x86ScalarExtensionProperties(ins.Op, ins, arch); !known || err == nil {
					t.Error("shared extension grammar admitted a bare symbol", known, err)
				}
				c, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.Value", Ret: Void}, nil)
				c.goarch = arch
				before := output.String()
				if handled, _, err := c.lowerMov(ins.Op, ins); !handled || err == nil || before != output.String() {
					t.Error("direct extension emitter created storage for a bare name", handled, err)
				}
				for _, address := range []string{"table<>(SB)", "1234"} {
					source := fmt.Sprintf("TEXT f(SB),4,$0-0\n%s %s,AX\nRET\n", row.op, address)
					goAssemblerOracleOutput(t, arch, source, "", true)
					control := ins
					control.Args = []Operand{{Kind: OpSym, Sym: address}, {Kind: OpReg, Reg: AX}}
					control.Raw = row.op + " " + address + ",AX"
					if _, known, err := x86ScalarExtensionProperties(control.Op, control, arch); !known || err != nil {
						t.Fatal("valid SB/absolute source lost its existing grammar", address, err)
					}
				}
			})
		}
	}
}
