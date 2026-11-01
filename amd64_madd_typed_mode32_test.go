package plan9asm

import "testing"

func TestX86MADDTypedMode32LegacySourceRules(t *testing.T) {
	for _, opcode := range []string{"PMADDWL", "PMADDUBSW"} {
		for _, operands := range []string{"X0,X1", "X0,X7", "(AX),X7"} {
			row := opcode + " " + operands
			source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			goAssemblerOracleOutput(t, "386", source, "", true)
			code := assembleX87ControlBytes(t, "386", source)
			if len(code) == 0 {
				t.Fatal("accepted legacy source has no original Go machine bytes", row)
			}
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, known, err := x86PackedMultiplyAddProperties(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1], "386")
			if !known || err != nil {
				t.Errorf("accepted low mode32 source lost its typed shape: %s bytes%x: %v", row, code, err)
			}
		}
		// Unlike the AVX name rows, the legacy encoder rejects these high
		// source spellings; do not label them accepted physical Context rows.
		for _, operands := range []string{"X8,X1", "X0,X15", "(AX),X8", "X16,X0", "X0,X16"} {
			source := "TEXT f(SB),4,$0-0\n" + opcode + " " + operands + "\nRET\n"
			goAssemblerOracleOutput(t, "386", source, "", false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, known, err := x86PackedMultiplyAddProperties(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1], "386")
			if !known || err == nil {
				t.Fatal("Go-rejected high legacy source obtained typed admission", source)
			}
		}
	}
	// The shared ymm is not a blanket 386 MMX row: Py1's original row
	// selection rejects its z<1 MMX forms in 32-bit mode.
	for _, source := range []string{"M0", "(AX)", "AX", "CX", "SI"} {
		row := "PMADDWL " + source + ",M1"
		goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
	}
}
