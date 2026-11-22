package plan9asm

import (
	"fmt"
	"strings"
)

func (e *nativeAMD64) emitScalarFloatInteger(out *strings.Builder, ins Instr, f x86ScalarFloatIntegerForm) error {
	var source string
	if f.memory {
		var err error
		source, err = e.operand(ins.Args[0], f.spec.inputBits)
		if err != nil {
			return err
		}
	} else {
		source = physicalScalarConversionXMM(ins.Args[0])
	}
	destination, err := nativeAMD64Reg(ins.Args[1], f.outputBits)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\t%s %s, %s\n", f.attOpcode(), source, destination)
	return nil
}

func (e *nativeAMD64) emitIntegerScalarFloat(out *strings.Builder, ins Instr, f x86SignedIntegerFloatForm, unsigned bool) error {
	source, err := e.operand(ins.Args[0], f.sourceBits)
	if err != nil {
		return err
	}
	destination := physicalScalarConversionXMM(ins.Args[f.destination])
	opcode := f.attOpcode(unsigned)
	if f.spec.legacy {
		fmt.Fprintf(out, "\t%s %s, %s\n", opcode, source, destination)
		return nil
	}
	if f.rounding != "" {
		rounding := strings.ToLower(strings.ReplaceAll(f.rounding, "_", "-"))
		source += ", {" + rounding + "}"
	}
	fmt.Fprintf(out, "\t%s %s, %s, %s\n", opcode, source, physicalScalarConversionXMM(ins.Args[f.upper]), destination)
	return nil
}

// The conversion family has already checked the operand and the XMM bank,
// including whether its encoding can address registers 16 through 31.
func physicalScalarConversionXMM(operand Operand) string {
	index, _ := amd64ParseXReg(operand.Reg)
	return fmt.Sprintf("%%xmm%d", index)
}
