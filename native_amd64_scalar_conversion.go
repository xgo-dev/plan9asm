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
		source = nativeAMD64VectorReg(ins.Args[0].Reg, 16)
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
	destination := nativeAMD64VectorReg(ins.Args[f.destination].Reg, 16)
	opcode := f.attOpcode(unsigned)
	if f.spec.legacy {
		fmt.Fprintf(out, "\t%s %s, %s\n", opcode, source, destination)
		return nil
	}
	if f.rounding != "" {
		rounding := strings.ToLower(strings.ReplaceAll(f.rounding, "_", "-"))
		source += ", {" + rounding + "}"
	}
	upper := nativeAMD64VectorReg(ins.Args[f.upper].Reg, 16)
	fmt.Fprintf(out, "\t%s %s, %s, %s\n", opcode, source, upper, destination)
	return nil
}
