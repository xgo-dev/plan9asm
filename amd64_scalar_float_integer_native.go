package plan9asm

import (
	"fmt"
	"strings"
)

// LLVM fptosi/fptoui produce poison outside the result domain. Even constrained
// conversions do not specify x86's indefinite integer or complete MXCSR effect.
// Execute one original-class instruction, including when its GP result is dead.
func (c *amd64Ctx) emitNativeScalarFloatInteger(ins Instr, f x86ScalarFloatIntegerForm) error {
	mnemonic := "cvt"
	if f.spec.truncating {
		mnemonic += "t"
	}
	if f.spec.inputBits == 32 {
		mnemonic += "ss2"
	} else {
		mnemonic += "sd2"
	}
	if f.spec.unsigned {
		mnemonic += "usi"
	} else {
		mnemonic += "si"
	}
	if f.outputBits == 64 {
		mnemonic += "q"
	} else {
		mnemonic += "l"
	}
	if f.spec.vector {
		mnemonic = "v" + mnemonic
	}
	if f.evex {
		mnemonic = "{evex} " + mnemonic
	}
	if f.suffix != "" {
		rounding := strings.ToLower(strings.ReplaceAll(f.suffix, "_", "-"))
		mnemonic += " {" + rounding + "},"
	}

	source := ins.Args[0]
	var value, typ, constraint, operand string
	if source.Kind == OpReg || source.Kind == OpFP {
		var err error
		value, err = c.evalScalarFloatForInteger(source, f.spec.inputBits)
		if err != nil {
			return err
		}
		typ, constraint, operand = string(amd64FloatingTypeForBits(f.spec.inputBits)), "x", "$1"
		if f.evex {
			constraint = "v"
		}
	} else {
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
		if err != nil {
			return err
		}
		segment := ""
		if pointerType == "ptr addrspace(256)" {
			segment = "%gs:"
		} else if pointerType == "ptr addrspace(257)" {
			segment = "%fs:"
		}
		value = pointer
		typ = fmt.Sprintf("%s elementtype([%d x i8])", pointerType, f.spec.inputBits/8)
		constraint, operand = "*m", segment+"$1"
	}
	result := c.newTmp()
	outputType := amd64IntegerTypeForBits(f.outputBits)
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s)\n", result, outputType,
		mnemonic+" "+operand+", $0", "=r,"+constraint+",~{memory},~{fpsr}", typ, value)
	return c.storeRegSized(ins.Args[1].Reg, outputType, "%"+result)
}
