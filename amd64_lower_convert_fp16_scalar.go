package plan9asm

import "fmt"

func (c *amd64Ctx) lowerRawScalarHalfConversion(ins Instr, f x86FP16ConversionForm) (bool, bool, error) {
	spec, properties := f.spec, f.controls
	source, upper, destination := ins.Args[0], ins.Args[f.upper], ins.Args[f.destination]
	mask := ""
	var err error
	if f.mask >= 0 {
		mask, err = c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	value, err := c.loadFMA3Scalar(source, spec.inputBits, mask)
	if err != nil {
		return true, false, err
	}
	inputType := amd64FMA3LLVMType(1, spec.inputBits)
	vector, bits := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x %s> poison, %s %s, i32 0\n", vector, inputType, inputType, value)
	fmt.Fprintf(c.b, "  %%%s = bitcast <1 x %s> %%%s to <1 x i%d>\n", bits, inputType, vector, spec.inputBits)
	result := c.emitHalfConversion(1, spec, "%"+bits, properties.rounding)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", low, spec.outputBits, result)
	upperBytes, err := c.loadX(upper.Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.outputBits, spec.outputBits, upperBytes)
	return true, false, c.storeScalarMoveRegister(destination.Reg, spec.outputBits, "%"+low, base, mask, properties.zeroing)
}
