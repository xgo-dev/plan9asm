package plan9asm

import "fmt"

func (c *arm64Ctx) lowerARM64PortableMixedSaturatingAdd(form arm64SaturatingArithmeticForm, sourceReg, destinationReg Reg) error {
	arrangement := form.arrangement
	bits := arrangement.elementBits
	if arrangement.lanes == 1 {
		source, err := c.arm64VDUPExtractLane(sourceReg, bits, 0)
		if err != nil {
			return err
		}
		destination, err := c.arm64VDUPExtractLane(destinationReg, bits, 0)
		if err != nil {
			return err
		}
		// LLVM 22 cannot select the overloaded scalar i8/i16 intrinsic. Place
		// the active lane in a zeroed vector instead. Other lanes cannot set
		// saturation state, and only the active result lane is written back.
		lanes := 64 / bits
		if bits == 64 {
			lanes = 2
		}
		typeName := fmt.Sprintf("<%d x i%d>", lanes, bits)
		sourceVector := c.newTmp()
		destinationVector := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, i%d %s, i32 0\n",
			sourceVector, typeName, bits, source)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, i%d %s, i32 0\n",
			destinationVector, typeName, bits, destination)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%di%d(%s %%%s, %s %%%s)\n",
			result, typeName, form.op.mnemonic, lanes, bits,
			typeName, destinationVector, typeName, sourceVector)
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 0\n", low, typeName, result)
		return c.storeARM64ScalarToVReg(destinationReg, bits, "%"+low)
	}

	source, err := c.loadARM64VectorInteger(sourceReg, arrangement)
	if err != nil {
		return err
	}
	destination, err := c.loadARM64VectorInteger(destinationReg, arrangement)
	if err != nil {
		return err
	}
	typeName := fmt.Sprintf("<%d x i%d>", arrangement.lanes, bits)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%di%d(%s %s, %s %s)\n",
		result, typeName, form.op.mnemonic, arrangement.lanes, bits,
		typeName, destination, typeName, source)
	return c.storeARM64VectorInteger(destinationReg, arrangement, "%"+result)
}
