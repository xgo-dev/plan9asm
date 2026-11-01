package plan9asm

import (
	"fmt"
	"strings"
)

var arm64VectorFloatMinMaxAcrossOps = map[Op]string{
	"VFMAXV":   "maximum",
	"VFMINV":   "minimum",
	"VFMAXNMV": "maxnum",
	"VFMINNMV": "minnum",
}

func (c *arm64Ctx) lowerARM64VectorFloatMinMaxAcross(op Op, ins Instr) (ok bool, terminated bool, err error) {
	operation, handled := arm64VectorFloatMinMaxAcrossOps[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects Vsrc.S4, Vdst and no suffix: %q", op, ins.Raw)
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationIndex, destinationValid := arm64ParseVReg(ins.Args[1].Reg)
	if !valid || arrangement != (arm64VectorArrangement{elementBits: 32, lanes: 4}) ||
		!destinationValid || strings.Contains(string(ins.Args[1].Reg), ".") {
		return true, false, fmt.Errorf("arm64 %s requires an S4 source and bare V destination: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64FloatMinMaxAcrossValues(
		operation,
		arrangement,
		ins.Args[0].Reg,
		Reg(fmt.Sprintf("F%d", destinationIndex)),
	)
}

func (c *arm64Ctx) lowerARM64FloatMinMaxAcrossValues(
	operation string,
	arrangement arm64VectorArrangement,
	sourceReg Reg,
	destination Reg,
) error {
	source, err := c.loadARM64VectorFloat(sourceReg, arrangement)
	if err != nil {
		return err
	}
	floatType := arm64RawFloatType(arrangement.elementBits)
	first := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 0\n", first, arrangement.lanes, floatType, source)
	result := "%" + first
	for lane := 1; lane < arrangement.lanes; lane++ {
		element := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n", element, arrangement.lanes, floatType, source, lane)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.f%d(%s %s, %s %%%s)\n",
			combined, floatType, operation, arrangement.elementBits, floatType, result, floatType, element)
		result = "%" + combined
	}
	return c.storeARM64ScalarFloatReg(destination, arrangement.elementBits, result)
}
