package plan9asm

import (
	"fmt"
	"strings"
)

// lowerLegacyIntegerToFloat implements Go 1.27's complete legacy integer to
// floating-point conversion group: yxcvlf/yxcvqf scalar conversions and the
// two yxcvm2 packed conversions.
func (c *amd64Ctx) lowerLegacyIntegerToFloat(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	if strings.Contains(rawOp, ".") {
		base := strings.SplitN(rawOp, ".", 2)[0]
		switch base {
		case "CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "CVTPL2PS", "CVTPL2PD":
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", base, ins.Raw)
		}
	}
	switch rawOp {
	case "CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD":
		return c.lowerLegacyScalarIntegerToFloat(rawOp, ins)
	case "CVTPL2PS", "CVTPL2PD":
		return c.lowerLegacyPackedIntegerToFloat(rawOp, ins)
	default:
		return false, false, nil
	}
}

func (c *amd64Ctx) lowerLegacyScalarIntegerToFloat(op string, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !isAMD64XReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("%s %s expects GP-or-memory source and X destination: %q", c.goarch, op, ins.Raw)
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		if !c.isGoYrlRegister(source) {
			return true, false, fmt.Errorf("%s %s expects GP-or-memory source: %q", c.goarch, op, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s expects GP-or-memory source: %q", c.goarch, op, ins.Raw)
	}
	bits := 32
	if strings.Contains(op, "Q2") {
		bits = 64
		if c.goarch == "386" {
			return true, false, fmt.Errorf("386 %s is an illegal 64-bit form: %q", op, ins.Raw)
		}
	}
	integerType := amd64IntegerTypeForBits(bits)
	value, err := c.evalIntSized(source, integerType)
	if err != nil {
		return true, false, err
	}
	floatType := LLVMType("float")
	if strings.HasSuffix(op, "SD") {
		floatType = LLVMType("double")
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sitofp %s %s to %s\n", converted, integerType, value, floatType)
	if floatType == LLVMType("float") {
		return true, false, c.storeXLowF32(ins.Args[1].Reg, "%"+converted)
	}
	return true, false, c.storeXLowF64(ins.Args[1].Reg, "%"+converted)
}

func (c *amd64Ctx) lowerLegacyPackedIntegerToFloat(op string, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !isAMD64XReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("amd64 %s expects X/MMX-or-memory source and X destination: %q", op, ins.Raw)
	}
	source := ins.Args[0]
	sourceIsX := source.Kind == OpReg && isAMD64XReg(source.Reg)
	sourceIsM := false
	if source.Kind == OpReg {
		_, sourceIsM = amd64ParseMReg(source.Reg)
	}
	if !sourceIsX && !sourceIsM && !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("amd64 %s expects X/MMX-or-memory source: %q", op, ins.Raw)
	}

	if op == "CVTPL2PS" && !sourceIsM {
		bytesValue, err := c.loadXVecOperand(source)
		if err != nil {
			return true, false, err
		}
		integers := c.newTmp()
		floats := c.newTmp()
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", integers, bytesValue)
		fmt.Fprintf(c.b, "  %%%s = sitofp <4 x i32> %%%s to <4 x float>\n", floats, integers)
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", out, floats)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
	}

	var pair string
	if sourceIsX {
		bytesValue, err := c.loadX(source.Reg)
		if err != nil {
			return true, false, err
		}
		all := c.newTmp()
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", all, bytesValue)
		fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i32> %%%s, <4 x i32> zeroinitializer, <2 x i32> <i32 0, i32 1>\n", low, all)
		pair = "%" + low
	} else {
		bits, err := c.evalIntSized(source, I64)
		if err != nil {
			return true, false, err
		}
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <2 x i32>\n", low, bits)
		pair = "%" + low
	}

	if op == "CVTPL2PD" {
		converted := c.newTmp()
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sitofp <2 x i32> %s to <2 x double>\n", converted, pair)
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x double> %%%s to <16 x i8>\n", out, converted)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
	}

	// The MMX CVTPI2PS form replaces only the low two float lanes and keeps
	// the high half of the X destination.
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sitofp <2 x i32> %s to <2 x float>\n", converted, pair)
	oldBytes, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	old := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", old, oldBytes)
	result := "%" + old
	for lane := 0; lane < 2; lane++ {
		value := c.newTmp()
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x float> %%%s, i32 %d\n", value, converted, lane)
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x float> %s, float %%%s, i32 %d\n", next, result, value, lane)
		result = "%" + next
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %s to <16 x i8>\n", out, result)
	return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
}
