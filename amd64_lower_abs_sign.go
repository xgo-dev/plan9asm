package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedAbsSuffix struct {
	broadcast bool
	zeroing   bool
}

func parseAMD64PackedAbsSuffix(rawOp, baseOp string) (amd64PackedAbsSuffix, error) {
	var result amd64PackedAbsSuffix
	if rawOp == baseOp {
		return result, nil
	}
	suffixes := strings.Split(strings.TrimPrefix(rawOp, baseOp+"."), ".")
	for index, suffix := range suffixes {
		switch suffix {
		case "BCST":
			if result.broadcast || result.zeroing || index != 0 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .BCST suffix", baseOp)
			}
			result.broadcast = true
		case "Z":
			if result.zeroing || index != len(suffixes)-1 {
				return result, fmt.Errorf("amd64 %s has invalid or misplaced .Z suffix", baseOp)
			}
			result.zeroing = true
		default:
			return result, fmt.Errorf("amd64 %s has unsupported suffix .%s", baseOp, suffix)
		}
	}
	return result, nil
}

// lowerPackedAbsSign implements Go 1.27's complete PABS*, VPABS*, PSIGN*,
// and VPSIGN* families. VPABS B/W/D share _yvmovddup, VPABSQ uses
// _yvexpandpd, and VPSIGN B/W/D are the two-width VEX-only _yvaddsubpd rows.
func (c *amd64Ctx) lowerPackedAbsSign(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	if laneBits, matched := amd64PackedAbsLaneBits(baseOp); matched {
		properties, err := parseAMD64PackedAbsSuffix(rawOp, baseOp)
		if err != nil {
			return true, false, fmt.Errorf("%w: %q", err, ins.Raw)
		}
		return c.lowerPackedAbs(baseOp, laneBits, ins, properties)
	}
	if laneBits, vector, matched := amd64PackedSignLaneBits(baseOp); matched {
		if rawOp != baseOp {
			return true, false, fmt.Errorf("amd64 %s does not accept suffixes: %q", baseOp, ins.Raw)
		}
		return c.lowerPackedSign(baseOp, laneBits, vector, ins)
	}
	return false, false, nil
}

func amd64PackedAbsLaneBits(op string) (int, bool) {
	switch op {
	case "PABSB", "VPABSB":
		return 8, true
	case "PABSW", "VPABSW":
		return 16, true
	case "PABSD", "VPABSD":
		return 32, true
	case "VPABSQ":
		return 64, true
	default:
		return 0, false
	}
}

func amd64PackedSignLaneBits(op string) (laneBits int, vector bool, matched bool) {
	switch op {
	case "PSIGNB", "VPSIGNB":
		laneBits = 8
	case "PSIGNW", "VPSIGNW":
		laneBits = 16
	case "PSIGND", "VPSIGND":
		laneBits = 32
	default:
		return 0, false, false
	}
	return laneBits, strings.HasPrefix(op, "V"), true
}

func (c *amd64Ctx) lowerPackedAbs(baseOp string, laneBits int, ins Instr, properties amd64PackedAbsSuffix) (bool, bool, error) {
	vector := strings.HasPrefix(baseOp, "V")
	if !vector {
		if properties != (amd64PackedAbsSuffix{}) || len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects X/m128 source and X destination: %q", baseOp, ins.Raw)
		}
		if !c.isGoLegacyPackedAbsSignRegister(ins.Args[1]) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's X register class: %q", c.goarch, baseOp, ins.Raw)
		}
		if (ins.Args[0].Kind == OpReg && !c.isGoLegacyPackedAbsSignRegister(ins.Args[0])) ||
			(ins.Args[0].Kind != OpReg && !isAMD64MemoryOperand(ins.Args[0])) {
			return true, false, fmt.Errorf("%s %s source must be an in-range X register or memory: %q", c.goarch, baseOp, ins.Raw)
		}
		values, err := c.loadPackedCompareLanes(ins.Args[0], 16, laneBits, false)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedAbs(values, 16, laneBits)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, 128/laneBits, laneBits, result)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
	}

	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 %s expects source, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z requires K1-K7: %q", baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
	}
	if properties.broadcast && laneBits != 32 && laneBits != 64 {
		return true, false, fmt.Errorf("amd64 %s has no Go 1.27 broadcast form: %q", baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s destination must be X, Y, or Z: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's vector class: %q", baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if properties.broadcast {
		if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("amd64 %s.BCST requires a memory source: %q", baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s source width does not match its destination: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("amd64 %s source must be a matching vector register or memory: %q", baseOp, ins.Raw)
	}
	values, err := c.loadPackedCompareLanes(source, byteWidth, laneBits, properties.broadcast)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedAbs(values, byteWidth, laneBits)
	lanes := byteWidth * 8 / laneBits
	if masked {
		mask, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPackedAbs(values string, byteWidth, laneBits int) string {
	lanes := byteWidth * 8 / laneBits
	negative := c.newTmp()
	negated := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt <%d x i%d> %s, zeroinitializer\n", negative, lanes, laneBits, values)
	fmt.Fprintf(c.b, "  %%%s = sub <%d x i%d> zeroinitializer, %s\n", negated, lanes, laneBits, values)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %%%s, <%d x i%d> %s\n", result, lanes, negative, lanes, laneBits, negated, lanes, laneBits, values)
	return "%" + result
}

func (c *amd64Ctx) lowerPackedSign(baseOp string, laneBits int, vector bool, ins Instr) (bool, bool, error) {
	wantArgs := 2
	if vector {
		wantArgs = 3
	}
	if len(ins.Args) != wantArgs {
		return true, false, fmt.Errorf("amd64 %s expects %d operands: %q", baseOp, wantArgs, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s destination must be X or Y: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if vector {
		if byteWidth != 16 && byteWidth != 32 || !c.isGoVEXPackedAbsSignRegister(destination, byteWidth) || !c.isGoVEXPackedAbsSignRegister(ins.Args[1], byteWidth) {
			return true, false, fmt.Errorf("%s %s requires matching in-range X or Y data registers: %q", c.goarch, baseOp, ins.Raw)
		}
	} else {
		byteWidth = 16
		if !c.isGoLegacyPackedAbsSignRegister(destination) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's X register class: %q", c.goarch, baseOp, ins.Raw)
		}
	}
	control := ins.Args[0]
	if control.Kind == OpReg {
		valid := c.isGoVEXPackedAbsSignRegister(control, byteWidth)
		if !vector {
			valid = c.isGoLegacyPackedAbsSignRegister(control)
		}
		if !valid {
			return true, false, fmt.Errorf("%s %s control source is outside Go 1.27's register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(control) {
		return true, false, fmt.Errorf("amd64 %s control source must be a matching vector or memory: %q", baseOp, ins.Raw)
	}
	controlValues, err := c.loadPackedCompareLanes(control, byteWidth, laneBits, false)
	if err != nil {
		return true, false, err
	}
	dataOperand := destination
	if vector {
		dataOperand = ins.Args[1]
	}
	dataValues, err := c.loadPackedCompareLanes(dataOperand, byteWidth, laneBits, false)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / laneBits
	positive := c.newTmp()
	negative := c.newTmp()
	negated := c.newTmp()
	nonpositive := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp sgt <%d x i%d> %s, zeroinitializer\n", positive, lanes, laneBits, controlValues)
	fmt.Fprintf(c.b, "  %%%s = icmp slt <%d x i%d> %s, zeroinitializer\n", negative, lanes, laneBits, controlValues)
	fmt.Fprintf(c.b, "  %%%s = sub <%d x i%d> zeroinitializer, %s\n", negated, lanes, laneBits, dataValues)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %%%s, <%d x i%d> zeroinitializer\n", nonpositive, lanes, negative, lanes, laneBits, negated, lanes, laneBits)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %s, <%d x i%d> %%%s\n", result, lanes, positive, lanes, laneBits, dataValues, lanes, laneBits, nonpositive)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) isGoLegacyPackedAbsSignRegister(operand Operand) bool {
	if !amd64VEXVectorRegister(operand, 16) {
		return false
	}
	index, _ := amd64ParseXReg(operand.Reg)
	return c.goarch != "386" || index < 8
}

func (c *amd64Ctx) isGoVEXPackedAbsSignRegister(operand Operand, byteWidth int) bool {
	return amd64VEXVectorRegister(operand, byteWidth)
}
