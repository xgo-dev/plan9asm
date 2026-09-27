package plan9asm

import (
	"fmt"
	"strings"
)

// lowerQwordPermute implements the complete Go 1.27 _yvpermq operand family
// shared by VPERMQ and VPERMPD. It includes immediate-control VEX/EVEX forms
// and variable-control EVEX forms; both preserve qword bits.
func (c *amd64Ctx) lowerQwordPermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	switch baseOp {
	case "VPERMQ", "VPERMPD":
	default:
		return false, false, nil
	}
	broadcast, zeroing := false, false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	case "BCST":
		broadcast = true
	case "BCST.Z":
		broadcast, zeroing = true, true
	default:
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's _yvpermq encodings: %q", c.goarch, baseOp, ins.Raw)
	}
	immediate := len(ins.Args) != 0 && ins.Args[0].Kind == OpImm
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects immediate/data, control, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be Y or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if byteWidth != 32 && byteWidth != 64 {
		return true, false, fmt.Errorf("%s %s destination must be Y or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoQwordPermuteVector(dstArg, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's vector range: %q", c.goarch, baseOp, ins.Raw)
	}

	dataArg := ins.Args[0]
	controlArg := ins.Args[1]
	var imm uint8
	if immediate {
		dataArg = ins.Args[1]
		value := ins.Args[0].Imm
		if value < -128 || value > 255 {
			return true, false, fmt.Errorf("%s %s immediate is outside Go 1.27's signed-or-unsigned imm8 classes: %q", c.goarch, baseOp, ins.Raw)
		}
		imm = uint8(value)
		if value < 0 {
			if masked || suffix != "" || byteWidth != 32 || !amd64VEXVectorRegister(dstArg, byteWidth) {
				return true, false, fmt.Errorf("%s %s signed imm8 exists only in the VEX Y form: %q", c.goarch, baseOp, ins.Raw)
			}
			if dataArg.Kind == OpReg && !amd64VEXVectorRegister(dataArg, byteWidth) {
				return true, false, fmt.Errorf("%s %s signed imm8 source is outside the VEX Y range: %q", c.goarch, baseOp, ins.Raw)
			}
		}
	} else if !c.isGoQwordPermuteVector(controlArg, byteWidth) {
		return true, false, fmt.Errorf("%s %s variable control and destination must be matching Y or Z registers: %q", c.goarch, baseOp, ins.Raw)
	}

	if broadcast {
		if !isAMD64MemoryOperand(dataArg) {
			return true, false, fmt.Errorf("%s %s.BCST requires a memory data source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if dataArg.Kind == OpReg {
		if !c.isGoQwordPermuteVector(dataArg, byteWidth) {
			return true, false, fmt.Errorf("%s %s data register must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(dataArg) {
		return true, false, fmt.Errorf("%s %s data must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	var mask string
	if masked {
		if !amd64NonzeroKOperand(ins.Args[2]) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
	}
	lanes := byteWidth / 8
	var data string
	if broadcast {
		scalar, err := c.evalIntSized(dataArg, I64)
		if err != nil {
			return true, false, err
		}
		data = amd64SplatInteger(c, lanes, 64, scalar)
	} else {
		dataBytes, err := c.loadPackedCompareBytes(dataArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		data = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, 64, dataBytes)
	}
	var result string
	if immediate {
		result = c.emitImmediateQwordPermute(data, lanes, imm)
	} else {
		controlBytes, err := c.loadPackedCompareBytes(controlArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		control := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, 64, controlBytes)
		result = c.emitVariableQwordPermute(data, control, lanes)
	}
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(dstArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, 64, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, 64, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", out, lanes, result, byteWidth)
	return true, false, c.storeVectorBytes(dstArg.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) isGoQwordPermuteVector(arg Operand, byteWidth int) bool {
	if !amd64EVEXVectorRegister(arg, byteWidth) {
		return false
	}
	if c.goarch == "386" && byteWidth == 64 {
		index, _ := amd64VectorRegisterIndex(arg.Reg, byteWidth)
		return index < 8
	}
	return true
}

func (c *amd64Ctx) emitImmediateQwordPermute(data string, lanes int, imm uint8) string {
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		groupBase := lane / 4 * 4
		selector := int(imm>>uint(2*(lane%4))) & 3
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i32 %d\n", value, lanes, data, groupBase+selector)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %%%s, i32 %d\n", inserted, lanes, result, value, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitVariableQwordPermute(data, control string, lanes int) string {
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		index := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i32 %d\n", index, lanes, control, lane)
		maskedIndex := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %d\n", maskedIndex, index, lanes-1)
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i64 %%%s\n", value, lanes, data, maskedIndex)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %%%s, i32 %d\n", inserted, lanes, result, value, lane)
		result = "%" + inserted
	}
	return result
}
