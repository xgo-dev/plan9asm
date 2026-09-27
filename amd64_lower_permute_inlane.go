package plan9asm

import (
	"fmt"
	"strings"
)

// lowerInLaneFloatingPermute implements the complete Go 1.27 _yvpermilpd
// operand family shared by VPERMILPD and VPERMILPS. The permutation preserves
// element bits and never selects across a 128-bit lane.
func (c *amd64Ctx) lowerInLaneFloatingPermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits := 0
	switch baseOp {
	case "VPERMILPD":
		laneBits = 64
	case "VPERMILPS":
		laneBits = 32
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
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's _yvpermilpd encodings: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects control/data, data, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	immediate := ins.Args[0].Kind == OpImm
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoInLanePermuteRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's vector-register class: %q", c.goarch, baseOp, ins.Raw)
	}

	rmArg := ins.Args[0]
	dataArg := ins.Args[1]
	var imm uint8
	if immediate {
		rmArg = ins.Args[1]
		value := ins.Args[0].Imm
		if value < -128 || value > 255 {
			return true, false, fmt.Errorf("%s %s immediate is outside Go 1.27's signed-or-unsigned imm8 classes: %q", c.goarch, baseOp, ins.Raw)
		}
		imm = uint8(value)
		if value < 0 {
			vex := !masked && suffix == "" && byteWidth != 64 && amd64VEXVectorRegister(destination, byteWidth)
			if rmArg.Kind == OpReg {
				vex = vex && amd64VEXVectorRegister(rmArg, byteWidth)
			}
			if !vex {
				return true, false, fmt.Errorf("%s %s signed imm8 exists only in its VEX X/Y rows: %q", c.goarch, baseOp, ins.Raw)
			}
		}
	} else if !c.isGoInLanePermuteRegister(dataArg, byteWidth) {
		return true, false, fmt.Errorf("%s %s data source must match the destination width: %q", c.goarch, baseOp, ins.Raw)
	}

	if broadcast {
		if !isAMD64MemoryOperand(rmArg) {
			return true, false, fmt.Errorf("%s %s.BCST requires a memory r/m source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if rmArg.Kind == OpReg {
		if !c.isGoInLanePermuteRegister(rmArg, byteWidth) {
			return true, false, fmt.Errorf("%s %s r/m register must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(rmArg) {
		return true, false, fmt.Errorf("%s %s r/m source must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	lanes := byteWidth * 8 / laneBits
	var data, control string
	if immediate {
		if broadcast {
			scalar, err := c.evalIntSized(rmArg, amd64IntegerTypeForBits(laneBits))
			if err != nil {
				return true, false, err
			}
			data = amd64SplatInteger(c, lanes, laneBits, scalar)
		} else {
			bytes, err := c.loadPackedCompareBytes(rmArg, byteWidth)
			if err != nil {
				return true, false, err
			}
			data = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, bytes)
		}
	} else {
		dataBytes, err := c.loadPackedCompareBytes(dataArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		data = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, dataBytes)
		if broadcast {
			scalar, err := c.evalIntSized(rmArg, amd64IntegerTypeForBits(laneBits))
			if err != nil {
				return true, false, err
			}
			control = amd64SplatInteger(c, lanes, laneBits, scalar)
		} else {
			controlBytes, err := c.loadPackedCompareBytes(rmArg, byteWidth)
			if err != nil {
				return true, false, err
			}
			control = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, controlBytes)
		}
	}

	var result string
	if immediate {
		result = c.emitImmediateInLanePermute(data, lanes, laneBits, imm)
	} else {
		result = c.emitVariableInLanePermute(data, control, lanes, laneBits)
	}
	if masked {
		mask, err := c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) isGoInLanePermuteRegister(arg Operand, byteWidth int) bool {
	if !amd64EVEXVectorRegister(arg, byteWidth) {
		return false
	}
	if c.goarch == "386" && byteWidth == 64 {
		index, _ := amd64VectorRegisterIndex(arg.Reg, byteWidth)
		return index < 8
	}
	return true
}

func (c *amd64Ctx) emitImmediateInLanePermute(data string, lanes, laneBits int, imm uint8) string {
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		var sourceLane int
		if laneBits == 32 {
			groupBase := lane / 4 * 4
			sourceLane = groupBase + int(imm>>uint(2*(lane%4)))&3
		} else {
			groupBase := lane / 2 * 2
			sourceLane = groupBase + int(imm>>uint(lane))&1
		}
		value := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", value, lanes, laneBits, data, sourceLane)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, laneBits, result, laneBits, value, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitVariableInLanePermute(data, control string, lanes, laneBits int) string {
	result := "poison"
	groupLanes := 128 / laneBits
	for lane := 0; lane < lanes; lane++ {
		controlLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", controlLane, lanes, laneBits, control, lane)
		selectorValue := "%" + controlLane
		if laneBits == 64 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 1\n", shifted, controlLane)
			selectorValue = "%" + shifted
		}
		selector := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %s, %d\n", selector, laneBits, selectorValue, groupLanes-1)
		index := "%" + selector
		groupBase := lane / groupLanes * groupLanes
		if groupBase != 0 {
			withBase := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i%d %%%s, %d\n", withBase, laneBits, selector, groupBase)
			index = "%" + withBase
		}
		value := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i%d %s\n", value, lanes, laneBits, data, laneBits, index)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, laneBits, result, laneBits, value, lane)
		result = "%" + inserted
	}
	return result
}
