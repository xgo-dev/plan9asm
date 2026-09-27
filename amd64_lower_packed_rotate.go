package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type amd64PackedRotateSpec struct {
	laneBits int
	left     bool
	variable bool
}

// amd64PackedRotateSpecs covers Go 1.27's complete _yvprold immediate and
// _yvblendmpd per-lane variable rotate families.
var amd64PackedRotateSpecs = map[Op]amd64PackedRotateSpec{
	"VPROLD":  {laneBits: 32, left: true},
	"VPROLQ":  {laneBits: 64, left: true},
	"VPRORD":  {laneBits: 32},
	"VPRORQ":  {laneBits: 64},
	"VPROLVD": {laneBits: 32, left: true, variable: true},
	"VPROLVQ": {laneBits: 64, left: true, variable: true},
	"VPRORVD": {laneBits: 32, variable: true},
	"VPRORVQ": {laneBits: 64, variable: true},
}

func (c *amd64Ctx) lowerPackedRotate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64PackedRotateSpecs[Op(baseOp)]
	if !recognized {
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
		return true, false, fmt.Errorf("%s %s has a suffix absent from Go 1.27's EVEX encoding: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s has an operand count absent from its Go 1.27 table: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed Go 1.27's assembler operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}

	firstIndex := 0
	if !spec.variable {
		if ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
			return true, false, fmt.Errorf("%s %s first operand must be Go 1.27's unsigned-imm8 class: %q", c.goarch, baseOp, ins.Raw)
		}
		firstIndex = 1
	}
	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be an X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if (byteWidth != 16 && byteWidth != 32 && byteWidth != 64) || !c.isGoEVEXVectorRegister(dstArg, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's EVEX vector class: %q", c.goarch, baseOp, ins.Raw)
	}

	firstArg := ins.Args[firstIndex]
	if broadcast {
		if !isAMD64MemoryOperand(firstArg) {
			return true, false, fmt.Errorf("%s %s.BCST requires a memory first source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if firstArg.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(firstArg, byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match the destination width and register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(firstArg) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.variable && !c.isGoEVEXVectorRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s data source must be a same-width EVEX vector register: %q", c.goarch, baseOp, ins.Raw)
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

	return c.emitPackedRotateInstruction(baseOp, spec, ins, firstArg, dstArg, mask, broadcast, zeroing)
}

func (c *amd64Ctx) emitPackedRotateInstruction(baseOp string, spec amd64PackedRotateSpec, ins Instr, firstArg, dstArg Operand, mask string, broadcast, zeroing bool) (bool, bool, error) {
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	lanes := byteWidth * 8 / spec.laneBits
	loadLanes := func(arg Operand, allowBroadcast bool) (string, error) {
		if allowBroadcast && broadcast {
			scalar, err := c.evalIntSized(arg, amd64IntegerTypeForBits(spec.laneBits))
			if err != nil {
				return "", err
			}
			return amd64SplatInteger(c, lanes, spec.laneBits, scalar), nil
		}
		bytesValue, err := c.loadPackedCompareBytes(arg, byteWidth)
		if err != nil {
			return "", err
		}
		return c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, bytesValue), nil
	}

	var data, counts string
	var err error
	if spec.variable {
		counts, err = loadLanes(firstArg, true)
		if err == nil {
			data, err = loadLanes(ins.Args[1], false)
		}
	} else {
		data, err = loadLanes(firstArg, true)
		counts = amd64SplatInteger(c, lanes, spec.laneBits, strconv.Itoa(int(ins.Args[0].Imm)&(spec.laneBits-1)))
	}
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedRotate(lanes, spec.laneBits, data, counts, spec.left)
	if mask != "" {
		oldBytes, err := c.loadPackedCompareBytes(dstArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	if err := c.storeVectorBytes(dstArg.Reg, byteWidth, "%"+out); err != nil {
		return true, false, fmt.Errorf("%s %s destination: %w", c.goarch, baseOp, err)
	}
	return true, false, nil
}

func (c *amd64Ctx) emitPackedRotate(lanes, laneBits int, data, counts string, left bool) string {
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	laneMask := amd64SplatInteger(c, lanes, laneBits, strconv.Itoa(laneBits-1))
	normalized := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", normalized, vectorType, counts, laneMask)
	negated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s zeroinitializer, %%%s\n", negated, vectorType, normalized)
	inverse := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", inverse, vectorType, negated, laneMask)

	low, high := c.newTmp(), c.newTmp()
	if left {
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", low, vectorType, data, normalized)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", high, vectorType, data, inverse)
	} else {
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", low, vectorType, data, normalized)
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", high, vectorType, data, inverse)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", result, vectorType, low, high)
	return "%" + result
}
