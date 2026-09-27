package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedLogicalMode uint8

const (
	amd64PackedLogicalAnd amd64PackedLogicalMode = iota
	amd64PackedLogicalAndNot
	amd64PackedLogicalOr
	amd64PackedLogicalXor
)

type amd64PackedLogicalSpec struct {
	laneBits int
	mode     amd64PackedLogicalMode
}

// amd64EVEXPackedLogicalSpecs is the complete Go 1.27 _yvblendmpd logical
// family. All eight instructions have identical X/Y/Z operand rows and differ
// only in lane width and Boolean operation.
var amd64EVEXPackedLogicalSpecs = map[Op]amd64PackedLogicalSpec{
	"VPANDD":  {laneBits: 32, mode: amd64PackedLogicalAnd},
	"VPANDQ":  {laneBits: 64, mode: amd64PackedLogicalAnd},
	"VPANDND": {laneBits: 32, mode: amd64PackedLogicalAndNot},
	"VPANDNQ": {laneBits: 64, mode: amd64PackedLogicalAndNot},
	"VPORD":   {laneBits: 32, mode: amd64PackedLogicalOr},
	"VPORQ":   {laneBits: 64, mode: amd64PackedLogicalOr},
	"VPXORD":  {laneBits: 32, mode: amd64PackedLogicalXor},
	"VPXORQ":  {laneBits: 64, mode: amd64PackedLogicalXor},
}

func (c *amd64Ctx) lowerEVEXPackedLogical(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64EVEXPackedLogicalSpecs[Op(baseOp)]
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
		return true, false, fmt.Errorf("%s %s expects src1, src2, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed Go 1.27's assembler operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}

	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be an X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if (byteWidth != 16 && byteWidth != 32 && byteWidth != 64) || !c.isGoEVEXVectorRegister(dstArg, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's EVEX vector class: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s second source must be a same-width EVEX vector register: %q", c.goarch, baseOp, ins.Raw)
	}
	if broadcast {
		if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s.BCST requires a memory first source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if ins.Args[0].Kind == OpReg {
		if !c.isGoEVEXVectorRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match the destination width and register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
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

	lanes := byteWidth * 8 / spec.laneBits
	loadLanes := func(arg Operand, allowBroadcast bool) (string, error) {
		if allowBroadcast && broadcast {
			scalar, loadErr := c.evalIntSized(arg, amd64IntegerTypeForBits(spec.laneBits))
			if loadErr != nil {
				return "", loadErr
			}
			return amd64SplatInteger(c, lanes, spec.laneBits, scalar), nil
		}
		bytesValue, loadErr := c.loadPackedCompareBytes(arg, byteWidth)
		if loadErr != nil {
			return "", loadErr
		}
		return c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, bytesValue), nil
	}
	first, err := loadLanes(ins.Args[0], true)
	if err != nil {
		return true, false, err
	}
	second, err := loadLanes(ins.Args[1], false)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedLogical(lanes, spec, first, second)
	if masked {
		oldBytes, loadErr := c.loadPackedCompareBytes(dstArg, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(dstArg.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPackedLogical(lanes int, spec amd64PackedLogicalSpec, first, second string) string {
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	if spec.mode == amd64PackedLogicalAndNot {
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", inverted, vectorType, second, llvmSplatInteger(lanes, spec.laneBits, ^uint64(0)))
		second = "%" + inverted
	}
	result := c.newTmp()
	llvmOp := "and"
	switch spec.mode {
	case amd64PackedLogicalOr:
		llvmOp = "or"
	case amd64PackedLogicalXor:
		llvmOp = "xor"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", result, llvmOp, vectorType, second, first)
	return "%" + result
}

func (c *amd64Ctx) isGoEVEXVectorRegister(op Operand, byteWidth int) bool {
	if !amd64EVEXVectorRegister(op, byteWidth) {
		return false
	}
	if c.goarch != "386" || byteWidth != 64 {
		return true
	}
	index, _ := amd64VectorRegisterIndex(op.Reg, byteWidth)
	return index < 8
}
