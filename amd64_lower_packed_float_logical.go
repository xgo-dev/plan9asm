package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedFloatingLogicalSpec struct {
	laneBits int
	mode     amd64PackedLogicalMode
	vector   bool
}

// amd64PackedFloatingLogicalSpecs is the complete Go 1.27 packed floating
// logical family. The eight legacy instructions use yxm. Their V-prefixed
// counterparts use _yvandnpd, which provides the common VEX/EVEX X/Y/Z,
// masking, zeroing, and scalar-broadcast forms.
var amd64PackedFloatingLogicalSpecs = map[Op]amd64PackedFloatingLogicalSpec{
	"ANDPS":   {laneBits: 32, mode: amd64PackedLogicalAnd},
	"ANDPD":   {laneBits: 64, mode: amd64PackedLogicalAnd},
	"ANDNPS":  {laneBits: 32, mode: amd64PackedLogicalAndNot},
	"ANDNPD":  {laneBits: 64, mode: amd64PackedLogicalAndNot},
	"ORPS":    {laneBits: 32, mode: amd64PackedLogicalOr},
	"ORPD":    {laneBits: 64, mode: amd64PackedLogicalOr},
	"XORPS":   {laneBits: 32, mode: amd64PackedLogicalXor},
	"XORPD":   {laneBits: 64, mode: amd64PackedLogicalXor},
	"VANDPS":  {laneBits: 32, mode: amd64PackedLogicalAnd, vector: true},
	"VANDPD":  {laneBits: 64, mode: amd64PackedLogicalAnd, vector: true},
	"VANDNPS": {laneBits: 32, mode: amd64PackedLogicalAndNot, vector: true},
	"VANDNPD": {laneBits: 64, mode: amd64PackedLogicalAndNot, vector: true},
	"VORPS":   {laneBits: 32, mode: amd64PackedLogicalOr, vector: true},
	"VORPD":   {laneBits: 64, mode: amd64PackedLogicalOr, vector: true},
	"VXORPS":  {laneBits: 32, mode: amd64PackedLogicalXor, vector: true},
	"VXORPD":  {laneBits: 64, mode: amd64PackedLogicalXor, vector: true},
}

func (c *amd64Ctx) lowerPackedFloatingLogical(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64PackedFloatingLogicalSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if !spec.vector {
		if suffix != "" {
			return true, false, fmt.Errorf("%s %s has a suffix absent from Go 1.27's yxm table: %q", c.goarch, baseOp, ins.Raw)
		}
		return c.lowerLegacyPackedFloatingLogical(baseOp, spec, ins)
	}
	return c.lowerVectorPackedFloatingLogical(baseOp, suffix, spec, ins)
}

func (c *amd64Ctx) lowerLegacyPackedFloatingLogical(baseOp string, spec amd64PackedFloatingLogicalSpec, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !c.isGoLegacyXReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("%s %s expects X/m128, X using Go 1.27's legacy X class: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's legacy X class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s source must be X or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	firstBytes, err := c.loadPackedCompareBytes(ins.Args[0], 16)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / spec.laneBits
	first := c.bitcastVectorBytesToIntegerLanes(16, lanes, spec.laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, lanes, spec.laneBits, secondBytes)
	result := c.emitPackedLogical(lanes, amd64PackedLogicalSpec{laneBits: spec.laneBits, mode: spec.mode}, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, spec.laneBits, result)
	return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedFloatingLogical(baseOp, suffix string, spec amd64PackedFloatingLogicalSpec, ins Instr) (bool, bool, error) {
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
		return true, false, fmt.Errorf("%s %s has a suffix absent from Go 1.27's _yvandnpd table: %q", c.goarch, baseOp, ins.Raw)
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
		loadedMask, loadErr := c.loadK(ins.Args[2].Reg)
		if loadErr != nil {
			return true, false, loadErr
		}
		mask = loadedMask
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
	result := c.emitPackedLogical(lanes, amd64PackedLogicalSpec{laneBits: spec.laneBits, mode: spec.mode}, first, second)
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
