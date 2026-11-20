package plan9asm

import (
	"fmt"
	"strconv"
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
	form, recognized, err := x86PackedRotateProperties(op, ins, c.goarch)
	if !recognized || err != nil {
		return recognized, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	var mask string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	return c.emitPackedRotateInstruction(form, ins, mask)
}

func (c *amd64Ctx) emitPackedRotateInstruction(form x86PackedRotateForm, ins Instr, mask string) (bool, bool, error) {
	spec, byteWidth := form.spec, form.byteWidth
	dstArg := ins.Args[form.destination]
	lanes := byteWidth * 8 / spec.laneBits
	// EVEX E4 suppresses inactive memory lanes, not merely their results.
	// The shared reader retains exact volatile active reads and broadcasts.
	first, err := c.loadX86PackedShiftLanes(ins.Args[form.first], byteWidth, spec.laneBits, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	var data, counts string
	if spec.variable {
		counts = first
		data, err = c.loadPackedCompareLanes(ins.Args[form.second], byteWidth, spec.laneBits, false)
	} else {
		data = first
		counts = amd64SplatInteger(c, lanes, spec.laneBits, strconv.Itoa(int(form.immediate)&(spec.laneBits-1)))
	}
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedRotate(lanes, spec.laneBits, data, counts, spec.left)
	if mask != "" {
		old := "zeroinitializer"
		if !form.zeroing {
			oldBytes, err := c.loadPackedCompareBytes(dstArg, byteWidth)
			if err != nil {
				return true, false, err
			}
			old = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(dstArg, byteWidth, "%"+out)
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
