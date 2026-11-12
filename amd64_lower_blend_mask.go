package plan9asm

import "fmt"

type amd64MaskBlendSpec struct {
	laneBits  int
	broadcast bool
}

// amd64MaskBlendSpecs is the complete shared _yvblendmpd grammar for the
// floating-point and integer mask-blend families.
var amd64MaskBlendSpecs = map[Op]amd64MaskBlendSpec{
	"VBLENDMPS": {laneBits: 32, broadcast: true},
	"VBLENDMPD": {laneBits: 64, broadcast: true},
	"VPBLENDMB": {laneBits: 8},
	"VPBLENDMW": {laneBits: 16},
	"VPBLENDMD": {laneBits: 32, broadcast: true},
	"VPBLENDMQ": {laneBits: 64, broadcast: true},
}

// lowerMaskBlend implements Go 1.27's complete _yvblendmpd operand table for
// VBLENDM{PS,PD} and VPBLENDM{B,W,D,Q}. A set K bit selects the first Plan 9
// (Intel r/m) source; an unset bit selects the second source, or zero for .Z.
func (c *amd64Ctx) lowerMaskBlend(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86MaskBlendProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	// E4 suppresses only inactive memory elements. The shared volatile reader
	// retains active faults even when all result bytes are discarded after O2.
	first, err := c.loadX86PackedShiftLanes(ins.Args[form.first], form.byteWidth, form.spec.laneBits, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	result := first
	lanes := form.byteWidth * 8 / form.spec.laneBits
	if form.mask >= 0 {
		second := "zeroinitializer"
		if !form.zeroing {
			second, err = c.loadPackedCompareLanes(ins.Args[form.second], form.byteWidth, form.spec.laneBits, false)
			if err != nil {
				return true, false, err
			}
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, form.spec.laneBits, first, second, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, form.spec.laneBits, result, form.byteWidth)
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, "%"+out)
}
