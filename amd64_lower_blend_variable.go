package plan9asm

import (
	"fmt"
)

type amd64VariableBlendSpec struct {
	laneBits int
	vector   bool
	opcode   int
}

// Go's yblendvpd and _yvblendvpd differ only in implicit/explicit mask,
// destructive/non-destructive destination and the available vector widths.
// The VEX raw decoder consumes the same opcode table as named lowering.
var amd64VariableBlendSpecs = map[Op]amd64VariableBlendSpec{
	"BLENDVPS":  {laneBits: 32, opcode: 0x14},
	"BLENDVPD":  {laneBits: 64, opcode: 0x15},
	"PBLENDVB":  {laneBits: 8, opcode: 0x10},
	"VBLENDVPS": {laneBits: 32, vector: true, opcode: 0x4a},
	"VBLENDVPD": {laneBits: 64, vector: true, opcode: 0x4b},
	"VPBLENDVB": {laneBits: 8, vector: true, opcode: 0x4c},
}

// lowerVariableBlend implements Go 1.27's complete yblendvpd and _yvblendvpd
// families. Each opcode tests the high bit of its mask lane: false selects the
// base/destination lane and true selects the register-or-memory source lane.
func (c *amd64Ctx) lowerVariableBlend(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, recognized, err := x86BlendMinposProperties(op, ins, c.goarch)
	if !recognized || form.minimum {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	laneBits, byteWidth := form.laneBits, form.byteWidth
	maskArg, source := ins.Args[form.mask], ins.Args[form.source]
	base, destination := ins.Args[form.base], ins.Args[form.destination]
	if form.legacy && form.memory {
		return true, false, c.lowerLegacyBlendMinposMemory(ins, form)
	}
	maskBytes, err := c.loadPackedCompareBytes(maskArg, byteWidth)
	if err != nil {
		return true, false, err
	}
	sourceBytes, err := c.loadX86PackedShiftBytes(source, byteWidth, true)
	if err != nil {
		return true, false, err
	}
	baseBytes, err := c.loadPackedCompareBytes(base, byteWidth)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / laneBits
	maskLanes := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, maskBytes)
	sourceLanes := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, sourceBytes)
	baseLanes := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, baseBytes)
	selectedMask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt <%d x i%d> %s, zeroinitializer\n", selectedMask, lanes, laneBits, maskLanes)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %s, <%d x i%d> %s\n", result, lanes, selectedMask, lanes, laneBits, sourceLanes, lanes, laneBits, baseLanes)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	if !form.legacy {
		return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
	}
	return true, false, c.storeLegacyXViews(destination.Reg, "%"+out)
}
