package plan9asm

import (
	"fmt"
)

type amd64FunnelShiftSpec struct {
	laneBits int
	left     bool
	variable bool
}

// amd64FunnelShiftSpecs is the complete Go 1.27 VBMI2 funnel-shift family:
// left/right, immediate/per-lane counts, and word/dword/qword lanes.
var amd64FunnelShiftSpecs = map[Op]amd64FunnelShiftSpec{
	"VPSHLDW":  {laneBits: 16, left: true},
	"VPSHLDD":  {laneBits: 32, left: true},
	"VPSHLDQ":  {laneBits: 64, left: true},
	"VPSHLDVW": {laneBits: 16, left: true, variable: true},
	"VPSHLDVD": {laneBits: 32, left: true, variable: true},
	"VPSHLDVQ": {laneBits: 64, left: true, variable: true},
	"VPSHRDW":  {laneBits: 16},
	"VPSHRDD":  {laneBits: 32},
	"VPSHRDQ":  {laneBits: 64},
	"VPSHRDVW": {laneBits: 16, variable: true},
	"VPSHRDVD": {laneBits: 32, variable: true},
	"VPSHRDVQ": {laneBits: 64, variable: true},
}

func (c *amd64Ctx) lowerFunnelShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86FunnelShiftProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	spec, byteWidth := form.spec, form.byteWidth
	destination := ins.Args[form.destination]
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	lanes := byteWidth * 8 / spec.laneBits
	// Every VBMI2 member is E4: retain exact volatile active-lane reads,
	// including discarded data/counts, and suppress only masked-off lanes.
	first, err := c.loadX86PackedShiftLanes(ins.Args[form.first], byteWidth, spec.laneBits, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedCompareLanes(ins.Args[form.second], byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	old := "zeroinitializer"
	if spec.variable || form.mask >= 0 && !form.zeroing {
		oldBytes, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		old = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
	}

	count := first
	leftInput, rightInput := old, second
	if !spec.variable {
		count = amd64SplatInteger(c, lanes, spec.laneBits, fmt.Sprintf("%d", uint8(ins.Args[0].Imm)))
		leftInput, rightInput = second, first
	}
	intrinsic := "fshl"
	firstArgument, secondArgument := leftInput, rightInput
	if !spec.left {
		intrinsic = "fshr"
		firstArgument, secondArgument = rightInput, leftInput
	}
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	computedName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.v%di%d(%s %s, %s %s, %s %s)\n",
		computedName, vectorType, intrinsic, lanes, spec.laneBits,
		vectorType, firstArgument, vectorType, secondArgument, vectorType, count)
	computed := "%" + computedName
	if form.mask >= 0 {
		computed = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computed, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, vectorType, computed, byteWidth)
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
}
