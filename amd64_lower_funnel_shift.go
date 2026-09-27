package plan9asm

import (
	"fmt"
	"strings"
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
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64FunnelShiftSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.sae || properties.rounding != "" {
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's funnel-shift encoding: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.laneBits == 16 && properties.broadcast {
		return true, false, fmt.Errorf("%s %s word forms do not enable EVEX broadcast: %q", c.goarch, baseOp, ins.Raw)
	}

	unmaskedArgs := 4
	maskedArgs := 5
	if spec.variable {
		unmaskedArgs, maskedArgs = 3, 4
	}
	if len(ins.Args) != unmaskedArgs && len(ins.Args) != maskedArgs {
		return true, false, fmt.Errorf("%s %s has an operand count outside Go 1.27's encoding table: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == maskedArgs
	if !spec.variable && c.goarch == "386" {
		return true, false, fmt.Errorf("386 %s is rejected by the Go assembler frontend's operand limit: %q", baseOp, ins.Raw)
	}
	if spec.variable && c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}

	immediateOffset := 0
	if !spec.variable {
		if !amd64UnsignedImmediate(ins.Args[0], 8) {
			return true, false, fmt.Errorf("%s %s first operand must be Go 1.27's unsigned-imm8 class: %q", c.goarch, baseOp, ins.Raw)
		}
		immediateOffset = 1
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 ||
		!c.isGoPackedVectorMoveRegister(destination, byteWidth) ||
		!c.isGoPackedVectorMoveRegister(ins.Args[immediateOffset+1], byteWidth) {
		return true, false, fmt.Errorf("%s %s second vector source and destination must be matching Go vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	rmSource := ins.Args[immediateOffset]
	if properties.broadcast {
		if !isAMD64MemoryOperand(rmSource) {
			return true, false, fmt.Errorf("%s %s.BCST requires a scalar memory first vector source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if rmSource.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(rmSource, byteWidth) {
			return true, false, fmt.Errorf("%s %s first vector source must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(rmSource) {
		return true, false, fmt.Errorf("%s %s first vector source must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	maskOperandIndex := len(ins.Args) - 2
	if masked && !amd64NonzeroKOperand(ins.Args[maskOperandIndex]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7 before the destination: %q", c.goarch, baseOp, ins.Raw)
	}

	lanes := byteWidth * 8 / spec.laneBits
	first, err := c.loadPackedCompareLanes(rmSource, byteWidth, spec.laneBits, properties.broadcast)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedCompareLanes(ins.Args[immediateOffset+1], byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	old := ""
	if spec.variable || masked {
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
	if masked {
		mask, loadErr := c.loadK(ins.Args[maskOperandIndex].Reg)
		if loadErr != nil {
			return true, false, loadErr
		}
		computed = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computed, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, vectorType, computed, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}
