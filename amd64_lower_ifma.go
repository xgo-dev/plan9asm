package plan9asm

import (
	"fmt"
)

type amd64IFMASpec struct {
	x86PackedBinarySpec
	high bool
}

// amd64IFMASpecs is the complete Go 1.27 integer fused multiply-add family.
// Both instructions use _yvblendmpd and operate on the low unsigned 52 bits
// of each qword source. LUQ adds product bits 51:0; HUQ adds bits 103:52.
var amd64IFMASpecs = map[Op]amd64IFMASpec{
	"VPMADD52HUQ": {
		x86PackedBinarySpec: x86PackedBinarySpec{
			encoding: x86PackedLogicalEVEX, broadcastBytes: 8, zeroing: true,
		},
		high: true,
	},
	"VPMADD52LUQ": {
		x86PackedBinarySpec: x86PackedBinarySpec{
			encoding: x86PackedLogicalEVEX, broadcastBytes: 8, zeroing: true,
		},
	},
}

func (c *amd64Ctx) lowerIFMA(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86IFMAProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	source, destination := ins.Args[form.first], ins.Args[form.destination]
	if form.memory >= 0 {
		if source.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(source, c.goarch) &&
			!x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			return true, false, fmt.Errorf("%w: IFMA source needs its original native storage binding", ErrProbeNeedsContext)
		}
		if source.Kind == OpFP {
			if err := c.validateX86PackedShiftFPSpan(source.FPOffset, form.memoryBytes); err != nil {
				return true, false, err
			}
		}
	}
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	first, err := c.loadX86PackedShiftLanes(source, form.byteWidth, 64, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedCompareLanes(ins.Args[form.second], form.byteWidth, 64, false)
	if err != nil {
		return true, false, err
	}
	oldBytes, err := c.loadPackedCompareBytes(destination, form.byteWidth)
	if err != nil {
		return true, false, err
	}
	lanes := form.byteWidth / 8
	old := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, 64, oldBytes)
	computed := c.emitIFMA(form.spec, lanes, first, second, old)
	if form.mask >= 0 {
		computed = amd64ApplyIntegerLaneMask(c, lanes, 64, computed, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", out, lanes, computed, form.byteWidth)
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}

func (c *amd64Ctx) emitIFMA(spec amd64IFMASpec, lanes int, first, second, accumulator string) string {
	const low52Mask = "4503599627370495"
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		firstLane := c.newTmp()
		secondLane := c.newTmp()
		oldLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i32 %d\n", firstLane, lanes, first, lane)
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i32 %d\n", secondLane, lanes, second, lane)
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i32 %d\n", oldLane, lanes, accumulator, lane)
		maskedFirst := c.newTmp()
		maskedSecond := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %s\n", maskedFirst, firstLane, low52Mask)
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %s\n", maskedSecond, secondLane, low52Mask)
		wideFirst := c.newTmp()
		wideSecond := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %%%s to i128\n", wideFirst, maskedFirst)
		fmt.Fprintf(c.b, "  %%%s = zext i64 %%%s to i128\n", wideSecond, maskedSecond)
		product := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i128 %%%s, %%%s\n", product, wideFirst, wideSecond)
		selected := "%" + product
		if spec.high {
			high := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 52\n", high, product)
			selected = "%" + high
		} else {
			low := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i128 %%%s, %s\n", low, product, low52Mask)
			selected = "%" + low
		}
		productPart := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %s to i64\n", productPart, selected)
		added := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", added, oldLane, productPart)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %%%s, i32 %d\n", inserted, lanes, result, added, lane)
		result = "%" + inserted
	}
	return result
}
