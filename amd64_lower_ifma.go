package plan9asm

import (
	"fmt"
	"strings"
)

type amd64IFMASpec struct {
	high bool
}

// amd64IFMASpecs is the complete Go 1.27 integer fused multiply-add family.
// Both instructions use _yvblendmpd and operate on the low unsigned 52 bits
// of each qword source. LUQ adds product bits 51:0; HUQ adds bits 103:52.
var amd64IFMASpecs = map[Op]amd64IFMASpec{
	"VPMADD52HUQ": {high: true},
	"VPMADD52LUQ": {},
}

func (c *amd64Ctx) lowerIFMA(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64IFMASpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}

	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.sae || properties.rounding != "" {
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's _yvblendmpd encoding: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects source2, source1, [K mask,] accumulator: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7 as its third operand: %q", c.goarch, baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s accumulator must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 ||
		!c.isGoPackedVectorMoveRegister(destination, byteWidth) ||
		!c.isGoPackedVectorMoveRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s source1 and accumulator must be matching Go vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	rmSource := ins.Args[0]
	if properties.broadcast {
		if !isAMD64MemoryOperand(rmSource) {
			return true, false, fmt.Errorf("%s %s.BCST requires a scalar memory source2: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if rmSource.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(rmSource, byteWidth) {
			return true, false, fmt.Errorf("%s %s source2 register must match the accumulator width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(rmSource) {
		return true, false, fmt.Errorf("%s %s source2 must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	lanes := byteWidth / 8
	first, err := c.loadPackedCompareLanes(rmSource, byteWidth, 64, properties.broadcast)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedCompareLanes(ins.Args[1], byteWidth, 64, false)
	if err != nil {
		return true, false, err
	}
	oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
	if err != nil {
		return true, false, err
	}
	old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, 64, oldBytes)
	computed := c.emitIFMA(spec, lanes, first, second, old)
	if masked {
		mask, loadErr := c.loadK(ins.Args[2].Reg)
		if loadErr != nil {
			return true, false, loadErr
		}
		computed = amd64ApplyIntegerLaneMask(c, lanes, 64, computed, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", out, lanes, computed, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
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
