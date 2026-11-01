package plan9asm

import (
	"fmt"
)

type amd64PackedExpandSpec struct {
	laneBits int
}

// amd64PackedExpandSpecs is the complete Go 1.27 _yvexpandpd grammar for the
// packed floating-point and integer expand families. None of these optabs has
// an EVEX broadcast attribute.
var amd64PackedExpandSpecs = map[Op]amd64PackedExpandSpec{
	"VEXPANDPD": {laneBits: 64},
	"VEXPANDPS": {laneBits: 32},
	"VPEXPANDB": {laneBits: 8},
	"VPEXPANDW": {laneBits: 16},
	"VPEXPANDD": {laneBits: 32},
	"VPEXPANDQ": {laneBits: 64},
}

// lowerPackedExpand implements all six _yvexpandpd rows for every instruction
// above: X/Y/Z register or memory sources and the corresponding K1-K7 merge or
// .Z forms. Logical FP fields are reconstructed independently; only native
// memory uses a pointer to the compact source array.
func (c *amd64Ctx) lowerPackedExpand(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86PackedCompactProperties(op, ins, c.goarch)
	if !known || !form.expand {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	if form.memory >= 0 && x86OrdinaryNativeMemoryOperand(ins.Args[form.memory], c.goarch) {
		return true, false, c.lowerNativeCompactMemory(ins, form)
	}
	byteWidth, laneBits := form.byteWidth, form.laneBits
	source, destination := ins.Args[0], ins.Args[form.destination]
	if form.mask < 0 {
		sourceBytes, err := c.loadPackedCompareBytes(source, byteWidth)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storePackedMoveOperand(destination, byteWidth, sourceBytes)
	}

	mask, err := c.loadK(ins.Args[form.mask].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / laneBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	maskVector := amd64IntegerMaskVector(c, lanes, mask)
	passthrough := "zeroinitializer"
	if !form.zeroing {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		passthrough = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
	}

	result := ""
	if isAMD64MemoryOperand(source) && source.Kind != OpFP {
		pointer, pointerType, intrinsicSuffix, err := c.packedVectorMemoryPointer(source)
		if err != nil {
			return true, false, err
		}
		expanded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.expandload.v%di%d%s(%s %s, <%d x i1> %s, %s %s)\n",
			expanded, vectorType, lanes, laneBits, intrinsicSuffix, pointerType, pointer, lanes, maskVector, vectorType, passthrough)
		result = "%" + expanded
	} else {
		sourceBytes, err := c.loadPackedCompareBytes(source, byteWidth)
		if err != nil {
			return true, false, err
		}
		sourceLanes := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, sourceBytes)
		result = c.expandPackedRegisterLanes(lanes, laneBits, sourceLanes, passthrough, mask, maskVector)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, vectorType, result, byteWidth)
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
}

// expandPackedRegisterLanes is the register-source inverse of vector
// compression. For destination lane i, the compact source index is the number
// of set mask bits below i. Building each lane from the original source before
// the final store keeps source/destination aliasing safe.
func (c *amd64Ctx) expandPackedRegisterLanes(lanes, laneBits int, source, passthrough, mask, maskVector string) string {
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	result := passthrough
	for lane := 0; lane < lanes; lane++ {
		active := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i1> %s, i32 %d\n", active, lanes, maskVector, lane)
		sourceIndex := "0"
		if lane != 0 {
			below := c.newTmp()
			count := c.newTmp()
			index := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", below, mask, (uint64(1)<<lane)-1)
			fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.ctpop.i64(i64 %%%s)\n", count, below)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", index, count)
			sourceIndex = "%" + index
		}
		sourceLane := c.newTmp()
		oldLane := c.newTmp()
		selected := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %s\n", sourceLane, vectorType, source, sourceIndex)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", oldLane, vectorType, result, lane)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", selected, active, laneBits, sourceLane, laneBits, oldLane)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n", inserted, vectorType, result, laneBits, selected, lane)
		result = "%" + inserted
	}
	return result
}
