package plan9asm

import (
	"fmt"
	"strings"
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
// .Z forms. Masked memory uses llvm.masked.expandload so disabled lanes do not
// spuriously read beyond the compact source array.
func (c *amd64Ctx) lowerPackedExpand(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, ok := amd64PackedExpandSpecs[Op(baseOp)]
	if !ok {
		return false, false, nil
	}
	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("%s %s accepts only Go 1.27's optional .Z suffix: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects source, [K1-K7,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s.Z requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be an X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth == 0 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go's EVEX register range: %q", c.goarch, baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if !isAMD64MemoryOperand(source) && !c.isGoEVEXVectorRegister(source, byteWidth) {
		return true, false, fmt.Errorf("%s %s source must be matching X/Y/Z register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if !masked {
		sourceBytes, err := c.loadPackedCompareBytes(source, byteWidth)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeVectorBytes(destination.Reg, byteWidth, sourceBytes)
	}

	maskArg := ins.Args[1]
	maskIndex, valid := amd64ParseKReg(maskArg.Reg)
	if maskArg.Kind != OpReg || !valid || maskIndex == 0 {
		return true, false, fmt.Errorf("%s %s masked form requires K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	mask, err := c.loadK(maskArg.Reg)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / spec.laneBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	maskVector := amd64IntegerMaskVector(c, lanes, mask)
	passthrough := "zeroinitializer"
	if !zeroing {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		passthrough = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
	}

	result := ""
	if isAMD64MemoryOperand(source) {
		pointer, pointerType, intrinsicSuffix, err := c.packedVectorMemoryPointer(source)
		if err != nil {
			return true, false, err
		}
		expanded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.expandload.v%di%d%s(%s %s, <%d x i1> %s, %s %s)\n",
			expanded, vectorType, lanes, spec.laneBits, intrinsicSuffix, pointerType, pointer, lanes, maskVector, vectorType, passthrough)
		result = "%" + expanded
	} else {
		sourceBytes, err := c.loadPackedCompareBytes(source, byteWidth)
		if err != nil {
			return true, false, err
		}
		sourceLanes := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, sourceBytes)
		result = c.expandPackedRegisterLanes(lanes, spec.laneBits, sourceLanes, passthrough, mask, maskVector)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, vectorType, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
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
