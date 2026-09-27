package plan9asm

import (
	"fmt"
	"strings"
)

var amd64PackedCompressLaneBits = map[Op]int{
	"VCOMPRESSPS": 32,
	"VCOMPRESSPD": 64,
	"VPCOMPRESSB": 8,
	"VPCOMPRESSW": 16,
	"VPCOMPRESSD": 32,
	"VPCOMPRESSQ": 64,
}

// lowerPackedCompress implements the complete Go 1.27 _yvcompresspd table.
// Masked register forms compact selected source lanes and merge/zero only the
// tail. Masked memory forms write selected lanes contiguously and leave every
// byte after the compacted tail untouched, including for Go's accepted .Z
// spelling.
func (c *amd64Ctx) lowerPackedCompress(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits, ok := amd64PackedCompressLaneBits[Op(baseOp)]
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
	source := ins.Args[0]
	if source.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s source must be an X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(source.Reg)
	if byteWidth == 0 || !c.isGoEVEXVectorRegister(source, byteWidth) {
		return true, false, fmt.Errorf("%s %s source is outside Go's EVEX register range: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(destination, byteWidth) {
			return true, false, fmt.Errorf("%s %s register destination must match the source width and range: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("%s %s destination must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	sourceBytes, err := c.loadPackedCompareBytes(source, byteWidth)
	if err != nil {
		return true, false, err
	}
	if !masked {
		return true, false, c.storeVectorBytesOperand(destination, byteWidth, sourceBytes)
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
	lanes := byteWidth * 8 / laneBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	sourceValue := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, sourceBytes)
	maskVector := amd64IntegerMaskVector(c, lanes, mask)
	if destination.Kind != OpReg {
		pointer, pointerType, intrinsicSuffix, err := c.packedVectorMemoryPointer(destination)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void @llvm.masked.compressstore.v%di%d%s(%s %s, %s %s, <%d x i1> %s)\n",
			lanes, laneBits, intrinsicSuffix, vectorType, sourceValue, pointerType, pointer, lanes, maskVector)
		if destination.Kind == OpFP {
			c.markFPResultWritten(destination.FPOffset)
		}
		return true, false, nil
	}
	passthrough := "zeroinitializer"
	if !zeroing {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		passthrough = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
	}
	compressed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.experimental.vector.compress.v%di%d(%s %s, <%d x i1> %s, %s %s)\n",
		compressed, vectorType, lanes, laneBits, vectorType, sourceValue, lanes, maskVector, vectorType, passthrough)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", out, vectorType, compressed, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func amd64IntegerMaskVector(c *amd64Ctx, lanes int, mask string) string {
	packed := mask
	if lanes < 64 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, mask, lanes)
		packed = "%" + narrow
	}
	vector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to <%d x i1>\n", vector, lanes, packed, lanes)
	return "%" + vector
}

func (c *amd64Ctx) packedVectorMemoryPointer(operand Operand) (ptr, ptrType, intrinsicSuffix string, err error) {
	switch operand.Kind {
	case OpMem:
		ptr, ptrType, err = c.ptrFromMem(operand.Mem)
		if err != nil {
			return "", "", "", err
		}
		switch ptrType {
		case "ptr":
			return ptr, ptrType, "", nil
		case "ptr addrspace(256)":
			return ptr, ptrType, ".p256", nil
		case "ptr addrspace(257)":
			return ptr, ptrType, ".p257", nil
		default:
			return "", "", "", fmt.Errorf("unsupported packed-vector pointer type %s", ptrType)
		}
	case OpSym:
		if address, parseErr := parseInt(strings.TrimSpace(operand.Sym)); parseErr == nil {
			return c.ptrFromAddrI64(fmt.Sprintf("%d", address)), "ptr", "", nil
		}
		ptr, err = c.ptrFromSB(operand.Sym)
		return ptr, "ptr", "", err
	case OpFP:
		if c.classicFrame != "" {
			return c.classicFramePtr(operand.FPOffset), "ptr", "", nil
		}
		if ptr = c.fpParamAlloca[operand.FPOffset]; ptr != "" {
			return ptr, "ptr", "", nil
		}
		if ptr, _, ok := c.fpResultAlloca(operand.FPOffset); ok {
			return ptr, "ptr", "", nil
		}
		return "", "", "", fmt.Errorf("%s %s FP operand has no addressable slot", c.goarch, operand.String())
	default:
		return "", "", "", fmt.Errorf("%s expected a packed-vector memory operand, got %s", c.goarch, operand.String())
	}
}
