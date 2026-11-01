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
// byte after the compacted tail untouched. Go's accepted EVEX.z memory spelling
// instead raises #UD before any mask, source or address access.
func (c *amd64Ctx) lowerPackedCompress(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86PackedCompactProperties(op, ins, c.goarch)
	if !known || form.expand {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	if form.undefinedOpcode() {
		return c.lowerSyscall("UD2", Instr{Op: "UD2"})
	}
	if form.memory >= 0 && x86OrdinaryNativeMemoryOperand(ins.Args[form.memory], c.goarch) {
		return true, false, c.lowerNativeCompactMemory(ins, form)
	}
	laneBits, byteWidth := form.laneBits, form.byteWidth
	source, destination := ins.Args[0], ins.Args[form.destination]

	sourceBytes, err := c.loadPackedCompareBytes(source, byteWidth)
	if err != nil {
		return true, false, err
	}
	if form.mask < 0 {
		return true, false, c.storePackedMoveOperand(destination, byteWidth, sourceBytes)
	}
	mask, err := c.loadK(ins.Args[form.mask].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / laneBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	sourceValue := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, sourceBytes)
	maskVector := amd64IntegerMaskVector(c, lanes, mask)
	if destination.Kind != OpReg && destination.Kind != OpFP {
		pointer, pointerType, intrinsicSuffix, err := c.packedVectorMemoryPointer(destination)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void @llvm.masked.compressstore.v%di%d%s(%s %s, %s %s, <%d x i1> %s)\n",
			lanes, laneBits, intrinsicSuffix, vectorType, sourceValue, pointerType, pointer, lanes, maskVector)
		return true, false, nil
	}
	passthrough := "zeroinitializer"
	if !form.zeroing {
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
	// FP results are separate scalar fields, not one contiguous native alloca.
	// The old complete span supplies the untouched compacted tail above.
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
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
