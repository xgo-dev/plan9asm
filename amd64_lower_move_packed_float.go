package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedVectorMove implements the complete Go 1.27 packed vector-move
// tables. VMOVAPD/APS/UPD/UPS share _yvmovapd, while VMOVDQA32/DQA64 and
// VMOVDQU8/DQU16/DQU32/DQU64 share _yvmovdqa32. All have bit-preserving move
// semantics; the element width only controls the granularity of an EVEX mask.
func (c *amd64Ctx) lowerPackedVectorMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	elemBits := 0
	switch baseOp {
	case "VMOVAPD", "VMOVUPD":
		elemBits = 64
	case "VMOVAPS", "VMOVUPS":
		elemBits = 32
	case "VMOVDQA32", "VMOVDQU32":
		elemBits = 32
	case "VMOVDQA64", "VMOVDQU64":
		elemBits = 64
	case "VMOVDQU8":
		elemBits = 8
	case "VMOVDQU16":
		elemBits = 16
	default:
		return false, false, nil
	}
	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("%s %s %s suffix is absent from its Go 1.27 packed-move encodings: %q", c.goarch, baseOp, suffix, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects source, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7 in the middle: %q", c.goarch, baseOp, ins.Raw)
	}

	src := ins.Args[0]
	dst := ins.Args[len(ins.Args)-1]
	byteWidth := 0
	switch {
	case src.Kind == OpReg:
		byteWidth = amd64VectorByteWidth(src.Reg)
		if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(src, byteWidth) {
			return true, false, fmt.Errorf("%s %s source must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
		}
		if dst.Kind == OpReg {
			if !c.isGoPackedVectorMoveRegister(dst, byteWidth) {
				return true, false, fmt.Errorf("%s %s register widths must match: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(dst) {
			return true, false, fmt.Errorf("%s %s register source requires a matching vector or memory destination: %q", c.goarch, baseOp, ins.Raw)
		}
	case isAMD64MemoryOperand(src):
		if dst.Kind != OpReg {
			return true, false, fmt.Errorf("%s %s memory source requires a vector destination: %q", c.goarch, baseOp, ins.Raw)
		}
		byteWidth = amd64VectorByteWidth(dst.Reg)
		if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(dst, byteWidth) {
			return true, false, fmt.Errorf("%s %s destination must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
		}
	default:
		return true, false, fmt.Errorf("%s %s source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	for _, operand := range []Operand{src, dst} {
		if operand.Kind != OpFP {
			continue
		}
		for offset := operand.FPOffset; offset < operand.FPOffset+int64(byteWidth); offset += 8 {
			_, parameter := c.fpParam(offset)
			_, _, result := c.fpResultAlloca(offset)
			if !parameter && !result {
				return true, false, fmt.Errorf("%s %s uses an undeclared FP vector slot at +%d(FP): %q", c.goarch, baseOp, offset, ins.Raw)
			}
		}
	}

	if !masked {
		value, err := c.loadPackedCompareBytes(src, byteWidth)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storePackedMoveOperand(dst, byteWidth, value)
	}
	mask, err := c.loadK(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	// FP operands describe checked virtual slots, not necessarily contiguous
	// native memory: each parameter/result can have its own alloca. Retain the
	// per-slot loads, mask selection and stores below for those operands.
	if (isAMD64MemoryOperand(src) && src.Kind != OpFP) || (isAMD64MemoryOperand(dst) && dst.Kind != OpFP) {
		return true, false, c.lowerMaskedPackedMoveMemory(src, dst, byteWidth, elemBits, mask, zeroing)
	}
	value, err := c.loadPackedCompareBytes(src, byteWidth)
	if err != nil {
		return true, false, err
	}
	oldBytes, err := c.loadPackedCompareBytes(dst, byteWidth)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / elemBits
	computed := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, elemBits, value)
	old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, elemBits, oldBytes)
	// Go accepts .Z for a masked FP/memory store, but inactive memory lanes
	// remain unchanged. Only register destinations have zeroing semantics.
	result := amd64ApplyIntegerLaneMask(c, lanes, elemBits, computed, old, mask, zeroing && dst.Kind == OpReg)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, elemBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(dst, byteWidth, "%"+out)
}

// VEX/EVEX register writes replace every overlapping view and zero all bits
// above the written width. Keep this separate from legacy SSE stores, which
// preserve those upper bits.
func (c *amd64Ctx) storePackedMoveOperand(dst Operand, byteWidth int, value string) error {
	if dst.Kind != OpReg {
		return c.storeVectorBytesOperand(dst, byteWidth, value)
	}
	index, valid := amd64VectorRegisterIndex(dst.Reg, byteWidth)
	if !valid {
		return fmt.Errorf("invalid packed move register %s", dst.Reg)
	}
	for _, view := range []struct {
		bytes int
		slots map[int]string
	}{{16, c.xRegSlot}, {32, c.yRegSlot}, {64, c.zRegSlot}} {
		slot, live := view.slots[index]
		if !live {
			continue
		}
		stored := value
		if view.bytes != byteWidth {
			indices := make([]string, view.bytes)
			for i := range indices {
				lane := i
				if lane >= byteWidth {
					lane = byteWidth // First byte of the zero second source.
				}
				indices[i] = fmt.Sprintf("i32 %d", lane)
			}
			converted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> <%s>\n", converted, byteWidth, value, byteWidth, view.bytes, strings.Join(indices, ", "))
			stored = "%" + converted
		}
		fmt.Fprintf(c.b, "  store <%d x i8> %s, ptr %s\n", view.bytes, stored, slot)
	}
	return nil
}

// Share the architectural lane mask across floating and integer moves. A
// select after an eager full-width load/store cannot suppress memory faults
// and must not be used for masked memory destinations (including write-only
// memory). LLVM 22's masked intrinsics access only enabled lanes.
func (c *amd64Ctx) lowerMaskedPackedMoveMemory(src, dst Operand, byteWidth, elemBits int, mask string, zeroing bool) error {
	load := isAMD64MemoryOperand(src)
	memory := dst
	if load {
		memory = src
	}
	pointer, pointerType, suffix, err := c.packedVectorMemoryPointer(memory)
	if err != nil {
		return err
	}
	if suffix == "" {
		suffix = ".p0"
	}
	lanes := byteWidth * 8 / elemBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, elemBits)
	predicate := amd64IntegerMaskVector(c, lanes, mask)
	if load {
		fallback := "zeroinitializer"
		if !zeroing {
			fallback, err = c.loadPackedCompareLanes(dst, byteWidth, elemBits, false)
			if err != nil {
				return err
			}
		}
		loaded, bytes := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.load.v%di%d%s(%s align 1 %s, <%d x i1> %s, %s %s)\n", loaded, vectorType, lanes, elemBits, suffix, pointerType, pointer, lanes, predicate, vectorType, fallback)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytes, vectorType, loaded, byteWidth)
		return c.storePackedMoveOperand(dst, byteWidth, "%"+bytes)
	}
	value, err := c.loadPackedCompareLanes(src, byteWidth, elemBits, false)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  call void @llvm.masked.store.v%di%d%s(%s %s, %s align 1 %s, <%d x i1> %s)\n", lanes, elemBits, suffix, vectorType, value, pointerType, pointer, lanes, predicate)
	return nil
}

func (c *amd64Ctx) isGoPackedVectorMoveRegister(arg Operand, byteWidth int) bool {
	if !amd64EVEXVectorRegister(arg, byteWidth) {
		return false
	}
	if c.goarch == "386" && byteWidth == 64 {
		index, _ := amd64VectorRegisterIndex(arg.Reg, byteWidth)
		return index < 8
	}
	return true
}
