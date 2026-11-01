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
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, recognized := amd64PackedVectorMoveSpecs[Op(base)]; !recognized {
		return false, false, nil
	}
	// Legacy helper calls may omit ins.Op. Never replace a conflicting source
	// identity when binding the dispatch argument for the shared grammar.
	if ins.Op != "" && strings.ToUpper(string(ins.Op)) != strings.ToUpper(string(op)) {
		return true, false, fmt.Errorf("packed move dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, recognized, err := amd64PackedVectorMoveProperties(ins, c.goarch)
	if !recognized || err != nil {
		return recognized, false, err
	}
	if form.undefinedOpcode() {
		// Invalid encoding faults before any mask, vector or address access.
		// An ordinary masked store would silently change the native semantics.
		return c.lowerSyscall("UD2", Instr{Op: "UD2"})
	}
	src, dst := ins.Args[0], ins.Args[form.destination]
	byteWidth, elemBits := form.byteWidth, form.spec.elementBits
	if form.spec.aligned && form.memory >= 0 {
		if !form.ordinaryMemory(ins, c.goarch) &&
			!x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			return true, false, fmt.Errorf("%w: %s requires original native memory backing and alignment effects", ErrProbeNeedsContext, op)
		}
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return true, false, fmt.Errorf("%w: aligned packed move needs its original native address size", ErrProbeNeedsContext)
		}
		return true, false, c.lowerAlignedPackedMoveMemory(ins, form)
	}
	for _, operand := range []Operand{src, dst} {
		if operand.Kind != OpFP {
			continue
		}
		if err := c.validateFPVectorSpan(operand.FPOffset, byteWidth); err != nil {
			return true, false, fmt.Errorf("%s %s: %w: %q", c.goarch, op, err, ins.Raw)
		}
	}
	if !form.spec.aligned && form.memory >= 0 &&
		(form.unalignedOrdinaryMemory(ins, c.goarch) || x86CallerMemoryCertified(ins, form.memory) || c.fixedLocalMemoryCertified(ins, form.memory)) {
		return true, false, c.lowerUnalignedPackedMoveMemory(ins, form)
	}

	if form.mask < 0 {
		value, err := c.loadPackedCompareBytes(src, byteWidth)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storePackedMoveOperand(dst, byteWidth, value)
	}
	mask, err := c.loadK(ins.Args[form.mask].Reg)
	if err != nil {
		return true, false, err
	}
	// FP operands describe checked virtual slots, not necessarily contiguous
	// native memory: each parameter/result can have its own alloca. Retain the
	// per-slot loads, mask selection and stores below for those operands.
	if (isAMD64MemoryOperand(src) && src.Kind != OpFP) || (isAMD64MemoryOperand(dst) && dst.Kind != OpFP) {
		return true, false, c.lowerMaskedPackedMoveMemory(src, dst, byteWidth, elemBits, mask, form.zeroing)
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
	// The invalid .Z memory-destination encoding was handled before evaluating
	// any operand. Valid zeroing forms always have a register destination.
	result := amd64ApplyIntegerLaneMask(c, lanes, elemBits, computed, old, mask, form.zeroing && dst.Kind == OpReg)
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

// Other EVEX families use this architecture/register axis without acquiring
// packed-move effects or caller-memory permissions.
func (c *amd64Ctx) isGoPackedVectorMoveRegister(arg Operand, byteWidth int) bool {
	return amd64GoPackedVectorMoveRegister(arg, byteWidth, c.goarch)
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
