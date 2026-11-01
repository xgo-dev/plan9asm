package plan9asm

import (
	"fmt"
	"strings"
)

type amd64VectorTestSpec struct {
	maxBytes     int
	vector       bool
	signLaneBits int
}

// amd64VectorTestSpecs models the complete Go 1.27 PTEST/VPTEST/VTEST grammar.
// PTEST uses the legacy yxm_q4 X/m128 row. The VEX instructions share
// _yvptest's X/m128,X and Y/m256,Y rows. VTESTPD and VTESTPS consider only the
// sign bit in each floating-point lane; PTEST and VPTEST consider every bit.
var amd64VectorTestSpecs = map[Op]amd64VectorTestSpec{
	"PTEST":   {maxBytes: 16},
	"VPTEST":  {maxBytes: 32, vector: true},
	"VTESTPD": {maxBytes: 32, vector: true, signLaneBits: 64},
	"VTESTPS": {maxBytes: 32, vector: true, signLaneBits: 32},
}

type x86VectorTestForm struct {
	amd64VectorTestSpec
	byteWidth int
}

// The lowerer and numerical observer share operand shape only. Original
// memory backing, initialized bytes and physical mode remain separate roles.
func x86VectorTestProperties(op Op, ins Instr, arch string) (x86VectorTestForm, bool, error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64VectorTestSpecs[Op(baseOp)]
	form := x86VectorTestForm{amd64VectorTestSpec: spec}
	if !recognized {
		return form, false, nil
	}
	if rawOp != baseOp || arch != "amd64" && arch != "386" ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), baseOp) {
		return form, true, fmt.Errorf("%s %s has an unbound mode, dispatch or suffix: %q", arch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return form, true, fmt.Errorf("%s %s expects vector/memory source and vector destination: %q", arch, baseOp, ins.Raw)
	}

	source, destination := ins.Args[0], ins.Args[1]
	byteWidth := amd64VectorByteWidth(destination.Reg)
	form.byteWidth = byteWidth
	legacy := func(reg Reg) bool {
		index, valid := amd64ParseXReg(reg)
		return valid && index < 16 && (arch != "386" || index < 8)
	}
	if (byteWidth != 16 && byteWidth != 32) || byteWidth > spec.maxBytes {
		return form, true, fmt.Errorf("%s %s destination width is outside its Go 1.27 table: %q", arch, baseOp, ins.Raw)
	}
	if spec.vector {
		// Go's VEX classes admit X/Y0-15 even in 386 mode. They also admit
		// extended address registers there, so do not apply the legacy 386
		// register filter to VEX memory operands.
		if !amd64VEXVectorRegister(destination, byteWidth) {
			return form, true, fmt.Errorf("%s %s destination is outside Go's VEX X/Y class: %q", arch, baseOp, ins.Raw)
		}
	} else if byteWidth != 16 || !legacy(destination.Reg) {
		return form, true, fmt.Errorf("%s %s destination is outside Go's legacy X class: %q", arch, baseOp, ins.Raw)
	}

	if source.Kind == OpReg {
		if spec.vector {
			if !amd64VEXVectorRegister(source, byteWidth) {
				return form, true, fmt.Errorf("%s %s source must match the destination's VEX width: %q", arch, baseOp, ins.Raw)
			}
		} else if byteWidth != 16 || !legacy(source.Reg) {
			return form, true, fmt.Errorf("%s %s source is outside Go's legacy X class: %q", arch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return form, true, fmt.Errorf("%s %s source must be a same-width vector register or memory: %q", arch, baseOp, ins.Raw)
	}
	if !spec.vector && source.Kind == OpMem && !x86MemoryRegistersValidForArch(source.Mem, arch) {
		return form, true, fmt.Errorf("%s %s source uses an out-of-range legacy address register: %q", arch, baseOp, ins.Raw)
	}
	return form, true, nil
}

func x86TypedVectorTestByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86VectorTestProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.byteWidth)
	return x86TypedByteEffect{requiresResultProof: true, flagsDefined: x86ByteFlagsAll,
		operands: []x86TypedByteOperand{
			{index: 0, operand: ins.Args[0], width: width, read: true},
			{index: 1, operand: ins.Args[1], width: width, read: true},
		}}, true, nil
}

func (c *amd64Ctx) lowerVectorTest(op Op, ins Instr) (ok bool, terminated bool, err error) {
	arch := c.goarch
	if arch == "" {
		arch = "amd64" // Preserve the existing direct-emitter default.
	}
	form, known, err := x86VectorTestProperties(op, ins, arch)
	if !known || err != nil {
		return known, false, err
	}
	source, destination := ins.Args[0], ins.Args[1]
	spec, byteWidth := form.amd64VectorTestSpec, form.byteWidth
	if source.Kind != OpReg && source.Kind != OpFP {
		if source.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(source, arch) &&
			!x86CallerMemoryCertified(ins, 0) && !c.fixedLocalMemoryCertified(ins, 0) {
			return true, false, fmt.Errorf("%w: vector test needs its original native memory binding", ErrProbeNeedsContext)
		}
		return true, false, c.emitVectorTestNativeMemory(ins, form, arch)
	}
	if source.Kind == OpFP {
		if !spec.vector {
			return true, false, fmt.Errorf("%w: legacy PTEST needs its original memory envelope", ErrProbeNeedsContext)
		}
		if err := c.validateX86PackedShiftFPSpan(source.FPOffset, byteWidth); err != nil {
			return true, false, err
		}
	}
	sourceBytes, err := c.loadX86PackedShiftBytes(source, byteWidth, true)
	if err != nil {
		return true, false, err
	}
	destinationBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
	if err != nil {
		return true, false, err
	}

	intersection := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and <%d x i8> %s, %s\n", intersection, byteWidth, destinationBytes, sourceBytes)
	invertedDestination := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor <%d x i8> %s, %s\n", invertedDestination, byteWidth, destinationBytes, llvmAllOnesI8Vec(byteWidth))
	outsideDestination := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and <%d x i8> %%%s, %s\n", outsideDestination, byteWidth, invertedDestination, sourceBytes)

	var zero, carry string
	if spec.signLaneBits == 0 {
		// Avoid an i256 scalar: LLVM 22 aborts while legalizing that type for
		// i386. Reducing individual bytes compiles on every supported target.
		zero = c.emitVectorBytesAreZero(byteWidth, "%"+intersection)
		carry = c.emitVectorBytesAreZero(byteWidth, "%"+outsideDestination)
	} else {
		zero = c.emitNoSignBits(byteWidth, spec.signLaneBits, "%"+intersection)
		carry = c.emitNoSignBits(byteWidth, spec.signLaneBits, "%"+outsideDestination)
	}

	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", zero, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", carry, c.flagsCFSlot)
	// All four instructions compute CF/ZF and clear AF/OF/SF/PF.
	c.clearX86StatusFlags(x86StatusAll &^ (x86StatusCF | x86StatusZF))
	return true, false, nil
}

func (c *amd64Ctx) emitVectorBytesAreZero(byteWidth int, bytes string) string {
	// Extract bytes directly. LLVM 22's i386 backend also aborts on some
	// otherwise-valid bitcasts between illegal 256-bit vector types.
	combined := "0"
	for index := 0; index < byteWidth; index++ {
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", element, byteWidth, bytes, index)
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i8 %s, %%%s\n", merged, combined, element)
		combined = "%" + merged
	}
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %s, 0\n", zero, combined)
	return "%" + zero
}

func (c *amd64Ctx) emitNoSignBits(byteWidth, laneBits int, bytes string) string {
	lanes := byteWidth * 8 / laneBits
	any := "false"
	for lane := 0; lane < lanes; lane++ {
		// X86 is little-endian, so each lane's sign bit is the high bit of
		// its final byte. Testing that byte avoids illegal 256-bit vector
		// bitcasts in LLVM 22's i386 legalizer.
		index := (lane+1)*(laneBits/8) - 1
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", element, byteWidth, bytes, index)
		negative := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i8 %%%s, 0\n", negative, element)
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %%%s\n", combined, any, negative)
		any = "%" + combined
	}
	none := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", none, any)
	return "%" + none
}
