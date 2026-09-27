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

func (c *amd64Ctx) lowerVectorTest(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64VectorTestSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed form in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects vector/memory source and vector destination: %q", c.goarch, baseOp, ins.Raw)
	}

	source, destination := ins.Args[0], ins.Args[1]
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if (byteWidth != 16 && byteWidth != 32) || byteWidth > spec.maxBytes {
		return true, false, fmt.Errorf("%s %s destination width is outside its Go 1.27 table: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.vector {
		// Go's VEX classes admit X/Y0-15 even in 386 mode. They also admit
		// extended address registers there, so do not apply the legacy 386
		// register filter to VEX memory operands.
		if !amd64VEXVectorRegister(destination, byteWidth) {
			return true, false, fmt.Errorf("%s %s destination is outside Go's VEX X/Y class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if byteWidth != 16 || !c.isGoLegacyXReg(destination.Reg) {
		return true, false, fmt.Errorf("%s %s destination is outside Go's legacy X class: %q", c.goarch, baseOp, ins.Raw)
	}

	if source.Kind == OpReg {
		if spec.vector {
			if !amd64VEXVectorRegister(source, byteWidth) {
				return true, false, fmt.Errorf("%s %s source must match the destination's VEX width: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if byteWidth != 16 || !c.isGoLegacyXReg(source.Reg) {
			return true, false, fmt.Errorf("%s %s source is outside Go's legacy X class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be a same-width vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if !spec.vector && source.Kind == OpMem && !x86MemoryRegistersValidForArch(source.Mem, c.goarch) {
		return true, false, fmt.Errorf("%s %s source uses an out-of-range legacy address register: %q", c.goarch, baseOp, ins.Raw)
	}

	sourceBytes, err := c.loadPackedCompareBytes(source, byteWidth)
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
	// Intel defines OF, SF, and PF as cleared for all four instructions.
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsPFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
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
