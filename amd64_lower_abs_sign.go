package plan9asm

import (
	"fmt"
	"strings"
)

// The complete shared grammar retains each source/data/mask role. Legacy
// Type4 keeps its original aligned m128 instruction; VEX is unaligned and
// EVEX E4 suppresses only inactive lanes. These access rules are distinct.
func (c *amd64Ctx) lowerPackedAbsSign(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86PackedAbsSignProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	if form.legacy && form.memory >= 0 {
		return true, false, c.lowerLegacyAbsSignMemory(ins, form)
	}
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	bits, width := form.spec.laneBits, form.byteWidth
	first, err := c.loadX86PackedShiftLanes(ins.Args[form.first], width, bits, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	result := ""
	if form.spec.sign {
		data, err := c.loadPackedCompareLanes(ins.Args[form.second], width, bits, false)
		if err != nil {
			return true, false, err
		}
		result = c.emitPackedSign(first, data, width, bits)
	} else {
		result = c.emitPackedAbs(first, width, bits)
	}
	lanes := width * 8 / bits
	destination := ins.Args[form.destination]
	if form.mask >= 0 {
		old := "zeroinitializer"
		if !form.zeroing {
			oldBytes, err := c.loadPackedCompareBytes(destination, width)
			if err != nil {
				return true, false, err
			}
			old = c.bitcastVectorBytesToIntegerLanes(width, lanes, bits, oldBytes)
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, bits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, bits, result, width)
	if form.legacy {
		return true, false, c.storeLegacyXViews(destination.Reg, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(destination, width, "%"+out)
}

// Intel Type4's legacy SSE m128 alignment exception applies to all six
// PABS[BWD]/PSIGN[BWD] names, unlike their VEX counterparts. A volatile
// align-1 read followed by arithmetic loses that exception, and align16 is
// merely an LLVM precondition, not a runtime check. Keep the actual opcode
// even for a dead result. Virtual FP bytes are not original native storage.
func (c *amd64Ctx) lowerLegacyAbsSignMemory(ins Instr, form x86PackedAbsSignForm) error {
	source := ins.Args[form.first]
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) || source.Kind == OpFP {
		return fmt.Errorf("%w: legacy ABS/sign m128 needs its original native x86 storage and alignment", ErrProbeNeedsContext)
	}
	bits := form.spec.laneBits
	mnemonic := strings.ToLower(string(ins.Op))
	var result string
	var err error
	if form.spec.sign {
		data, failure := c.loadPackedCompareLanes(ins.Args[form.second], 16, bits, false)
		if failure != nil {
			return failure
		}
		result, err = c.emitPackedBinaryNativeMemory(source, bits, data, mnemonic)
	} else {
		// Unary ABS has no old-destination input. Do not manufacture one just
		// to reuse the tied binary carrier used by PSIGN and other families.
		pointer, pointerType, _, failure := c.packedVectorMemoryPointer(source)
		if failure != nil {
			return failure
		}
		segment := ""
		if pointerType == "ptr addrspace(256)" {
			segment = "%gs:"
		} else if pointerType == "ptr addrspace(257)" {
			segment = "%fs:"
		}
		call, lanes := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <4 x float> asm sideeffect %q, %q(%s %s)\n",
			call, mnemonic+" "+segment+"($1), $0", "=x,r,~{memory}", pointerType, pointer)
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <%d x i%d>\n", lanes, call, 128/bits, bits)
		result = "%" + lanes
	}
	if err != nil {
		return err
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", bytes, 128/bits, bits, result)
	return c.storeLegacyXViews(ins.Args[form.destination].Reg, "%"+bytes)
}

func (c *amd64Ctx) emitPackedAbs(values string, byteWidth, laneBits int) string {
	lanes := byteWidth * 8 / laneBits
	negative := c.newTmp()
	negated := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt <%d x i%d> %s, zeroinitializer\n", negative, lanes, laneBits, values)
	// No nsw: ABS of the most negative signed value wraps to itself.
	fmt.Fprintf(c.b, "  %%%s = sub <%d x i%d> zeroinitializer, %s\n", negated, lanes, laneBits, values)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %%%s, <%d x i%d> %s\n", result, lanes, negative, lanes, laneBits, negated, lanes, laneBits, values)
	return "%" + result
}

func (c *amd64Ctx) emitPackedSign(control, data string, width, bits int) string {
	lanes := width * 8 / bits
	positive := c.newTmp()
	negative := c.newTmp()
	negated := c.newTmp()
	nonpositive := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp sgt <%d x i%d> %s, zeroinitializer\n", positive, lanes, bits, control)
	fmt.Fprintf(c.b, "  %%%s = icmp slt <%d x i%d> %s, zeroinitializer\n", negative, lanes, bits, control)
	fmt.Fprintf(c.b, "  %%%s = sub <%d x i%d> zeroinitializer, %s\n", negated, lanes, bits, data)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %%%s, <%d x i%d> zeroinitializer\n", nonpositive, lanes, negative, lanes, bits, negated, lanes, bits)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %s, <%d x i%d> %%%s\n", result, lanes, positive, lanes, bits, data, lanes, bits, nonpositive)
	return "%" + result
}
