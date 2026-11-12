package plan9asm

import (
	"fmt"
	"strings"
)

// lowerImmediatePackedBlend implements the complete Go 1.27 immediate
// packed-blend family. The legacy instructions use yxshuf, while all four
// V-prefixed instructions use _yvblendpd and therefore have VEX X/Y forms
// only (no EVEX Z, mask, zeroing, broadcast, or SAE forms).
func (c *amd64Ctx) lowerImmediatePackedBlend(op Op, ins Instr) (ok bool, terminated bool, err error) {
	f, known, err := x86ImmediateBlendProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if f.legacy && f.memory {
		return true, false, c.lowerLegacyImmediateBlendMemory(ins, f)
	}
	first, err := c.loadX86PackedShiftBytes(ins.Args[f.source], f.byteWidth, true)
	if err != nil {
		return true, false, err
	}
	base, err := c.loadPackedCompareBytes(ins.Args[f.base], f.byteWidth)
	if err != nil {
		return true, false, err
	}
	result := c.emitImmediatePackedBlend(f.byteWidth, f.laneBytes*8, f.selector, first, base)
	if f.legacy {
		return true, false, c.storeLegacyXViews(ins.Args[f.destination].Reg, result)
	}
	return true, false, c.storePackedMoveOperand(ins.Args[f.destination], f.byteWidth, result)
}

func amd64ImmediatePackedBlendProperties(op string) (laneBits int, vector, ok bool) {
	switch op {
	case "PBLENDW":
		return 16, false, true
	case "BLENDPS":
		return 32, false, true
	case "BLENDPD":
		return 64, false, true
	case "VPBLENDW":
		return 16, true, true
	case "VPBLENDD", "VBLENDPS":
		return 32, true, true
	case "VBLENDPD":
		return 64, true, true
	default:
		return 0, false, false
	}
}

// Legacy Type4 m128 retains its original alignment/fault behavior, including
// imm8=0 and dead results. Logical FP bytes are not native aligned backing.
func (c *amd64Ctx) lowerLegacyImmediateBlendMemory(ins Instr, f x86ImmediateBlendForm) error {
	source := ins.Args[f.source]
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) || source.Kind == OpFP {
		return fmt.Errorf("%w: legacy immediate blend needs original native m128 storage", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	base, err := c.loadPackedCompareBytes(ins.Args[f.base], 16)
	if err != nil {
		return err
	}
	carrier, result, bytes := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", carrier, base)
	assembly := fmt.Sprintf("%s $$%d, %s($2), $0", strings.ToLower(string(ins.Op)), f.selector, segment)
	fmt.Fprintf(c.b, "  %%%s = call <4 x float> asm sideeffect %q, %q(<4 x float> %%%s, %s %s)\n",
		result, assembly, "=x,0,r,~{memory}", carrier, pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", bytes, result)
	return c.storeLegacyXViews(ins.Args[f.destination].Reg, "%"+bytes)
}

// emitImmediatePackedBlend selects the first (r/m) source when the immediate
// bit is one and the second source when it is zero. VPBLENDW repeats the eight
// immediate bits independently in each 128-bit lane of a Y register.
func (c *amd64Ctx) emitImmediatePackedBlend(byteWidth, laneBits int, imm uint8, firstBytes, secondBytes string) string {
	lanes := byteWidth * 8 / laneBits
	first := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, secondBytes)
	mask := make([]string, 0, lanes)
	for lane := 0; lane < lanes; lane++ {
		if imm&(1<<uint(lane%8)) != 0 {
			mask = append(mask, fmt.Sprintf("i32 %d", lane))
		} else {
			mask = append(mask, fmt.Sprintf("i32 %d", lanes+lane))
		}
	}
	shuffled := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> %s, <%d x i32> <%s>\n",
		shuffled, lanes, laneBits, first, lanes, laneBits, second, lanes, strings.Join(mask, ", "))
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <%d x i8>\n", out, lanes, laneBits, shuffled, byteWidth)
	return "%" + out
}
