package plan9asm

import (
	"fmt"
	"strings"
)

// All four legacy m128 names use Intel Type4, unlike their VEX forms.
// An unaligned load or align16 metadata cannot retain the original #GP.
// One sideeffect opcode also retains the read for dead/zero-mask results.
func (c *amd64Ctx) lowerLegacyBlendMinposMemory(ins Instr, form x86BlendMinposForm) error {
	source := ins.Args[form.source]
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) || source.Kind == OpFP {
		return fmt.Errorf("%w: legacy blend/minimum m128 needs its original native x86 storage and alignment", ErrProbeNeedsContext)
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
	mnemonic := strings.ToLower(string(ins.Op))
	result := c.newTmp()
	if form.minimum {
		fmt.Fprintf(c.b, "  %%%s = call <4 x float> asm sideeffect %q, %q(%s %s)\n",
			result, mnemonic+" "+segment+"($1), $0", "=x,r,~{memory}", pointerType, pointer)
	} else {
		// The original implicit X0 is an independent input even when the
		// source destination aliases X0. A temporary early-clobber output
		// prevents LLVM's carrier allocation from overwriting that input.
		mask, failure := c.loadPackedCompareBytes(ins.Args[form.mask], 16)
		if failure != nil {
			return failure
		}
		base, failure := c.loadPackedCompareBytes(ins.Args[form.base], 16)
		if failure != nil {
			return failure
		}
		maskCarrier, baseCarrier := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", maskCarrier, mask)
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", baseCarrier, base)
		fmt.Fprintf(c.b, "  %%%s = call <4 x float> asm sideeffect %q, %q(<4 x float> %%%s, %s %s, <4 x float> %%%s)\n",
			result, mnemonic+" "+segment+"($2), $0", "=&x,0,r,{xmm0},~{memory}", baseCarrier, pointerType, pointer, maskCarrier)
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", bytes, result)
	return c.storeLegacyXViews(ins.Args[form.destination].Reg, "%"+bytes)
}
