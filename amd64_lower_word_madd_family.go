package plan9asm

import (
	"fmt"
)

func (c *amd64Ctx) lowerWordMultiplyAddForm(op Op, ins Instr, form x86PackedPhysicalForm) (bool, bool, error) {
	first, second, destination := form.source, ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && !form.mmx && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: %s m128 needs original native storage, not virtual FP/SP/BP alignment", ErrProbeNeedsContext, op)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	if form.mmx {
		if first.Reg != ins.Args[form.first].Reg {
			return true, false, fmt.Errorf("%w: %s GP spelling encodes a separate MMX source bank", ErrProbeNeedsContext, op)
		}
		var a string
		var err error
		if form.memory < 0 {
			a, err = c.loadReg(first.Reg)
		} else {
			a, err = c.loadPackedUnpackMMXSource(first, 8)
		}
		if err != nil {
			return true, false, err
		}
		b, err := c.loadReg(second.Reg)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedWordMultiplyAdd(4, c.bitcastI64ToIntegerLanes(4, 16, a), c.bitcastI64ToIntegerLanes(4, 16, b))
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i32> %s to i64\n", bits, result)
		return true, false, c.storeReg(destination.Reg, "%"+bits)
	}
	b, err := c.loadPackedCompareLanes(second, form.byteWidth, form.spec.inputBits, false)
	if err != nil {
		return true, false, err
	}
	var result string
	if form.legacy && form.memory >= 0 && first.Kind != OpFP {
		result, err = c.emitMultiplyAddNativeMemory(first, b, form.spec)
	} else {
		// Intel SDM's E4NF.nb is non-fault-suppressing. A plain eager LLVM
		// load can disappear under a constant zero mask, so use the reviewed
		// complete volatile native reader, never logical masked loads.
		a, loadErr := c.loadPackedUnpackSource(first, x86PackedUnpackForm{
			x86PackedBinaryForm: form.x86PackedBinaryForm, spec: x86PackedUnpackSpec{laneBits: form.spec.inputBits},
		})
		if loadErr != nil {
			return true, false, loadErr
		}
		if form.spec.inputBits == 8 {
			result = c.emitPackedUnsignedSignedByteMultiplyAdd(form.byteWidth, a, b)
		} else {
			result = c.emitPackedWordMultiplyAdd(form.byteWidth/2, a, b)
		}
	}
	if err != nil {
		return true, false, err
	}
	lanes := form.byteWidth * 8 / form.spec.outputBits
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareLanes(destination, form.byteWidth, form.spec.outputBits, false)
			if err != nil {
				return true, false, err
			}
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, form.spec.outputBits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, form.spec.outputBits, result, form.byteWidth)
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}

func (c *amd64Ctx) emitMultiplyAddNativeMemory(source Operand, data string, spec x86PackedPhysicalSpec) (string, error) {
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	segment := ""
	switch pointerType {
	case "ptr addrspace(256)":
		segment = "%gs:"
	case "ptr addrspace(257)":
		segment = "%fs:"
	}
	carrier, value := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <4 x i32>\n", carrier, 128/spec.inputBits, spec.inputBits, data)
	fmt.Fprintf(c.b, "  %%%s = call <4 x i32> asm sideeffect %q, %q(<4 x i32> %%%s, %s %s)\n",
		value, spec.nativeOpcode+" "+segment+"($2), $0", "=x,0,r,~{memory}", carrier, pointerType, pointer)
	if spec.outputBits != 32 {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <%d x i%d>\n", result, value, 128/spec.outputBits, spec.outputBits)
		return "%" + result, nil
	}
	return "%" + value, nil
}
