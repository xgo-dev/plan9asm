package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerDuplicateMove(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86DuplicateMoveProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	ins.Op = op
	return true, false, c.emitDuplicateMove(ins, form)
}

func (c *amd64Ctx) emitDuplicateMove(ins Instr, form x86DuplicateMoveForm) error {
	destination := ins.Args[form.destination]
	if form.legacy && form.spec.laneBytes == 4 && form.memory >= 0 {
		if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) ||
			form.source.Kind == OpFP || form.source.Kind == OpMem &&
			!x86OrdinaryNativeMemoryOperand(form.source, c.goarch) &&
			!x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			return fmt.Errorf("%w: legacy duplicate m128 needs its original native alignment and storage", ErrProbeNeedsContext)
		}
		return c.emitLegacyDuplicateMemory(ins.Op, form, destination)
	}
	laneBits := form.spec.laneBytes * 8
	lanes, sourceBytes := form.byteWidth/form.spec.laneBytes, form.byteWidth
	if form.memory >= 0 {
		sourceBytes = form.memoryBytes
	}
	bytes, err := c.loadDuplicateMoveSource(form)
	if err != nil {
		return err
	}
	cast := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i%d>\n", cast, sourceBytes, bytes,
		sourceBytes/form.spec.laneBytes, laneBits)
	// X-width m64 DDUP's source has one lane; every other source is full
	// width. Register and memory forms share exactly the same lane selector.
	indices := make([]int, lanes)
	for lane := range indices {
		indices[lane] = form.sourceByte(lane*form.spec.laneBytes) / form.spec.laneBytes
	}
	shuffle := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %%%s, <%d x i%d> poison, <%d x i32> %s\n",
		shuffle, sourceBytes/form.spec.laneBytes, laneBits, cast,
		sourceBytes/form.spec.laneBytes, laneBits, lanes, llvmI32Mask(indices))
	result := "%" + shuffle
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return err
		}
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareLanes(destination, form.byteWidth, laneBits, false)
			if err != nil {
				return err
			}
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, form.byteWidth)
	if form.legacy {
		return c.storeLegacyPackedLogical(destination, "%"+out)
	}
	return c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}

func (c *amd64Ctx) loadDuplicateMoveSource(form x86DuplicateMoveForm) (string, error) {
	if form.source.Kind == OpReg {
		return c.loadPackedCompareBytes(form.source, form.byteWidth)
	}
	if form.source.Kind == OpFP {
		return c.loadFPVectorBytes(form.source.FPOffset, form.memoryBytes)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.source)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	// E4NF.nb and E5NF retain the complete access even for a dead result or
	// zero mask. No alignment or initialized-pointee assumption is introduced.
	fmt.Fprintf(c.b, "  %%%s = load volatile <%d x i8>, %s %s, align 1\n", value, form.memoryBytes, pointerType, pointer)
	return "%" + value, nil
}

func (c *amd64Ctx) emitLegacyDuplicateMemory(op Op, form x86DuplicateMoveForm, destination Operand) error {
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.source)
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	loaded, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <4 x float> asm sideeffect %q, %q(%s %s)\n", loaded,
		strings.ToLower(string(op))+" "+segment+"($1), $0", "=x,r,~{memory}", pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", bytes, loaded)
	return c.storeLegacyPackedLogical(destination, "%"+bytes)
}

func llvmI32Mask(indices []int) string {
	var b strings.Builder
	b.WriteByte('<')
	for i, index := range indices {
		if i != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "i32 %d", index)
	}
	b.WriteByte('>')
	return b.String()
}
