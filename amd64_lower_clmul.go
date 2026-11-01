package plan9asm

import "fmt"

// lowerPackedCarrylessMultiply implements Go 1.27's complete legacy and
// vector PCLMULQDQ tables. VPCLMULQDQ applies one independent 64x64->128
// carryless multiplication to every 128-bit lane.
func (c *amd64Ctx) lowerPackedCarrylessMultiply(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	f, known, err := x86CLMULProperties(rawOp, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if f.legacy && f.memory >= 0 {
		return true, false, c.lowerLegacyCLMULMemory(ins, f)
	}
	second, err := c.loadX86PackedShiftBytes(ins.Args[f.source], f.byteWidth, true)
	if err != nil {
		return true, false, err
	}
	first, err := c.loadPackedCompareBytes(ins.Args[f.second], f.byteWidth)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedCarrylessMultiply(f.byteWidth, first, second, f.immediate)
	if f.legacy {
		return true, false, c.storeX(ins.Args[f.destination].Reg, result)
	}
	return true, false, c.storePackedMoveOperand(ins.Args[f.destination], f.byteWidth, result)
}

// The legacy m128 opcode, not its selected numerical qword, determines the
// native memory/alignment/fault effect. Retain the whole original instruction
// even when its product is dead; virtual FP/SP/BP storage is not that address.
func (c *amd64Ctx) lowerLegacyCLMULMemory(ins Instr, f x86CLMULForm) error {
	source := ins.Args[f.source]
	virtual := source.Kind == OpFP
	if source.Kind == OpMem && !x86CallerMemoryCertified(ins, f.source) && !c.fixedLocalMemoryCertified(ins, f.source) {
		virtual = !x86OrdinaryNativeMemoryOperand(source, c.goarch)
	}
	if virtual {
		return fmt.Errorf("%w: legacy carryless multiply m128 needs original native storage, not virtual FP/SP/BP", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return err
	}
	first, err := c.loadPackedCompareLanes(ins.Args[f.second], 16, 64, false)
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	assembly := fmt.Sprintf("pclmulqdq $$%d, %s($2), $0", f.immediate, segment)
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <2 x i64> asm sideeffect %q, %q(<2 x i64> %s, %s %s)\n",
		result, assembly, "=x,0,r,~{memory}", first, pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytes, result)
	return c.storeX(ins.Args[f.destination].Reg, "%"+bytes)
}

func (c *amd64Ctx) emitPackedCarrylessMultiply(byteWidth int, firstBytes, secondBytes string, immediate uint8) string {
	qwords := byteWidth / 8
	first := c.newTmp()
	second := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", first, byteWidth, firstBytes, qwords)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", second, byteWidth, secondBytes, qwords)
	result := "zeroinitializer"
	for lane := 0; lane < byteWidth/16; lane++ {
		firstLane := c.newTmp()
		secondLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i64> %%%s, <%d x i64> poison, <2 x i32> <i32 %d, i32 %d>\n", firstLane, qwords, first, qwords, lane*2, lane*2+1)
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i64> %%%s, <%d x i64> poison, <2 x i32> <i32 %d, i32 %d>\n", secondLane, qwords, second, qwords, lane*2, lane*2+1)
		product := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> %%%s, <2 x i64> %%%s, i8 %d)\n", product, firstLane, secondLane, immediate)
		for word := 0; word < 2; word++ {
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 %d\n", extracted, product, word)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %%%s, i32 %d\n", inserted, qwords, result, extracted, lane*2+word)
			result = "%" + inserted
		}
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", bytes, qwords, result, byteWidth)
	return "%" + bytes
}
