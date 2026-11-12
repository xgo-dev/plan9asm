package plan9asm

import "reflect"

// Only these complete typed read families consume an owned indexed table.
// This selects the actual operand and access width, not a caller/pointer role.
func x86OwnedIndexedVectorRead(ins Instr, arch string) (int, int64, bool) {
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil || ins.x86SDKLiteral != nil {
		return 0, 0, false
	}
	if form, known, err := x86PackedLogicalProperties(ins, arch); known {
		return form.memory, int64(form.memoryBytes), err == nil && !form.mmx && form.memory >= 0
	}
	if form, known, err := x86ByteShuffleProperties(ins.Op, ins, arch); known {
		return form.memory, int64(form.memoryBytes), err == nil && form.memory >= 0
	}
	if form, known, err := x86LegacyIntegerArithmeticProperties(ins.Op, ins, arch); known {
		return form.memory, int64(form.memoryBytes), err == nil && !form.mmx && form.memory >= 0
	}
	if form, known, err := x86PackedLowMultiplyProperties(ins.Op, ins, arch); known {
		return form.memory, int64(form.memoryBytes), err == nil && form.legacy && form.memory >= 0
	}
	if form, known, err := x86PackedWordMultiplyProperties(ins.Op, ins, arch); known {
		return form.memory, int64(form.memoryBytes), err == nil && form.legacy && !form.mmx &&
			form.spec.mode == amd64PackedWordMultiplyLow && form.memory >= 0
	}
	return 0, 0, false
}

func (c *amd64Ctx) ownedIndexedVectorReads(fn Func, sig FuncSig, arch string) map[int]x86SDKLiteralAccess {
	if c.fpStaticAddressValues == nil || len(c.fpStaticAddressValues.numericLiterals) == 0 {
		return nil
	}
	literals := c.fpStaticAddressValues.numericLiterals
	address, memory, direct := false, false, false
	for _, ins := range fn.Instrs {
		operand, _, vector := x86OwnedIndexedVectorRead(ins, arch)
		memory = memory || vector && ins.Args[operand].Kind == OpMem
		for index := range ins.Args {
			form, valid := x86SDKLiteralOperandProperties(ins, index, arch)
			address = address || valid && form.address && literals[form.symbol] > 0
			// Mode32 may name the table directly instead of materializing a
			// GP base. This selects a proof candidate, not an index or extent.
			direct = direct || vector && index == operand && valid && !form.address &&
				form.memory.Index != "" && literals[form.symbol] > 0
		}
	}
	if !memory || !address && !direct {
		return nil // No new proof or restriction for unrelated source domains.
	}
	// The existing pure CFG/range algorithm takes ordinary source, signature
	// and actual numeric extents. Its result is not an SDK observation/token.
	// Failure grants nothing; the original complete result proof still runs.
	facts, err := proveX86SDKLiteralAccesses(fn, sig, arch, literals)
	if err != nil {
		return nil
	}
	reads := make(map[int]x86SDKLiteralAccess)
	for _, fact := range facts {
		operand, width, valid := x86OwnedIndexedVectorRead(fact.Original, arch)
		if valid && !fact.Address && fact.LowBits == nil && fact.Operand == operand && fact.Width == width {
			reads[fact.Instruction] = fact
		}
	}
	return reads
}

func x86OwnedIndexedVectorReadAt(reads map[int]x86SDKLiteralAccess, ordinal int, ins Instr) (Operand, int64, bool) {
	fact, present := reads[ordinal]
	if !present || fact.Operand < 0 || fact.Operand >= len(ins.Args) ||
		!reflect.DeepEqual(ins, fact.Original) {
		return Operand{}, 0, false
	}
	return ins.Args[fact.Operand], fact.Width, true
}
