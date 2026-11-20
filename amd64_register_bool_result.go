package plan9asm

import "strings"

func x86RegisterBoolResultNeedsProof(fn Func, sig FuncSig, arch string) bool {
	if arch != "amd64" || !strings.HasSuffix(fn.Sym, "<ABIInternal>") {
		return false
	}
	if sig.Ret == I1 {
		return true
	}
	for _, slot := range sig.Frame.Results {
		if slot.Type == I1 {
			return true
		}
	}
	return false
}

// Canonicality is a second must-fact beside byte initialization. This helper
// does not establish reads, FLAGS, memory or entry authority; the caller first
// executes the independent complete typed source transfer and then intersects
// these facts with its actual initialized GP bytes. Unmodeled effects revoke
// facts, never invent a value. Original Op/Raw/certificate identity is retained.
func x86RegisterCanonicalBytesAfter(original Instr, before [16]uint8, arch string) [16]uint8 {
	if next, known := x86SegmentQueryCanonicalBytesAfter(original, before, arch); known {
		return next
	}
	ins := x86SourceMoveInstruction(original, arch)
	next := before
	if _, known, err := x86DuplicateMoveProperties(ins.Op, ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
		return next // No GP write; vector results cannot create canonical bool facts.
	}
	read := func(operand Operand, width int64) uint8 {
		if operand.Kind == OpImm && operand.ImmRaw == "" && !operand.ImmIsFloat {
			return fixedLocalConstantBooleans(operand.Imm, width)
		}
		if operand.Kind == OpReg {
			if root, _, valid := x86ResultGP(operand.Reg, width, arch); valid {
				return before[root] >> fixedLocalBooleanShift(operand.Reg) & uint8((uint16(1)<<uint(width))-1)
			}
		}
		return 0 // Neither numerical memory bytes nor a vector imply 0/1.
	}
	write := func(reg Reg, width int64, canonical uint8) {
		root, mask, valid := x86ResultGP(reg, width, arch)
		if !valid {
			return
		}
		canonical <<= fixedLocalBooleanShift(reg)
		if width == 4 && arch == "amd64" {
			mask, canonical = 255, canonical|240
		}
		next[root] = next[root]&^mask | canonical&mask
	}
	if form, width, known, err := x86SwapProperties(ins, arch); known {
		if err != nil || !x86ResultNamedPredicateInstruction(ins) {
			return [16]uint8{}
		}
		if form.nop {
			return next
		}
		write(form.register.Reg, width, read(form.other, width))
		if form.other.Kind == OpReg {
			write(form.other.Reg, width, read(form.register, width))
		}
		return next // Reads use the original array, including overlapping AH/AL.
	}
	if bits, known, err := x86ByteSwapProperties(ins.Op, ins, arch); known {
		if err != nil {
			return [16]uint8{}
		}
		width := int64(bits / 8)
		write(ins.Args[0].Reg, width, x86ByteSwapByteMask(read(ins.Args[0], width), bits))
		return next
	}
	if form, known, err := x86ConditionalSetProperties(ins.Op, ins, arch); known {
		if err == nil && form.destination.Kind == OpReg {
			write(form.destination.Reg, 1, 1)
		}
		return next
	}
	if width := x86RawReturnScalarMoveBytes(ins.Op); width != 0 && len(ins.Args) == 2 {
		if ins.Args[1].Kind == OpReg {
			// Mixed high-byte/REX source spellings need the actual physical
			// view; do not let a legacy alias manufacture a bool result.
			if width == 1 && x86CompareExchangeHasREXByteView(x86CompareExchangeForm{source: ins.Args[0], destination: ins.Args[1]}) {
				for _, operand := range ins.Args {
					if operand.Kind == OpReg && fixedLocalBooleanShift(operand.Reg) != 0 {
						return [16]uint8{}
					}
				}
			}
			write(ins.Args[1].Reg, width, read(ins.Args[0], width))
		}
		return next
	}
	if form, known, err := x86ScalarExtensionProperties(ins.Op, ins, arch); known {
		if err != nil {
			return [16]uint8{}
		}
		from, to := int64(form.spec.sourceBits/8), int64(form.spec.destinationBits/8)
		canonical := read(form.source, from)
		// Every zero-extended high byte is zero. Sign extension also yields
		// zero high bytes when the original highest byte itself is 0/1.
		if !form.spec.signed || canonical&(1<<uint(from-1)) != 0 {
			for index := from; index < to; index++ {
				canonical |= 1 << uint(index)
			}
		}
		write(form.result, to, canonical)
		return next
	}
	if form, known, err := x86ConditionalMoveProperties(ins.Op, ins, arch); known {
		if err != nil {
			return [16]uint8{}
		}
		width := int64(form.bits / 8)
		write(form.destination.Reg, width, read(form.source, width)&read(form.destination, width))
		return next
	}
	if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known {
		if err != nil {
			return [16]uint8{}
		}
		if form.destination.Kind != OpReg {
			return next
		}
		width := int64(form.spec.bits / 8)
		canonical := uint8(0)
		if x86ScalarXORZeroRegister(form, width) {
			canonical = uint8((uint16(1) << uint(width)) - 1)
		} else {
			first, previous := read(form.source, width), read(form.destination, width)
			switch form.spec.stem {
			case "AND":
				canonical = first | previous // Any 0/1 byte bounds the AND.
			case "OR", "XOR":
				canonical = first & previous
			}
		}
		write(form.destination.Reg, width, canonical)
		return next
	}
	if _, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known {
		if err == nil {
			return next
		} // Only FLAGS are written.
		return [16]uint8{}
	}
	if effect, known, err := x86TypedCounterControlByteEffect(ins.Op, ins, arch); known {
		if err != nil {
			return [16]uint8{}
		}
		for _, operand := range effect.operands {
			if operand.write && operand.operand.Kind == OpReg {
				write(operand.operand.Reg, operand.width, 0)
			}
		}
		return next // A decrement supplies NUM, never a newly canonical count.
	}
	if ins.Op == "NOP" || ins.Op == OpJMP || isAMD64ConditionalBranch(ins.Op) {
		return next
	}
	if _, known, err := x86DirectiveProperties(ins); known && err == nil {
		return next
	}
	if form, known, err := x86ImplicitDivideProperties(ins.Op, ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
		for _, output := range x86ImplicitDivideWrites(form) {
			write(output.operand.Reg, output.width, 0)
		}
		return next // A quotient/remainder is numerical, never a newly canonical bool.
	}
	if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known && err == nil {
		for _, operand := range effect.operands {
			if operand.write && operand.operand.Kind == OpReg {
				write(operand.operand.Reg, operand.width, 0)
			}
		}
		return next // Complete effects preserve only genuinely unwritten GP bytes.
	}
	return [16]uint8{}
}
