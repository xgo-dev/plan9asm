package plan9asm

import (
	"fmt"
	"strings"
)

// Both complete Go tables have X/Y/Z register rows and a matching memory
// alternative. Compression writes its compact memory prefix; expansion reads
// one. Neither family admits broadcast/rounding, K0, or unmasked .Z.
type x86PackedCompactForm struct {
	laneBits, byteWidth       int
	destination, mask, memory int
	expand, zeroing           bool
}

// Go accepts EVEX.z on compressed memory destinations, but Intel XED requires
// ZEROING=0 for every such memory pattern. This is an architectural #UD, not
// a store that ignores zeroing or a numerical continuation with unknown inputs.
func (form x86PackedCompactForm) undefinedOpcode() bool {
	return !form.expand && form.memory == form.destination && form.zeroing
}

func x86PackedCompactProperties(op Op, ins Instr, arch string) (x86PackedCompactForm, bool, error) {
	name, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, known := amd64PackedCompressLaneBits[Op(name)]
	form := x86PackedCompactForm{laneBits: bits, mask: -1, memory: -1}
	if !known {
		spec, matched := amd64PackedExpandSpecs[Op(name)]
		if !matched {
			return form, false, nil
		}
		form.laneBits, form.expand = spec.laneBits, true
	}
	fail := func(reason string) (x86PackedCompactForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go compact/expand grammar (%s): %q", arch, op, reason, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail("mode or dispatch identity")
	}
	if dotted && suffix != "Z" {
		return fail("only optional .Z is accepted")
	}
	form.zeroing = dotted
	if len(ins.Args) != 2 && len(ins.Args) != 3 || form.zeroing && len(ins.Args) != 3 {
		return fail("source, [K1-K7,] destination; .Z requires a mask")
	}
	form.destination = len(ins.Args) - 1
	if len(ins.Args) == 3 {
		mask := ins.Args[1]
		index, valid := amd64ParseKReg(mask.Reg)
		if mask.Kind != OpReg || !valid || index == 0 {
			return fail("masked forms require K1-K7")
		}
		form.mask = 1
	}
	register := ins.Args[0]
	if form.expand {
		register = ins.Args[form.destination]
	}
	form.byteWidth = amd64VectorByteWidth(register.Reg)
	if !amd64GoPackedVectorMoveRegister(register, form.byteWidth, arch) {
		return fail("X/Y/Z register width or mode-bound bank")
	}
	other := form.destination
	if form.expand {
		other = 0
	}
	operand := ins.Args[other]
	if operand.Kind == OpReg {
		if !amd64GoPackedVectorMoveRegister(operand, form.byteWidth, arch) {
			return fail("register widths or banks do not match")
		}
	} else if isAMD64MemoryOperand(operand) {
		form.memory = other
	} else {
		return fail("memory alternative is not a Go memory operand")
	}
	return form, true, nil
}

func x86TypedCompactExpandByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedCompactProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	if form.undefinedOpcode() {
		return x86TypedByteEffect{}, true, fmt.Errorf("%w: compact EVEX.z memory encoding has no ordinary byte continuation", ErrProbeNeedsContext)
	}
	operands := []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: int64(form.byteWidth), read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: int64(form.byteWidth),
			read: form.mask >= 0 && !form.zeroing && form.memory != form.destination, write: true},
	}
	if form.mask >= 0 {
		operands = append(operands, x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: 8, read: true})
	}
	return x86TypedByteEffect{operands: operands, dynamicMemory: form.memory >= 0, requiresResultProof: true}, true, nil
}
