package plan9asm

// This bounded projection observes only the zero-iteration case of an already
// accepted original REP/REPN comparison. It does not define FLAGS or change an
// executable edge. The ordinary transfer still checks every nonempty access,
// operand and result; both empty-case successors must independently return the
// same complete constant result without any observable memory/control effect.
func x86ResultRepeatEmptyBranch(instructions []Instr, edges [][]int, previous []int,
	pc int, owned []bool, resultOffset int64, arch string) (bool, int) {
	const limit = 32
	work := 0
	stepBack := func(at int) int {
		if at > 0 && previous[at] == at-1 && len(edges[at-1]) == 1 && edges[at-1][0] == at {
			return at - 1
		}
		return -1
	}
	plain := func(ins Instr) bool { return x86ResultNamedPredicateInstruction(ins) }
	harmless := func(ins Instr) bool {
		return plain(ins) && len(ins.Args) == 0 && (ins.Op == "CLD" || ins.Op == "STD" || ins.Op == "NOP")
	}
	if pc < 0 || pc >= len(instructions) || !plain(instructions[pc]) ||
		!isAMD64ConditionalBranch(instructions[pc].Op) || len(edges[pc]) != 2 {
		return false, work
	}
	comparison := stepBack(pc)
	for comparison >= 0 && harmless(instructions[comparison]) && work < limit {
		work++
		comparison = stepBack(comparison)
	}
	if comparison < 0 || work >= limit {
		return false, work
	}
	form, known, err := x86StringInstructionProperties(instructions[comparison], arch)
	prefix := stepBack(comparison)
	if !known || err != nil || !plain(instructions[comparison]) ||
		(form.kind != "scas" && form.kind != "cmps") || prefix < 0 ||
		!plain(instructions[prefix]) || len(instructions[prefix].Args) != 0 ||
		(instructions[prefix].Op != "REP" && instructions[prefix].Op != "REPN") {
		return false, work
	}
	// Recover exact copies only in one short, straight-line predecessor region.
	// Different loads/affine offsets never share an identity just because their
	// caller-address origins happen to match. Every other write kills equality.
	start := prefix
	for count := 0; count < limit; count++ {
		before := stepBack(start)
		if before < 0 {
			break
		}
		start = before
	}
	var identities [16]uint16
	next := uint16(len(identities))
	for index := range identities {
		identities[index] = uint16(index + 1)
	}
	word := x86ResultPointerWord(arch)
	move, subtract := Op("MOVQ"), Op("SUBQ")
	if arch == "386" {
		move, subtract = "MOVL", "SUBL"
	}
	for at := start; at < comparison; at++ {
		work++
		ins := x86SourceMoveInstruction(instructions[at], arch)
		width := x86RawReturnScalarMoveBytes(ins.Op)
		if plain(ins) && width != 0 && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
			destination, _, valid := x86ResultGP(ins.Args[1].Reg, width, arch)
			if !valid {
				return false, work
			}
			next++
			identity := next
			if width == word && ins.Args[0].Kind == OpReg {
				if source, _, valid := x86ResultGP(ins.Args[0].Reg, word, arch); valid {
					identity = identities[source]
				}
			}
			identities[destination] = identity
		} else if !harmless(ins) && ins.Op != "REP" && ins.Op != "REPN" {
			for index := range identities {
				next++
				identities[index] = next
			}
		}
	}
	type value struct {
		identity uint16
		bits     uint64
		known    bool
	}
	var initial [16]value
	for index, identity := range identities {
		initial[index] = value{identity: identity, known: true}
	}
	initial[1] = value{known: true} // Only this projection assumes native CX=0.
	mask := ^uint64(0)
	if arch == "386" {
		mask = 1<<32 - 1
	}
	// There is no second CFG/fixed point here: each successor is a bounded,
	// forward-only scalar continuation. The caller charges all steps to the
	// existing shared source-flow work envelope; no mutable proof is cached.
	observe := func(at int) ([]uint16, bool) {
		registers := initial
		result := make([]uint16, len(owned)) // 0 unknown; otherwise exact byte+1.
		read := func(operand Operand) value {
			if operand.Kind == OpImm && operand.ImmRaw == "" && !operand.ImmIsFloat {
				return value{bits: uint64(operand.Imm) & mask, known: true}
			}
			if operand.Kind == OpReg {
				if index, _, valid := x86ResultGP(operand.Reg, word, arch); valid {
					return registers[index]
				}
			}
			return value{}
		}
		for count := 0; count < limit && at >= 0 && at < len(instructions); count++ {
			work++
			ins := x86SourceMoveInstruction(instructions[at], arch)
			if !plain(ins) {
				return nil, false
			}
			if ins.Op == OpRET && len(ins.Args) == 0 {
				for offset, required := range owned {
					if int64(offset) >= resultOffset && required && result[offset] == 0 {
						return nil, false
					}
				}
				return result, true
			}
			if !(ins.Op == "NOP" && len(ins.Args) == 0) && ins.Op != OpJMP {
				if (ins.Op != move && ins.Op != subtract) || len(ins.Args) != 2 {
					return nil, false
				}
				// MOV uses the ordinary full-word move grammar already checked
				// source-wide. Arithmetic also binds its typed effect here.
				if ins.Op == subtract {
					if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); !known || err != nil {
						return nil, false
					}
				}
				v, destination := read(ins.Args[0]), ins.Args[1]
				if !v.known {
					return nil, false
				}
				if destination.Kind == OpReg {
					index, _, valid := x86ResultGP(destination.Reg, word, arch)
					if !valid {
						return nil, false
					}
					if ins.Op == subtract {
						old := registers[index]
						if !old.known || v.identity != 0 && old.identity != v.identity {
							return nil, false
						}
						old.bits = (old.bits - v.bits) & mask
						if v.identity != 0 {
							old.identity = 0 // Exact same opaque value cancels.
						}
						v = old
					}
					registers[index] = v
				} else if destination.Kind == OpFP && ins.Op == move && v.identity == 0 {
					offset := destination.FPOffset
					if offset < resultOffset || offset < 0 || offset > int64(len(owned))-word {
						return nil, false
					}
					for byte := int64(0); byte < word; byte++ {
						if !owned[offset+byte] {
							return nil, false
						}
						result[offset+byte] = uint16(uint8(v.bits>>uint(8*byte))) + 1
					}
				} else {
					return nil, false
				}
			}
			if len(edges[at]) != 1 || edges[at][0] <= at {
				return nil, false
			}
			at = edges[at][0]
		}
		return nil, false
	}
	left, valid := observe(edges[pc][0])
	if !valid {
		return false, work
	}
	right, valid := observe(edges[pc][1])
	if !valid || len(left) != len(right) {
		return false, work
	}
	for index := range left {
		if left[index] != right[index] {
			return false, work
		}
	}
	return true, work
}
