package plan9asm

type x86ResultPredicateKind uint8

const (
	x86ResultNoPredicate x86ResultPredicateKind = iota
	x86ResultComparisonBytes
	x86ResultTestComparisonBytes
	x86ResultNonzeroComparisonBytes
	x86ResultNonzeroMaskGP
)

// One bounded, ephemeral relation follows a complete typed comparison/test/
// branch/movemask chain. It never asserts a value from numerical definedness.
// Width identifies the exact vector view, or the potentially nonzero GP bits.
// Unknown/intervening effects revoke it; joins retain only identical facts.
type x86ResultPredicate struct {
	kind     x86ResultPredicateKind
	register uint8
	width    uint8
}

func x86ResultNamedPredicateInstruction(ins Instr) bool {
	return !ins.x86Encoded && ins.x86SourceRaw == nil && ins.x86RawNearReturn == nil &&
		ins.x86AddressBits == 0 && !ins.x86UnboundAddressOverride && ins.x86SegmentPrefix == 0
}

// Called only after the independent complete byte/effect transfer succeeds.
func x86ResultPredicateAfter(ins Instr, before x86ResultPredicate, arch string) x86ResultPredicate {
	if x86PreservesNumericalSourceState(ins) {
		return before
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86ResultPredicate{}
	}
	if known, err := x86SizedNOPProperties(ins, arch); known && err == nil {
		return before // No input, write or FLAGS change revokes the existing relation.
	}
	if isAMD64ConditionalBranch(ins.Op) {
		if spec, counter := x86CounterControlPropertiesForOpcode(ins.Op); counter && spec.decrement &&
			before.kind == x86ResultNonzeroMaskGP && before.register == 1 {
			return x86ResultPredicate{} // The old numerical CX relation does not survive a decrement.
		}
		return before // The CFG refines each successor independently.
	}
	if form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, arch); known && err == nil && !form.mmx && !form.maskResult {
		index, valid := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
		if valid {
			return x86ResultPredicate{kind: x86ResultComparisonBytes, register: uint8(index), width: uint8(form.byteWidth)}
		}
	}
	if form, known, err := x86VectorTestProperties(ins.Op, ins, arch); known && err == nil &&
		before.kind == x86ResultComparisonBytes && ins.Args[0].Kind == OpReg && ins.Args[0].Reg == ins.Args[1].Reg {
		index, valid := amd64VectorRegisterIndex(ins.Args[0].Reg, form.byteWidth)
		if valid && before.register == uint8(index) && before.width == uint8(form.byteWidth) {
			before.kind = x86ResultTestComparisonBytes
			return before // For all-00/FF bytes, sign tests also detect nonzero.
		}
	}
	if form, known, err := x86MoveMaskProperties(ins.Op, ins, arch); known && err == nil &&
		before.kind == x86ResultNonzeroComparisonBytes && before.width == uint8(form.byteWidth) {
		source, valid := amd64VectorRegisterIndex(ins.Args[0].Reg, form.byteWidth)
		destination, _, gp := x86ResultGP(ins.Args[1].Reg, 4, arch)
		if valid && gp && before.register == uint8(source) {
			bits := form.byteWidth
			if form.floatingLaneBits != 0 {
				bits /= form.floatingLaneBits / 8
			}
			return x86ResultPredicate{kind: x86ResultNonzeroMaskGP, register: uint8(destination), width: uint8(bits)}
		}
	}
	return x86ResultPredicate{}
}

func x86ResultPredicateEdge(state x86ResultState, ins Instr, edge int) x86ResultState {
	state = x86ResultBitScanEdge(state, ins, edge)
	if _, counter := x86CounterControlPropertiesForOpcode(ins.Op); counter {
		return state // Count branches do not establish the ordinary JE/JNE vector-mask relation.
	}
	if state.predicate.kind != x86ResultTestComparisonBytes || !isAMD64ConditionalBranch(ins.Op) {
		return state
	}
	nonzero := (ins.Op == "JE" || ins.Op == "JEQ" || ins.Op == "JZ") && edge == 0 ||
		(ins.Op == "JNE" || ins.Op == "JNZ") && edge == 1
	if nonzero {
		state.predicate.kind = x86ResultNonzeroComparisonBytes
	} else {
		state.predicate = x86ResultPredicate{}
	}
	return state
}

func x86ResultVectorTestStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultVectorTestStepWithRead(ins, state, owned, arch, false)
}

func x86ResultVectorTestStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86VectorTestProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	for role, operand := range ins.Args {
		if operand.Kind != OpReg {
			if !native || role != 0 || !x86ResultReadWithNativeContinuation(ins, operand,
				int64(form.byteWidth), state, owned, arch, true) {
				return false, true // Shape cannot supply native memory or alignment.
			}
			continue
		}
		index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		mask := x86CallerVectorByteMask(int64(form.byteWidth))
		if !valid || arch == "386" && index >= 8 || state.vectorBytes(index)&mask != mask {
			return false, true
		}
	}
	state.flags = x86ByteFlagsAll
	return true, true
}
