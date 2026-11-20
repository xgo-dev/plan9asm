package plan9asm

// A GP view derived from caller addresses can feed the next flag computation.
// Its bits are separate from numerical values and dereferenceable addresses.
type x86AddressObservation struct {
	register uint8
	bytes    uint8
}

func (observation x86AddressObservation) reads(operand Operand, width int64, arch string) bool {
	if observation.bytes == 0 || operand.Kind != OpReg {
		return false
	}
	register, mask, valid := x86ResultGP(operand.Reg, width, arch)
	return valid && register == int(observation.register) && observation.bytes&mask == mask
}

func x86ResultObserveAddress(ins Instr, state *x86ResultState, prior x86AddressObservation, owned []bool, arch string) bool {
	if state.shapeOnly || !x86ResultNamedPredicateInstruction(ins) || len(ins.Args) != 2 {
		return false
	}
	source, destination := ins.Args[0], ins.Args[1]
	switch ins.Op {
	case "MOVL":
		if arch != "amd64" || source.Kind != OpReg || destination.Kind != OpReg {
			return false
		}
		index, _, valid := x86ResultGP(source.Reg, 4, arch)
		return valid && state.callerAddressGP[index] && state.observeAddressWrite(destination, 4, arch)
	case "ORL", "ORQ", "SUBL", "SUBQ":
		form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
		if !known || err != nil || form.source.Kind != OpReg || form.destination.Kind != OpReg {
			return false
		}
		width := int64(form.spec.bits / 8)
		first, _, firstValid := x86ResultGP(form.source.Reg, width, arch)
		last, _, lastValid := x86ResultGP(form.destination.Reg, width, arch)
		if !firstValid || !lastValid {
			return false
		}
		left := state.callerAddressGP[first] || prior.reads(form.source, width, arch)
		right := state.callerAddressGP[last] || prior.reads(form.destination, width, arch)
		if form.spec.stem == "SUB" {
			origin := state.callerAddressOrigin[first]
			if width != x86ResultPointerWord(arch) || !state.callerAddressGP[first] || !state.callerAddressGP[last] ||
				origin != 0 && origin == state.callerAddressOrigin[last] {
				return false // A same-origin delta uses the existing numerical transfer.
			}
		} else if !(left || right) || !(left || x86ResultRead(form.source, width, state, owned, arch)) ||
			!(right || x86ResultRead(form.destination, width, state, owned, arch)) {
			return false
		}
		if !state.observeAddressWrite(form.destination, width, arch) {
			return false
		}
		state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
		return true
	}
	if prior.bytes == 0 {
		return false
	}
	comparison, known, err := x86ScalarCompareProperties(ins.Op, ins, arch)
	if !known || err != nil || comparison.memory >= 0 {
		return false
	}
	width := int64(comparison.bits / 8)
	left := prior.reads(comparison.args[0], width, arch)
	right := prior.reads(comparison.args[1], width, arch)
	if !(left || right) || !(left || x86ResultRead(comparison.args[0], width, state, owned, arch)) ||
		!(right || x86ResultRead(comparison.args[1], width, state, owned, arch)) {
		return false
	}
	state.flags = x86ByteFlagsAll
	if comparison.test {
		state.flags &^= x86ByteFlagAF
	}
	return true
}

func (state *x86ResultState) observeAddressWrite(destination Operand, width int64, arch string) bool {
	register, mask, valid := x86ResultGP(destination.Reg, width, arch)
	if !valid {
		return false
	}
	state.gp[register], state.canonicalGP[register] = 0, 0
	if width == 4 && arch == "amd64" {
		state.gp[register] = 0xf0 // The independent upper half is architectural zero.
	}
	state.pointerGP[register], state.callerAddressGP[register] = false, false
	state.resultAddressGP[register] = x86ResultSlotAddress{}
	if state.boolFrameGP != nil {
		state.boolFrameGP[register] = x86ResultSlotAddress{}
	}
	state.addressObservation = x86AddressObservation{register: uint8(register), bytes: mask}
	return true
}
