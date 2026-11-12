package plan9asm

import "reflect"

// A pointer is never recovered from arbitrary integer data. The region and
// affine offset survive only exact full-register copies/address arithmetic.
type x86CallerPointerValue struct {
	argument int
	offset   int64
	span     int64
}

// Instruction-local access, not a function-wide memory exemption. The final
// guard compares the complete operands, effect direction and native width.
type x86CallerMemoryAccess struct {
	op    Op
	args  []Operand
	width int64
	write bool
}

func x86CallerSignatureMatches(sig FuncSig, proof *x86GoCallerRegionProof) bool {
	if proof == nil || proof.calls == 0 || proof.symbol != sig.Name || len(proof.arguments) != len(sig.Args) {
		return false
	}
	sig.x86CallerRegions = nil
	return reflect.DeepEqual(sig, proof.signature)
}

func x86CallerRegionSourceMatches(sig FuncSig, source Func, arch string) bool {
	if arch != "amd64" || !x86CallerSignatureMatches(sig, sig.x86CallerRegions) {
		return false
	}
	fingerprint, err := x86CallerSourceFingerprint(source)
	if err != nil {
		return false
	}
	if fingerprint == sig.x86CallerRegions.source {
		return true
	}
	// Module/text lowering normalize more than once. Only the exact result of
	// an earlier complete proof may be re-proved; edited public operands cannot
	// inherit its private metadata or the original source fingerprint.
	previous := source.x86SourceStack
	return previous != nil && previous.caller == sig.x86CallerRegions && fingerprint == previous.normalized
}

func x86CallerNormalizedSourceMatches(fn Func, sig FuncSig) bool {
	proof := fn.x86SourceStack
	if proof == nil || proof.caller == nil || proof.caller != sig.x86CallerRegions || !x86CallerSignatureMatches(sig, proof.caller) {
		return false
	}
	fingerprint, err := x86CallerSourceFingerprint(fn)
	return err == nil && fingerprint == proof.normalized
}

func x86CallerGP(reg Reg) (Reg, bool) {
	// This class includes R14, not numerical knowledge of incoming g. The
	// complete source-stack proof separately requires its opaque identity at
	// every return; only actual source definitions add numerical/pointer bits.
	root, valid := amd64FullRegBase(reg)
	if !valid {
		return "", false
	}
	switch root {
	case AX, BX, CX, DX, DI, SI, SP, BP, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15":
		return root, true
	default:
		return "", false
	}
}

func x86CallerScalarOperands(ins Instr) bool {
	for _, operand := range ins.Args {
		if operand.Kind == OpImm && (operand.ImmIsFloat || operand.ImmRaw != "") {
			return false
		}
		if operand.Kind == OpReg {
			if _, valid := x86CallerGP(operand.Reg); !valid {
				return false
			}
		}
		if operand.Kind == OpMem {
			for _, reg := range []Reg{operand.Mem.Base, operand.Mem.Index} {
				if reg != "" && reg != PC {
					if _, valid := x86CallerGP(reg); !valid {
						return false
					}
				}
			}
		}
	}
	return true
}

func x86CloneCallerPointers(source map[Reg]x86CallerPointerValue) map[Reg]x86CallerPointerValue {
	copy := make(map[Reg]x86CallerPointerValue, len(source))
	for reg, value := range source {
		copy[reg] = value
	}
	return copy
}

func x86CloneCallerKnown(source map[Reg]uint8) map[Reg]uint8 {
	copy := make(map[Reg]uint8, len(source))
	for reg, value := range source {
		copy[reg] = value
	}
	return copy
}

func x86CallerByteMask(reg Reg, width int64) uint8 {
	if width < 1 || width > 8 {
		return 0
	}
	shift := uint(0)
	if _, bits, alias := amd64ByteAlias(reg); alias {
		if width != 1 {
			return 0
		}
		shift = bits / 8
	}
	return uint8((uint16(1)<<uint(width) - 1) << shift)
}

func x86CallerNumericRead(operand Operand, width int64, state *x86SourceStackState) bool {
	if operand.Kind == OpImm {
		return operand.ImmRaw == "" && !operand.ImmIsFloat
	}
	if operand.Kind != OpReg {
		return false
	}
	root, valid := x86CallerGP(operand.Reg)
	if !valid || root == SP || root == BP {
		return false
	}
	if _, pointer := state.callers[root]; pointer {
		return false
	}
	mask := x86CallerByteMask(operand.Reg, width)
	return mask != 0 && state.known[root]&mask == mask
}

func x86CallerNumericWrite(reg Reg, width int64, state *x86SourceStackState) bool {
	root, valid := x86CallerGP(reg)
	if !valid || root == SP || root == BP {
		return false
	}
	mask := x86CallerByteMask(reg, width)
	if mask == 0 {
		return false
	}
	if _, pointer := state.callers[root]; pointer && width < 4 {
		return false // A partial write cannot wash surviving pointer bits.
	}
	delete(state.callers, root)
	if width == 4 || width == 8 {
		state.known[root] = 0xff // A native L write zeroes the upper GP half.
	} else {
		state.known[root] |= mask
	}
	return true
}

func x86CallerRecordMemory(ins *Instr, index int, width int64, write bool) {
	if ins.x86CallerMemory == nil {
		ins.x86CallerMemory = make(map[int]x86CallerMemoryAccess)
	}
	ins.x86CallerMemory[index] = x86CallerMemoryAccess{
		op: ins.Op, args: append([]Operand(nil), ins.Args...), width: width, write: write,
	}
}

func x86CallerMemoryStep(ins *Instr, state *x86SourceStackState, proof *x86GoCallerRegionProof, width int64) bool {
	for index, operand := range ins.Args {
		switch operand.Kind {
		case OpSym:
			// A static object may have its own old raw-return bounds, but it is
			// not one of this caller's read inputs or independent result locals.
			return false
		case OpFP:
			// Parameter pointers are imported once as complete words. Stores or
			// partial scalar reads cannot invent a different pointee contract.
			if index != 0 || len(ins.Args) != 2 || width != 8 || operand.FPOffset < 0 ||
				operand.FPOffset%8 != 0 || operand.FPOffset/8 >= int64(len(proof.arguments)) ||
				ins.Args[1].Kind != OpReg {
				return false
			}
			root, valid := x86CallerGP(ins.Args[1].Reg)
			if !valid || root != ins.Args[1].Reg || root == SP || root == BP {
				return false
			}
			x86CallerRecordMemory(ins, index, width, false)
		case OpMem:
			// The existing stack proof separately maps complete physical SP
			// argument words to actual FP slots, excluding the native return PC.
			if offset, mapped := ins.x86SourceStackFP[index]; mapped {
				if index != 0 || len(ins.Args) != 2 || width != 8 || offset < 0 || offset%8 != 0 ||
					offset/8 >= int64(len(proof.arguments)) || ins.Args[1].Kind != OpReg {
					return false
				}
				root, valid := x86CallerGP(ins.Args[1].Reg)
				if !valid || root != ins.Args[1].Reg || root == SP || root == BP {
					return false
				}
				x86CallerRecordMemory(ins, index, width, false)
				continue
			}
			if len(ins.Args) != 2 || !x86CallerOrdinaryMemoryStep(ins, index, state, proof, width, index == 1) {
				return false
			}
		}
	}
	return true
}

func x86CallerOrdinaryMemoryStep(ins *Instr, index int, state *x86SourceStackState, proof *x86GoCallerRegionProof, width int64, write bool) bool {
	if index < 0 || index >= len(ins.Args) || ins.Args[index].Kind != OpMem || width <= 0 {
		return false
	}
	if _, parameter := ins.x86SourceStackFP[index]; parameter {
		return false // Only the scalar GP import above can consume pointer slots.
	}
	memory := ins.Args[index].Mem
	if memory.Sym != "" || memory.Segment != "" || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		memory.Off < -x86SourceStackLimit || memory.Off > x86SourceStackLimit {
		return false
	}
	base, valid := x86CallerGP(memory.Base)
	pointer, known := state.callers[base]
	if !valid || base != memory.Base || !known || pointer.argument < 0 || pointer.argument >= len(proof.arguments) {
		return false
	}
	region := proof.arguments[pointer.argument]
	if _, valid := x86CallerPointerEnd(pointer); !valid || pointer.span != 0 && region.kind != x86CallerSliceInput {
		return false
	}
	if memory.Index != "" {
		if write || region.kind != x86CallerSliceInput ||
			memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 ||
			!x86CallerNumericRead(Operand{Kind: OpReg, Reg: memory.Index}, 8, state) {
			return false
		}
	}
	offset := pointer.offset + memory.Off
	if write {
		if region.kind != x86CallerFreshResult || offset < 0 || offset > region.width || width > region.width-offset {
			return false
		}
	} else if region.kind != x86CallerSliceInput {
		if offset < 0 || offset > region.width || width > region.width-offset {
			return false
		}
	}
	x86CallerRecordMemory(ins, index, width, write)
	return true
}

// The existing complete source stack handles all SP/BP transformations and
// returns. This additional transfer tracks only actual caller pointer regions
// and numerical byte initialization; it grants no unknown instruction effects.
func x86CallerScalarStep(ins *Instr, state *x86SourceStackState, proof *x86GoCallerRegionProof) (pointerFlags, valid bool) {
	if accepted, recognized := x86CallerNumericalReadStep(*ins, state); recognized {
		return false, accepted
	}
	if _, known, err := x86OrderingHintProperties(ins.Op, *ins, "amd64"); known {
		return false, err == nil
	}
	op := Op(normalizeInstructionOpcode(x86SourceMoveInstruction(*ins, "amd64").Op))
	if effect, known, err := x86TypedCounterControlByteEffect(ins.Op, *ins, "amd64"); known {
		if err != nil {
			return false, false
		}
		// The already registered caller supplies NUM; the descriptor grants no role.
		for _, operand := range effect.operands {
			if operand.read && !x86CallerNumericRead(operand.operand, operand.width, state) {
				return false, false
			}
		}
		for _, operand := range effect.operands {
			if operand.write && (operand.operand.Kind != OpReg ||
				!x86CallerNumericWrite(operand.operand.Reg, operand.width, state)) {
				return false, false
			}
		}
		return false, true // The source-stack FLAGS consumer separately checks flagsRead.
	}
	if op == OpTEXT || op == OpLABEL || op == OpRET || op == OpJMP || isAMD64ConditionalBranch(op) {
		return false, !isAMD64CounterZeroBranch(op) || x86CallerNumericRead(Operand{Kind: OpReg, Reg: CX}, 8, state)
	}
	if _, stack := amd64StackWidthSpecs[op]; stack {
		return false, true // Exact saved values/flags are tracked by the stack step.
	}
	if recognized, valid := x86CallerExplicitIMULStep(ins, state, proof); recognized {
		return false, valid
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpReg && x86RawReturnStackRegister(operand.Reg) {
			return false, true // Only the preceding exact address step admits this.
		}
	}
	if recognized, valid := x86CallerExtensionStep(ins, state, proof); recognized {
		return false, valid
	}
	if recognized, valid := x86CallerConditionalSetStep(ins, state, proof); recognized {
		return false, valid
	}
	if recognized, valid := x86CallerConditionalMoveStep(ins, state, proof); recognized {
		return false, valid
	}
	width := x86RawReturnScalarMoveBytes(op)
	if width != 0 {
		if len(ins.Args) != 2 || !x86CallerMemoryStep(ins, state, proof, width) {
			return false, false
		}
		source, destination := ins.Args[0], ins.Args[1]
		if isAMD64MemoryOperand(source) && isAMD64MemoryOperand(destination) {
			return false, false
		}
		var pointer x86CallerPointerValue
		hasPointer := false
		if source.Kind == OpFP {
			pointer = x86CallerPointerValue{argument: int(source.FPOffset / 8)}
			hasPointer = true
		} else if source.Kind == OpMem {
			if offset, mapped := ins.x86SourceStackFP[0]; mapped {
				pointer = x86CallerPointerValue{argument: int(offset / 8)}
				hasPointer = true
			}
		} else if source.Kind == OpReg {
			root, _ := x86CallerGP(source.Reg)
			pointer, hasPointer = state.callers[root]
		}
		if hasPointer {
			root, full := x86CallerGP(destination.Reg)
			sourceRoot, _ := x86CallerGP(source.Reg)
			if width != 8 || source.Kind == OpReg && source.Reg != sourceRoot ||
				destination.Kind != OpReg || !full || root != destination.Reg {
				return false, false // Pointer-as-data stores and partial copies stay unknown.
			}
			state.callers[root] = pointer
			delete(state.known, root)
			return false, true
		}
		if source.Kind != OpMem && !x86CallerNumericRead(source, width, state) {
			return false, false
		}
		if destination.Kind == OpReg {
			return false, x86CallerNumericWrite(destination.Reg, width, state)
		}
		return false, destination.Kind == OpMem
	}
	if x86LEAWidth(ins.Op, "amd64") != 0 {
		return false, x86CallerLEAStep(ins, state)
	}
	name := string(op)
	if len(name) < 2 {
		return false, false
	}
	base, suffix := name[:len(name)-1], name[len(name)-1:]
	switch suffix {
	case "B":
		width = 1
	case "W":
		width = 2
	case "L":
		width = 4
	case "Q":
		width = 8
	default:
		return false, false
	}
	if len(ins.Args) == 2 && (op == "ADDQ" || op == "SUBQ") && ins.Args[0].Kind == OpImm &&
		ins.Args[0].ImmRaw == "" && !ins.Args[0].ImmIsFloat && ins.Args[1].Kind == OpReg {
		root, _ := x86CallerGP(ins.Args[1].Reg)
		if pointer, present := state.callers[root]; present {
			if root != ins.Args[1].Reg {
				return false, false
			}
			delta := int64(ins.Args[0].Imm)
			if delta < -x86SourceStackLimit || delta > x86SourceStackLimit {
				return false, false
			}
			if op == "SUBQ" {
				delta = -delta
			}
			var valid bool
			pointer, valid = x86CallerPointerShift(pointer, delta)
			if !valid {
				return false, false
			}
			state.callers[root] = pointer
			return true, true // Private local addresses cannot define numerical flags.
		}
	}
	zero := base == "XOR" && len(ins.Args) == 2 && ins.Args[0].Kind == OpReg && reflect.DeepEqual(ins.Args[0], ins.Args[1])
	for _, argument := range ins.Args {
		if !zero && !x86CallerNumericRead(argument, width, state) {
			return false, false
		}
	}
	if base == "CMP" || base == "TEST" {
		return false, true
	}
	if len(ins.Args) == 0 || ins.Args[len(ins.Args)-1].Kind != OpReg {
		return false, false
	}
	return false, x86CallerNumericWrite(ins.Args[len(ins.Args)-1].Reg, width, state)
}

func x86CallerMemoryCertified(ins Instr, index int) bool {
	access, found := ins.x86CallerMemory[index]
	width, write, valid := x86CallerMoveMemoryShape(ins, index)
	// Producer memory proofs admit only native/default addressing. A later
	// address-size override cannot reuse even otherwise identical operands.
	return found && valid && ins.x86AddressBits == 0 && !ins.x86UnboundAddressOverride && access.op == ins.Op && reflect.DeepEqual(access.args, ins.Args) &&
		access.width == width && width > 0 && access.write == write
}
