package plan9asm

// Each bit records initialization of one bit in private numerical storage.
// This retains independently unknown status bits through PUSHF/POPF without
// turning an entire packed byte into a numerical or pointer witness.
type x86ResultValueStack struct {
	bytes   []uint8 // Low byte is at the end, matching a descending byte stack.
	invalid bool
	id      bool // ID is separate from the six arithmetic flags and DF.
	// Eight bounded bitmap words cover at most 504 private byte positions.
	// Mode32 uses only the first four; unused positions must remain zero.
	pointerCells [8]uint64
	// Nil means the existing ordinary NUM bytes. FLAGS pushes additionally
	// retain precisely which source bits the adjacent mask may refine. Keep
	// those masks in stack-byte order through mixed widths, not GP positions.
	refinable   []uint8
	correlation *x86ResultFlagsCorrelation // Paired mode32 lowering only; no native stack permission.
}

func x86ResultValueStackLimit(arch string) int {
	// AMD64 lowering reserves eight bytes for its synthetic entry word.
	// This observer stays within the private bytes in both source modes.
	return (x86PrivateStackWords - 1) * int(x86ResultPointerWord(arch))
}

func (state *x86ResultState) adjustRelativeValueStack(form x86RelativeStackStep, arch string) bool {
	if state.shapeOnly {
		return true
	}
	stack := state.valueStack
	if stack.invalid || int64(len(stack.bytes)) != form.before {
		return false
	}
	next := int(form.before + form.amount)
	if form.amount > 0 {
		stack.bytes = append(stack.bytes, make([]uint8, form.amount)...)
		if stack.refinable != nil {
			stack.refinable = append(stack.refinable, make([]uint8, form.amount)...)
		}
	} else {
		stack.revokePointerCells(next, len(stack.bytes), int(x86ResultPointerWord(arch)))
		stack.bytes = stack.bytes[:next]
		if stack.refinable != nil {
			stack.refinable = stack.refinable[:next]
		}
	}
	return true
}

// The lower address indices of the shared object belong to dynamic SP.
// Map that part of each scalar access into descending stack-byte order.
// The returned offset starts the remainder in the fixed AUTO frame.
func (state *x86ResultState) accessRelativeStackBytes(offset, end int, arch string, write bool) (int, bool) {
	if offset >= state.relativeScratch {
		return offset, true
	}
	fixed := end
	if fixed > state.relativeScratch {
		fixed = state.relativeScratch
	}
	if state.shapeOnly {
		return fixed, true
	}
	stack := state.valueStack
	begin, limit := state.relativeScratch-fixed, state.relativeScratch-offset
	if limit > len(stack.bytes) {
		return 0, false
	}
	if write {
		stack.revokePointerCells(begin, limit, int(x86ResultPointerWord(arch)))
		for index := begin; index < limit; index++ {
			stack.bytes[index] = 0xff
			if stack.refinable != nil {
				stack.refinable[index] = 0xff
			}
		}
	} else {
		for _, known := range stack.bytes[begin:limit] {
			if known != 0xff {
				return 0, false
			}
		}
	}
	return fixed, true
}

// Private numerical storage and ID survive these independently accepted
// transfers. This is not the stronger inert-source rule: a vector product
// changes data registers, but neither accesses SP nor changes private FLAGS.
// Exact decoder identity supplies no input, pointer or entry permission.
func x86ResultPreservesPrivateStorage(ins Instr, arch string) bool {
	if x86RawCOMISource(ins, arch) {
		return true // Scalar status/MXCSR effects do not access private SP or ID.
	}
	if x86RawMULXSource(ins, arch) {
		return true // Exact GP products do not access private SP or ID.
	}
	if x86RawZeroExtendSource(ins, arch) {
		return true // Exact vector widening does not access private SP or ID.
	}
	if x86RawPermute128Source(ins, arch) {
		return true // No private SP or ID effect follows from vector selection.
	}
	if x86RawBlendMinposSource(ins, arch) {
		return true // Exact vector data effects do not access private SP or ID.
	}
	if x86RawImmediateBlendSource(ins, arch) {
		return true // Exact vector selection does not access private SP or ID.
	}
	if x86FMA3PreservesPrivateSourceState(ins, arch) {
		return true // Exact vector/MXCSR effects do not access private SP or ID.
	}
	if x86RawScalarPrecisionSource(ins, arch) || x86RawScalarFloatIntegerSource(ins, arch) ||
		x86RawPackedPrecisionSource(ins, arch) || x86RawNamedHalfSource(ins, arch) {
		return true // The exact X/MXCSR conversion does not access private SP or ID.
	}
	if x86RawExplicitMaskMoveSource(ins, arch) {
		return true // Exact native vector/memory effects do not access private SP or ID.
	}
	if x86RawPackedDotSource(ins, arch) {
		return true // Exact vector arithmetic does not access private SP or ID.
	}
	if x86RawUnalignedLoadSource(ins, arch) {
		return true
	}
	if x86RawIntegerMinMaxSource(ins, arch) {
		return true // Exact vector data effects do not access private SP or FLAGS.
	}
	if x86RawTernaryLogicSource(ins, arch) {
		return true // Exact bitwise vector writes do not create or replace private storage.
	}
	if x86RawLegacyFloatCompareSource(ins, arch) {
		return true // Numerical X writes do not access the private stack or ID.
	}
	if x86FloatMinMaxPreservesSourceState(ins, arch) {
		return true // Exact floating vector writes do not access private storage or ID.
	}
	return ins.Op != OpCALL && (x86ResultNamedPredicateInstruction(ins) ||
		x86RegisterQueryPreservesSourceState(ins) || x86WaitPackagePreservesStorage(ins) ||
		x86PreservesNumericalSourceState(ins) || x86MaskLogicalPreservesStorage(ins) ||
		x86EnqueuePreservesStorage(ins) || x86RawPackedConversionSource(ins, arch) || x86RawPackedReductionSource(ins, arch) || x86RawDwordProductResultSource(ins, arch) ||
		x86RawCMOVSource(ins, arch) || x86RawAESSource(ins, arch) || x86RawSHASource(ins, arch) || x86RawVectorTestSource(ins, arch) ||
		x86RawIFMASource(ins, arch) || x86RawQwordLookupSource(ins, arch) ||
		x86RawPackedIntegerCompareSource(ins, arch) || x86RawImmediatePackedCompareSource(ins, arch) ||
		x86RawBroadcastSource(ins, arch) || x86RawCLMULSource(ins, arch))
}

func x86ResultValueStackContinuation(ins Instr, state *x86ResultState, arch string) bool {
	if state.valueStack == nil || state.shapeOnly || len(state.valueStack.bytes) == 0 && !state.valueStack.invalid {
		return true
	}
	if state.valueStack.invalid || !x86ResultPreservesPrivateStorage(ins, arch) {
		return false
	}
	// On 386 the private byte stack moves the simulated SP. An AUTO access
	// cannot borrow the independent unchanged-SP local-byte proof while live.
	if arch == "386" && state.relativeScratch == 0 {
		if x86InertNOP(ins, arch) {
			return true
		}
		if _, _, private := x86ResultPrivateStackXORForm(ins, arch); private && state.valueStack.correlation != nil {
			return true // The transfer still checks every byte against reaching private depth.
		}
		for _, arg := range ins.Args {
			if arg.Kind == OpMem && x86LogicalSourceFrameRegister(arg.Mem.Base, arch) {
				return false
			}
		}
	}
	return true
}

type x86StackValueBinding uint8

const (
	x86StackValueOrdinary x86StackValueBinding = iota
	x86StackValueNativeStore
	x86StackValueOwnedAddress
)

func x86ResultValueStackStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	return x86ResultBoundValueStackStep(ins, state, owned, resultOffset, arch, x86StackValueOrdinary)
}

func x86ResultBoundValueStackStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string, binding x86StackValueBinding) (bool, bool) {
	spec, known, err := x86StackWidthProperties(ins, arch)
	if !known {
		return false, false
	}
	if err != nil || !x86ResultNamedPredicateInstruction(ins) || state.valueStack == nil || state.valueStack.invalid {
		return false, true
	}
	width := int64(spec.bits / 8)
	storage := int(width)
	stack := state.valueStack
	if spec.mode == amd64StackPopValue && ins.Args[0].Kind == OpReg && ins.Args[0].Reg == SP {
		return false, true // Numerical storage cannot rebind the physical/private stack pointer.
	}
	if state.relativeScratch == 0 && len(stack.bytes)%2 != 0 || len(stack.bytes) > x86ResultValueStackLimit(arch) ||
		!stack.pointerCellsBounded(arch) ||
		stack.refinable != nil && len(stack.refinable) != len(stack.bytes) ||
		stack.correlation != nil && (arch != "386" || len(stack.correlation.bytes) != len(stack.bytes)) {
		return false, true
	}
	push := spec.mode == amd64StackPushValue || spec.mode == amd64StackPushFlags
	if push {
		bits := ^uint64(0)
		pointer := false
		if spec.mode == amd64StackPushValue {
			arg := ins.Args[0]
			if x86SegmentRegisterOperand(arg) {
				return false, true
			}
			if arg.Kind == OpReg {
				index, _, valid := x86ResultGP(arg.Reg, width, arch)
				if !valid {
					return false, true
				}
				pointer = width == x86ResultPointerWord(arch) && state.pointerGP[index]
				// This is a bit-preserving private copy, not a numerical use.
				// Retain only independently known source bytes.
				bits = 0
				for offset := int64(0); offset < width; offset++ {
					if !pointer && state.gp[index]&(1<<uint(offset)) != 0 {
						bits |= uint64(255) << uint(8*offset)
					}
				}
			} else if x86AbsoluteRelocationSource(arg, arch, spec.bits) {
				if binding != x86StackValueOwnedAddress {
					bits = ^uint64(0) << uint(8*width)
				}
			} else if !x86ResultRead(arg, width, state, owned, arch) {
				return false, true
			}
		} else {
			for index, physical := range []uint{0, 2, 4, 6, 7, 11} {
				if state.flags&(1<<uint(index)) == 0 {
					bits &^= 1 << physical
				}
			}
			if state.direction == x86ResultDirectionUnknown {
				bits &^= 1 << 10
			}
			if !stack.id && spec.bits > 16 {
				bits &^= 1 << 21
			}
			if state.relativeScratch != 0 {
				// A physical alias must not observe synthetic system flags.
				// These bits are outside the ordinary arithmetic/DF/ID model.
				const systemFlags = 1<<8 | 1<<9 | 3<<12 | 1<<14 | 7<<18
				bits &^= systemFlags
			}
		}
		if state.shapeOnly {
			return true, true
		}
		if len(stack.bytes) > x86ResultValueStackLimit(arch)-storage {
			return false, true
		}
		x86ResultFlagsStackPush(stack, bits, storage, spec.mode == amd64StackPushFlags)
		if spec.mode == amd64StackPushFlags && stack.refinable == nil {
			stack.refinable = make([]uint8, len(stack.bytes))
			copy(stack.refinable, stack.bytes)
		}
		for index := storage - 1; index >= 0; index-- {
			initialized := uint8(bits >> uint(8*index))
			if stack.refinable != nil {
				eligible := initialized
				if spec.mode == amd64StackPushFlags {
					const modeledFlags = uint64(0x200cff)
					eligible &= uint8(modeledFlags >> uint(8*index))
				}
				stack.refinable = append(stack.refinable, eligible)
			}
			stack.bytes = append(stack.bytes, initialized)
		}
		if pointer {
			stack.markPointerCell(len(stack.bytes))
		}
		return true, true
	}
	bits := ^uint64(0)
	pointer := false
	refinable := bits
	var origins [32]uint8
	if !state.shapeOnly {
		if len(stack.bytes) < storage {
			return false, true
		}
		pointer = width == x86ResultPointerWord(arch) && stack.pointerCell(len(stack.bytes))
		stack.revokePointerCells(len(stack.bytes)-storage, len(stack.bytes), int(x86ResultPointerWord(arch)))
		bits = 0
		refinable = 0
		for index := 0; index < storage; index++ {
			position := len(stack.bytes) - 1 - index
			bits |= uint64(stack.bytes[position]) << uint(8*index)
			eligible := stack.bytes[position]
			if stack.refinable != nil {
				eligible &= stack.refinable[position]
			}
			refinable |= uint64(eligible) << uint(8*index)
		}
		origins = x86ResultFlagsStackPop(stack, storage)
		if stack.refinable != nil {
			stack.refinable = stack.refinable[:len(stack.bytes)-storage]
			if len(stack.refinable) == 0 {
				stack.refinable = nil
			}
		}
		stack.bytes = stack.bytes[:len(stack.bytes)-storage]
	}
	if spec.mode == amd64StackPopFlags {
		if stack.correlation != nil && !state.shapeOnly {
			copy(stack.correlation.flags[:spec.bits], origins[:spec.bits])
		}
		state.flags = 0
		for index, physical := range []uint{0, 2, 4, 6, 7, 11} {
			if bits&(1<<physical) != 0 {
				state.flags |= 1 << uint(index)
			}
		}
		state.direction = x86ResultDirectionUnknown
		if bits&(1<<10) != 0 {
			state.direction = x86ResultDirectionEither
		}
		if spec.bits > 16 {
			stack.id = bits&(1<<21) != 0
		}
		return true, true
	}
	arg := ins.Args[0]
	if x86SegmentRegisterOperand(arg) {
		return false, true
	}
	if arg.Kind == OpReg {
		index, mask, valid := x86ResultGP(arg.Reg, width, arch)
		if !valid {
			return false, true
		}
		var initialized uint8
		for b := int64(0); b < width; b++ {
			if uint8(bits>>uint(8*b)) == 0xff {
				initialized |= 1 << uint(b)
			}
		}
		state.gp[index] = state.gp[index]&^mask | initialized
		if width == 4 {
			state.gp[index] |= 0xf0
		}
		state.pointerGP[index], state.callerAddressGP[index] = pointer, false
		state.canonicalGP[index] &^= mask
		// Preserve partial-bit knowledge for exactly the next instruction.
		// Whole known bytes outside a narrow POP remain independently known.
		known := uint64(0)
		for b := int64(0); b < width; b++ {
			known |= uint64(uint8(refinable>>uint(8*b))) << uint(8*b)
		}
		for b := width; b < 8; b++ {
			if state.gp[index]&(1<<uint(b)) != 0 {
				known |= uint64(0xff) << uint(8*b)
			}
		}
		state.gpBits = x86ResultGPBits{bits: known, register: index, valid: true, fromStack: true}
		if stack.correlation != nil {
			stack.correlation.popped = origins
		}
		return true, true
	}
	for b := int64(0); b < width; b++ {
		if uint8(bits>>uint(8*b)) != 0xff {
			return false, true
		}
	}
	if binding == x86StackValueNativeStore && ins.x86NumericalRead == nil && x86OrdinaryNativeMemoryOperand(arg, arch) &&
		x86ResultIncomingPointerAddressIdentity(arg, state, arch) {
		return true, true // Only the existing private pop changes; no pointee or later-read fact.
	}
	return x86ResultStore(arg, width, state, owned, resultOffset, arch), true
}
