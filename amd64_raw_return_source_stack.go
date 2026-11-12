package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

// This is a source ABI0 stack, not LLVM's physical stack or an incoming native
// pointer. It is enabled only after all returns and all stack uses are proved.
// Ordinary pointers need a separately consumed complete Go caller proof.
// Nonzero TEXT frames, calls and private-stack address escape cannot use it.
type x86SourceStackProof struct {
	minimum      int64
	word         int64
	caller       *x86GoCallerRegionProof
	scalarResult *x86SourceStackScalarProof
	// Exact public normalized source bytes, excluding private certificates.
	normalized [32]byte
	// Diagnostic-only finite replay counts, never used as permission inputs.
	countedIterations [4]int
}

// Bind raw stack producer identity before consulting Go's named PUSH/POP
// deltasp rules. Edited normalized instructions cannot borrow that origin.
type x86SourceRawInstruction struct {
	op          Op
	args        []Operand
	vectorBytes int
	addressBits int // Exact decoded mode; not an address-size or native-entry permission.
	// Conversion-only physical identity, captured explicitly by the decoder.
	// A zero value is absent, not an SSE/VEX or non-MMX assertion.
	packedConversion x86RawPackedConversionIdentity
	// A low-bank unmasked packed move still retains its physical generation.
	packedMove      x86RawPackedMoveIdentity
	packedReduction x86RawPackedReductionIdentity
	ternaryLogic    x86RawTernaryLogicIdentity
	// An absent mode snapshot cannot claim a legacy compare continuation.
	legacyFloatCompare x86RawLegacyFloatCompareIdentity
	comi               x86RawCOMIIdentity
	floatMinMax        x86RawFloatMinMaxIdentity
	// Neither an absent snapshot nor a low bank implies a VEX conversion.
	scalarPrecision    x86RawScalarPrecisionIdentity
	scalarFloatInteger x86RawScalarFloatIntegerIdentity
	packedPrecision    x86RawPackedPrecisionIdentity
	namedHalf          x86RawNamedHalfIdentity
	fma3               x86RawFMA3Identity
	explicitMaskMove   x86RawExplicitMaskMoveIdentity
	packedShift        x86RawPackedShiftIdentity
	packedAbs          x86RawPackedAbsIdentity
	packedDot          x86RawPackedDotIdentity
	permute128         x86RawPermute128Identity
	zeroExtend         x86RawZeroExtendIdentity
	scalarSegmentLoad  x86RawScalarSegmentLoadIdentity
}

type x86SourceStackAddress struct {
	// original distinguishes the caller's opaque BP from an entry-SP offset.
	original bool
	offset   int64
}

type x86SourceStackCell struct {
	offset              int64
	width               int64
	bp                  *x86SourceStackAddress
	flags               bool
	numericFlags        bool
	partialNumericFlags uint8
	caller              *x86CallerPointerValue
	known               uint8
	canonical           uint8
	scalarFlags         uint8
	gOriginal           bool
}

type x86SourceStackState struct {
	sp                  int64
	bp                  x86SourceStackAddress
	cells               []x86SourceStackCell
	numericFlags        bool
	partialNumericFlags uint8
	callers             map[Reg]x86CallerPointerValue
	known               map[Reg]uint8
	vectors             map[Reg]uint64
	masks               map[Reg]bool
	gOriginal           bool
	scalarResult        *x86SourceStackScalarState
}

const x86SourceStackLimit = int64(1 << 20)

// Recompute the proof on every final normalization. No caller-supplied signature,
// changed source, or prepartition result inherits a cached admission flag.
func normalizeX86RawReturnSourceStack(fn Func, opt Options, bindFrame bool, original ...Func) Func {
	input := fn
	if len(original) != 0 {
		input = original[0]
	}
	fn.x86SourceStack = nil
	fn.x86SourceStackFailure = ""
	reject := func(index int, reason string) Func {
		fn.x86SourceStackFailure = fmt.Sprintf("normalized instruction %d: %s", index, reason)
		return fn
	}
	if fn.FrameSize != 0 || strings.Contains(fn.Sym, "<ABIInternal>") {
		return fn
	}
	hasRawReturn := false
	for _, ins := range fn.Instrs {
		if form := ins.x86RawNearReturn; form != nil {
			if !form.nativeWidth || form.cleanup != 0 {
				return fn
			}
			hasRawReturn = true
		}
	}
	if !hasRawReturn {
		return fn
	}
	word, nativeMove, nativeSuffix := int64(8), Op("MOVQ"), "Q"
	if opt.Goarch == "386" {
		word, nativeMove, nativeSuffix = 4, "MOVL", "L"
	}
	name := fn.Sym
	if opt.ResolveSym != nil {
		name = opt.ResolveSym(name)
	}
	sig, hasSig := opt.Sigs[name]
	physicalBool := bindFrame && hasSig && x86SourceStackBoolCandidate(fn, sig)
	if physicalBool {
		// This argument is a request-local Options value. Match the public
		// ArchAMD64 default for the complete grammar; do not rewrite the
		// caller's bound Options or the raw decoder's original mode spelling.
		opt.Goarch = x86SourceStackScalarArch(opt.Goarch)
	}
	caller := bindFrame && hasSig && x86CallerRegionSourceMatches(sig, input, opt.Goarch)
	if !caller {
		for index, instruction := range fn.Instrs {
			if _, known, _ := x86ExplicitIMULProperties(instruction.Op, instruction, opt.Goarch); known {
				return reject(index, "explicit multiply needs a complete typed caller input proof")
			}
			if _, known, _ := x86ConditionalMoveProperties(instruction.Op, instruction, opt.Goarch); known {
				return reject(index, "conditional move needs a complete typed caller input and flags proof")
			}
			if _, conditionalSet, _ := x86ConditionalSetProperties(instruction.Op, instruction, opt.Goarch); conditionalSet {
				return reject(index, "conditional byte output needs a complete typed caller input proof")
			}
			if _, extension := amd64ScalarExtensionMoveSpecs[instruction.Op]; extension || instruction.x86RawMOVSXDNeedsCaller {
				if x86RawDwordLiteralInput(instruction) {
					continue
				}
				// The old scalar slot contract proves frame bounds, not GP
				// input availability. It cannot authorize a new extension read
				// of unknown or partially initialized native entry registers.
				return reject(index, "scalar extension needs a complete typed caller input proof")
			}
		}
	}
	if !caller && !physicalBool && x86RawReturnLeafStackUnobserved(fn) {
		return fn
	}
	if bindFrame && hasSig && !caller {
		opt.Goarch = x86SourceStackScalarArch(opt.Goarch)
	}
	if bindFrame && (!hasSig || !caller && !x86SourceStackScalarABI0(sig, fn.ArgSize, opt.Goarch)) {
		return fn
	}

	// Validate the complete source, including dead instructions. A dead CALL
	// still changes Go's source prologue; unknown stack effects stay Context.
	labels := map[string]int{}
	var instructions []int
	goDeltas := map[int]int64{}
	var goDelta int64
	hasText := false
	for index, ins := range fn.Instrs {
		op := Op(normalizeInstructionOpcode(ins.Op))
		if op == OpTEXT {
			if hasText || !x86RawReturnLeafStackUnobserved(Func{Instrs: []Instr{ins}}) {
				return fn
			}
			hasText = true
		}
		if op == OpLABEL {
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpLabel {
				return fn
			}
			if _, duplicate := labels[ins.Args[0].Sym]; duplicate {
				return fn
			}
			labels[ins.Args[0].Sym] = len(instructions)
			continue
		}
		vectorMove := caller && x86CallerVectorMoveKnown(ins)
		if !x86SourceStackInstructionKnown(ins, nativeMove, nativeSuffix, opt.Goarch) && !vectorMove {
			return reject(index, "unregistered source-stack effect: "+string(ins.Op))
		}
		if x86LEAWidth(ins.Op, opt.Goarch) != 0 && ins.Op != Op("LEA"+nativeSuffix) && !caller {
			// The older scalar stack proof establishes a continuation, not
			// numerical GP initialization. Only the actual caller's complete
			// must-defined transfer can authorize these additional widths.
			return reject(index, "non-native-width LEA requires actual numerical caller source")
		}
		if opt.Goarch == "amd64" && !caller && x86SourceGOperand(ins) {
			if _, stack := amd64StackWidthSpecs[op]; !stack {
				return reject(index, "g numerical/address use requires actual caller source")
			}
		}
		if caller && !vectorMove && !x86CallerScalarOperands(ins) {
			return reject(index, "unregistered caller-region operand bank: "+string(ins.Op))
		}
		if _, stack := amd64StackWidthSpecs[op]; stack && ins.x86SourceRaw != nil &&
			(ins.x86SourceRaw.op != op || !reflect.DeepEqual(ins.x86SourceRaw.args, ins.Args)) {
			return fn
		}
		for _, operand := range ins.Args {
			if operand.Kind == OpFPAddr || (operand.Kind == OpFP && operand.FPOffset < 0) {
				return fn
			}
			if operand.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(operand.Sym), "$") {
				// Address-of is not an ordinary numeric immediate, regardless of
				// the register spelling or whether its later value is overwritten.
				return fn
			}
		}
		instructions = append(instructions, index)
		goDeltas[index] = goDelta
		// cmd/internal/obj/x86 preprocess adjusts named FP operands using
		// its linear deltasp. BYTE/WORD pushes are opaque to that pass.
		if spec, stack := amd64StackWidthSpecs[op]; stack && ins.x86SourceRaw == nil {
			width := int64(spec.bits / 8)
			if spec.mode == amd64StackPushValue || spec.mode == amd64StackPushFlags {
				goDelta += width
			} else {
				goDelta -= width
			}
			if goDelta < -x86SourceStackLimit || goDelta > x86SourceStackLimit {
				return fn
			}
		}
	}
	if !hasText || len(instructions) == 0 {
		return fn
	}

	copyFn := fn
	copyFn.Instrs = append([]Instr(nil), fn.Instrs...)
	for index := range copyFn.Instrs {
		copyFn.Instrs[index].Args = append([]Operand(nil), fn.Instrs[index].Args...)
		copyFn.Instrs[index].x86SourceStackFP = nil
		copyFn.Instrs[index].x86CallerMemory = nil
	}
	states := map[int]x86SourceStackState{}
	work := []int{0}
	states[0] = x86SourceStackState{bp: x86SourceStackAddress{original: true}, gOriginal: true}
	proof := &x86SourceStackProof{word: word}
	if bindFrame && hasSig && (!caller || sig.Ret == I1) {
		states[0] = x86SourceStackState{bp: x86SourceStackAddress{original: true}, gOriginal: true,
			scalarResult: x86SourceStackScalarInitial(fn, sig, opt.Goarch)}
		if states[0].scalarResult == nil || caller {
			return reject(0, "physical scalar result requires its independent scalar declaration")
		}
	}
	if caller {
		proof.caller = sig.x86CallerRegions
		states[0] = x86SourceStackState{
			bp:        x86SourceStackAddress{original: true},
			callers:   make(map[Reg]x86CallerPointerValue),
			known:     make(map[Reg]uint8),
			vectors:   make(map[Reg]uint64),
			masks:     make(map[Reg]bool),
			gOriginal: true,
		}
	}
	transfer := func(pc int, ins *Instr, state *x86SourceStackState) (bool, string) {
		op := Op(normalizeInstructionOpcode(ins.Op))
		if op == OpRET {
			if word == 8 && !state.gOriginal {
				return false, "unrestored original g identity at source return"
			}
			if len(ins.Args) != 0 || state.sp != 0 || !state.bp.original || goDeltas[instructions[pc]] != 0 {
				return false, "unproved source-stack or ABI0 continuation effect"
			}
			if value := state.scalarResult; value != nil && !value.complete() {
				return false, "physical scalar result lacks initialized/canonical bytes on every return"
			}
			return true, ""
		}
		for _, operand := range ins.Args {
			if operand.Kind == OpFP && state.sp+goDeltas[instructions[pc]] != 0 {
				return false, "unproved source-stack or ABI0 continuation effect"
			}
		}

		if spec, stack := amd64StackWidthSpecs[op]; stack {
			if !x86SourceStackStep(spec, ins, state, word) {
				return false, "unproved source-stack or ABI0 continuation effect"
			}
		} else if !x86SourceStackAddressStep(ins, state, nativeMove, nativeSuffix, word) {
			return false, "unproved source-stack or ABI0 continuation effect"
		}
		if state.sp < -x86SourceStackLimit || state.sp > 0 {
			return false, "unproved source-stack or ABI0 continuation effect"
		}
		if state.sp < proof.minimum {
			proof.minimum = state.sp
		}
		for operandIndex, operand := range ins.Args {
			if operand.Kind != OpMem || !x86RawReturnStackMemory(operand.Mem) {
				continue
			}
			if x86LEAWidth(ins.Op, opt.Goarch) != 0 {
				continue // The address step proved its destination and range.
			}
			width := x86ScalarMoveMemoryBytes(*ins, operandIndex, opt.Goarch)
			memory := operand.Mem
			if width == 0 || memory.Sym != "" || memory.Index != "" || memory.Segment != "" ||
				ins.x86AddressBits != 0 {
				return false, "unproved source-stack or ABI0 continuation effect"
			}
			base := state.sp
			if memory.Base == BP {
				if state.bp.original {
					return false, "unproved source-stack or ABI0 continuation effect"
				}
				base = state.bp.offset
			} else if memory.Base != SP {
				return false, "unproved source-stack or ABI0 continuation effect"
			}
			// Source entry SP[0:word] is the return PC. Only declaration-backed
			// data at entry SP+word can be mapped to FP shadow storage.
			if memory.Off < -x86SourceStackLimit || memory.Off > x86SourceStackLimit {
				return false, "unproved source-stack or ABI0 continuation effect"
			}
			offset := base + memory.Off - word
			if offset < 0 || offset > fn.ArgSize || width > fn.ArgSize-offset {
				return false, "unproved source-stack or ABI0 continuation effect"
			}
			if bindFrame {
				if !x86RawReturnFPBound(offset, width, sig, opt.Goarch) {
					return false, "unproved source-stack or ABI0 continuation effect"
				}
				if ins.x86SourceStackFP == nil {
					ins.x86SourceStackFP = map[int]int64{}
				}
				ins.x86SourceStackFP[operandIndex] = offset
			}
		}
		pointerFlags := false
		if caller {
			var valid bool
			if x86CallerVectorMoveKnown(*ins) {
				valid = x86CallerVectorMoveStep(ins, state, sig.x86CallerRegions)
			} else {
				pointerFlags, valid = x86CallerScalarStep(ins, state, sig.x86CallerRegions)
			}
			if !valid {
				return false, "unproved caller-region effect: " + string(ins.Op)
			}
			x86CallerGDefinition(*ins, state)
		}
		if !x86SourceStackFlagsStepForArch(*ins, state, opt.Goarch) {
			return false, "unproved source-stack or ABI0 continuation effect"
		}
		if pointerFlags {
			x86SourceStackSetNumericFlags(state, 0)
		}
		if state.scalarResult != nil && !state.scalarResult.step(*ins, opt.Goarch) {
			return false, "physical scalar result has an undefined numerical input or effect"
		}

		return false, ""
	}
	returned := false
	acyclic := (caller || states[0].scalarResult != nil) && x86CallerReachableAcyclic(copyFn, instructions, labels)
	if caller && !acyclic {
		if plan := deriveX86CallerCountedPlan(input, copyFn, instructions, labels); plan != nil {
			first, reason := replayX86CallerCountedPlan(plan, &copyFn, instructions, states[0], proof.caller, transfer)
			if reason != "" {
				return reject(0, reason)
			}
			minimum := proof.minimum
			proof.minimum = 0
			for index := range copyFn.Instrs {
				copyFn.Instrs[index].x86CallerMemory = nil
				copyFn.Instrs[index].x86SourceStackFP = nil
			}
			finalPlan := deriveX86CallerCountedPlan(input, copyFn, instructions, labels)
			if !reflect.DeepEqual(plan, finalPlan) {
				return reject(0, "counted-loop plan changed during independent replay")
			}
			second, reason := replayX86CallerCountedPlan(finalPlan, &copyFn, instructions, states[0], proof.caller, transfer)
			if reason != "" || minimum != proof.minimum || !reflect.DeepEqual(first, second) {
				return reject(0, "counted-loop final access/state replay changed: "+reason)
			}
			for _, visit := range second {
				if _, header := finalPlan.headers[visit.pc]; header {
					proof.countedIterations[visit.residue]++
				}
			}
			var err error
			proof.normalized, err = x86CallerSourceFingerprint(copyFn)
			if err != nil {
				return fn
			}
			copyFn.x86SourceStack = proof
			return copyFn
		}
	}
	final := false
	scalarByteWork := 0
	for budget := 0; ; budget++ {
		if len(work) == 0 {
			if !acyclic || final {
				break
			}
			// Discard every provisional certificate. Independently replay all
			// final reachable inputs, once, after the finite merge fixed point.
			final = true
			budget = 0
			for pc, index := range instructions {
				copyFn.Instrs[index].x86CallerMemory = nil
				copyFn.Instrs[index].x86SourceStackFP = nil
				if _, reachable := states[pc]; reachable {
					work = append(work, pc)
				}
			}
		}
		if budget >= 8192 {
			return fn
		}
		pc := work[0]
		work = work[1:]
		state := states[pc]
		if value := state.scalarResult; value != nil {
			scalarByteWork += 8 * (2*len(value.bytes.fp) + 33 + 2*len(state.cells))
			if scalarByteWork > 64<<20 {
				return reject(instructions[pc], "physical scalar source-CFG byte budget exhausted")
			}
		}
		if caller {
			state = x86CloneCallerState(state)
		} else {
			state.cells = append([]x86SourceStackCell(nil), state.cells...)
			state.scalarResult = state.scalarResult.clone()
		}
		ins := &copyFn.Instrs[instructions[pc]]
		ins.x86CallerMemory = nil
		ins.x86SourceStackFP = nil
		op := Op(normalizeInstructionOpcode(ins.Op))
		isReturn, reason := transfer(pc, ins, &state)
		if reason != "" {
			return reject(instructions[pc], reason)
		}
		if isReturn {
			returned = true
			continue
		}
		successors := []int{pc + 1}
		if op == OpJMP || isAMD64ConditionalBranch(op) {
			if len(ins.Args) != 1 {
				return fn
			}
			operand := ins.Args[0]
			label := operand.Sym
			if operand.Kind == OpIdent {
				label = operand.Ident
			}
			target, known := labels[label]
			if operand.Kind == OpMem && operand.Mem.Base == PC && operand.Mem.Index == "" &&
				operand.Mem.Sym == "" && operand.Mem.Off >= -int64(len(instructions)) && operand.Mem.Off <= int64(len(instructions)) {
				target, known = pc+int(operand.Mem.Off), true
			} else if operand.Kind != OpLabel && operand.Kind != OpIdent {
				return fn
			}
			if !known {
				return fn
			}
			if op == OpJMP {
				successors = []int{target}
			} else {
				successors = append(successors, target)
			}
		}
		for _, next := range successors {
			if next < 0 || next >= len(instructions) {
				return fn // Fallthrough cannot invent a source continuation.
			}
			if old, visited := states[next]; visited {
				if !reflect.DeepEqual(old, state) {
					if !acyclic {
						return reject(instructions[next], "different source-stack or caller-region states at join")
					}
					var merged x86SourceStackState
					var valid bool
					if caller {
						merged, valid = x86CallerAcyclicMerge(old, state, sig.x86CallerRegions)
					} else {
						merged, valid = x86SourceStackScalarMerge(old, state)
					}
					if !valid {
						return reject(instructions[next], "different source-stack or caller-region states at join")
					}
					if reflect.DeepEqual(old, merged) {
						continue
					}
					if final {
						return reject(instructions[next], "caller-region changed during final certificate replay")
					}
					states[next] = merged
					work = append(work, next)
				}
				continue
			}
			if final {
				return reject(instructions[next], "new caller-region state during final certificate replay")
			}
			states[next] = state
			work = append(work, next)
		}
	}
	if !returned {
		return fn
	}
	if states[0].scalarResult != nil {
		proof.scalarResult = sealX86SourceStackScalar(copyFn, input, sig, proof)
		if proof.scalarResult == nil {
			return reject(0, "physical scalar result source seal failed")
		}
	}
	if caller {
		var err error
		proof.normalized, err = x86CallerSourceFingerprint(copyFn)
		if err != nil {
			return fn
		}
	}
	copyFn.x86SourceStack = proof
	return copyFn
}

func x86SourceStackScalarABI0(sig FuncSig, argSize int64, arch string) bool {
	if len(sig.ArgRegs) != 0 || argSize <= 0 || argSize > x86SourceStackLimit || len(sig.Frame.Results) != 1 ||
		len(sig.Frame.Params) != len(sig.Args) || len(sig.Args) == 0 {
		return false
	}
	seen := map[int]bool{}
	for _, slot := range sig.Frame.Params {
		width := x86FrameScalarBytes(slot.Type, arch)
		if !x86SourceStackScalarType(slot.Type) || len(frameSlotFields(slot)) != 0 ||
			slot.Index < 0 || slot.Index >= len(sig.Args) || slot.Type != sig.Args[slot.Index] ||
			width == 0 || !x86RawReturnFPBound(slot.Offset, width, sig, arch) ||
			slot.Offset > argSize || width > argSize-slot.Offset || seen[slot.Index] {
			return false
		}
		seen[slot.Index] = true
	}
	slot := sig.Frame.Results[0]
	width := x86FrameScalarBytes(slot.Type, arch)
	return x86SourceStackScalarType(slot.Type) && slot.Type == sig.Ret && width != 0 &&
		x86RawReturnFPBound(slot.Offset, width, sig, arch) && slot.Offset <= argSize && width <= argSize-slot.Offset
}

func x86SourceStackScalarType(typ LLVMType) bool {
	switch typ {
	case I1, I8, I16, I32, I64:
		return true
	default:
		return false
	}
}

func x86SourceStackInstructionKnown(ins Instr, nativeMove Op, suffix, arch string) bool {
	if _, known, err := x86CounterControlProperties(ins.Op, ins, arch); known {
		return err == nil // Original raw/address metadata cannot borrow named count semantics.
	}
	if _, known, err := x86ExplicitIMULProperties(ins.Op, ins, arch); known {
		return err == nil
	}
	if _, known, err := x86ConditionalMoveProperties(ins.Op, ins, arch); known {
		return err == nil
	}
	if _, known, err := x86OrderingHintProperties(ins.Op, ins, arch); known {
		return err == nil
	}
	op := Op(normalizeInstructionOpcode(x86SourceMoveInstruction(ins, arch).Op))
	if _, recognized, err := x86ConditionalSetProperties(ins.Op, ins, arch); recognized {
		return err == nil
	}
	if op == OpTEXT || op == OpRET || op == OpJMP || isAMD64ConditionalBranch(op) {
		return true
	}
	if spec, stack := amd64StackWidthSpecs[op]; stack {
		return string(ins.Op) == string(op) && (spec.bits == 16 || (spec.bits == 32 && arch == "386") || (spec.bits == 64 && arch == "amd64"))
	}
	if op == nativeMove || x86LEAWidth(ins.Op, arch) != 0 || x86RawReturnScalarMoveBytes(op) != 0 {
		return true
	}
	if _, recognized, err := x86ScalarExtensionProperties(op, ins, arch); recognized {
		return err == nil
	}
	// This bounded numerical contract does not infer effects for opaque raw,
	// native/system calls, aggregate/vector memory, or instructions with hidden
	// stack inputs. These remain Context, not unsupported decoder forms.
	for _, base := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "CMP", "TEST", "INC", "DEC", "NEG", "NOT", "SHL", "SHR", "SAR"} {
		for _, width := range []string{"B", "W", "L", "Q"} {
			if op == Op(base+width) && (width != "Q" || arch == "amd64") {
				return true
			}
		}
	}
	return false
}

func x86SourceStackStep(spec amd64StackWidthSpec, ins *Instr, state *x86SourceStackState, word int64) bool {
	width := int64(spec.bits / 8)
	push := spec.mode == amd64StackPushValue || spec.mode == amd64StackPushFlags
	flags := spec.mode == amd64StackPushFlags || spec.mode == amd64StackPopFlags
	if flags && len(ins.Args) != 0 || !flags && len(ins.Args) != 1 {
		return false
	}
	cell := x86SourceStackCell{width: width, flags: flags, numericFlags: state.numericFlags, partialNumericFlags: state.partialNumericFlags}
	if state.scalarResult != nil && flags {
		cell.scalarFlags = state.scalarResult.bytes.flags
	}
	if !flags {
		operand := ins.Args[0]
		if operand.Kind != OpReg && (!push || operand.Kind != OpImm) {
			return false // Memory/segment stack transfers need a separate contract.
		}
		if operand.Kind == OpReg {
			if x86SegmentRegisterOperand(operand) || operand.Reg == SP {
				return false
			}
			if x86RawReturnStackRegister(operand.Reg) {
				if operand.Reg != BP || width != word {
					return false
				}
				value := state.bp
				cell.bp = &value
			}
			if x86SourceGRegister(operand.Reg) && state.gOriginal && push {
				if word != 8 || width != word || operand.Reg != "R14" {
					return false // A partial token cannot preserve the opaque g identity.
				}
				cell.gOriginal = true
			}
			if state.callers != nil && operand.Reg != BP {
				root, valid := x86CallerGP(operand.Reg)
				if !valid {
					return false
				}
				if pointer, present := state.callers[root]; present {
					if width != word || operand.Reg != root {
						return false
					}
					value := pointer
					cell.caller = &value
				}
				cell.known = state.known[root]
			}
			if state.scalarResult != nil && operand.Reg != BP {
				arch := "amd64"
				if word == 4 {
					arch = "386"
				}
				index, mask, valid := x86ResultGP(operand.Reg, width, arch)
				if !valid {
					return false
				}
				cell.known = state.scalarResult.bytes.gp[index] & mask
				cell.canonical = state.scalarResult.bytes.canonicalGP[index] & mask
			}
		}
		if state.scalarResult != nil && operand.Kind == OpImm {
			if operand.ImmRaw != "" || operand.ImmIsFloat {
				return false
			}
			cell.known = uint8((uint16(1) << uint(width)) - 1)
			cell.canonical = fixedLocalConstantBooleans(operand.Imm, width)
		}
	}
	if push {
		state.sp -= width
		cell.offset = state.sp
		// A new store replaces the covered old cell, never reuses stale data.
		for len(state.cells) != 0 && state.cells[len(state.cells)-1].offset <= state.sp {
			state.cells = state.cells[:len(state.cells)-1]
		}
		state.cells = append(state.cells, cell)
		return true
	}
	if len(state.cells) == 0 {
		return false
	}
	// Restoring a saved SP may discard lower private cells. The next POP must
	// still read a complete initialized source PUSH of the same physical width.
	for len(state.cells) != 0 && state.cells[len(state.cells)-1].offset < state.sp {
		state.cells = state.cells[:len(state.cells)-1]
	}
	if len(state.cells) == 0 {
		return false
	}
	saved := state.cells[len(state.cells)-1]
	if saved.offset != state.sp || saved.width != width {
		return false
	}
	if flags != saved.flags {
		return false // Scalar bytes and complete hardware FLAGS are not interchangeable.
	}
	if flags {
		state.numericFlags = saved.numericFlags
		state.partialNumericFlags = saved.partialNumericFlags
		if state.scalarResult != nil {
			state.scalarResult.bytes.flags = saved.scalarFlags
		}
	}
	if state.scalarResult != nil && !flags && ins.Args[0].Reg != BP {
		arch := "amd64"
		if word == 4 {
			arch = "386"
		}
		index, mask, valid := x86ResultGP(ins.Args[0].Reg, width, arch)
		if !valid {
			return false
		}
		value := &state.scalarResult.bytes
		value.gp[index] = value.gp[index]&^mask | saved.known&mask
		value.canonicalGP[index] = value.canonicalGP[index]&^mask | saved.canonical&mask
		if width == 4 && word == 8 {
			value.gp[index] |= 240
			value.canonicalGP[index] |= 240
		}
	}
	if saved.bp != nil {
		if flags || ins.Args[0].Reg != BP {
			return false // A saved frame pointer cannot become numeric output.
		}
		state.bp = *saved.bp
	} else if !flags && ins.Args[0].Reg == BP {
		return false
	}
	if saved.gOriginal {
		if flags || word != 8 || width != word || ins.Args[0].Reg != "R14" {
			return false // The saved opaque g never becomes an ordinary GP value.
		}
		state.gOriginal = true
		delete(state.callers, "R14")
		delete(state.known, "R14")
	} else if !flags && x86SourceGRegister(ins.Args[0].Reg) {
		state.gOriginal = false
	}
	if state.callers != nil && !flags && ins.Args[0].Reg != BP {
		root, valid := x86CallerGP(ins.Args[0].Reg)
		if !valid {
			return false
		}
		if _, pointer := state.callers[root]; pointer && width != word {
			return false
		}
		delete(state.callers, root)
		if saved.caller != nil {
			if width != word || ins.Args[0].Reg != root {
				return false
			}
			state.callers[root] = *saved.caller
		}
		if saved.gOriginal {
			delete(state.known, root)
		} else if width == word {
			state.known[root] = saved.known
		} else {
			mask := x86CallerByteMask(ins.Args[0].Reg, width)
			state.known[root] = state.known[root]&^mask | saved.known&mask
		}
	}
	state.cells = state.cells[:len(state.cells)-1]
	state.sp += width
	return true
}

// Source SP arithmetic operates on a Go stack address, not our LLVM private
// allocation's address. Its flags cannot be assumed equivalent. This bounded
// proof permits numerical redefinitions and matching FLAGS save/restore, but
// never exposes incomplete FLAGS as scalar data or invents incoming flags.
func x86SourceStackFlagsStep(ins Instr, state *x86SourceStackState) bool {
	return x86SourceStackFlagsStepForArch(ins, state, "amd64")
}

func x86SourceStackFlagsStepForArch(ins Instr, state *x86SourceStackState, arch string) bool {
	if form, known, err := x86ConditionalMoveProperties(ins.Op, ins, arch); known {
		return err == nil && x86SourceStackNumericFlagsRead(state, x86ByteConditionFlags(form.condition))
	}
	op := Op(normalizeInstructionOpcode(ins.Op))
	if condition, conditionalSet := x86ConditionalSetConditions[op]; conditionalSet {
		return x86SourceStackNumericFlagsRead(state, x86ByteConditionFlags(condition)) // SETcc preserves flags.
	}
	if effect, known, err := x86TypedCounterControlByteEffect(ins.Op, ins, arch); known {
		if err != nil || state.callers == nil && state.scalarResult == nil {
			return false // A physical stack identity alone proves no numerical counter.
		}
		// The existing caller or scalar-result transfer owns every NUM read/write.
		// Zero FLAGS reads require no producer; no status bit is defined here.
		return x86SourceStackNumericFlagMask(state)&effect.flagsRead == effect.flagsRead
	}
	if isAMD64ConditionalBranch(op) {
		return isAMD64CounterZeroBranch(op) || x86SourceStackNumericFlagsRead(state, x86ByteBranchFlags(op))
	}
	if state.callers != nil {
		if effect, known, err := x86TypedGPByteEffect(ins.Op, ins, arch); known {
			mask := x86SourceStackNumericFlagMask(state)
			if err != nil || mask&effect.flagsRead != effect.flagsRead {
				return false
			}
			for _, operand := range ins.Args {
				if operand.Kind == OpReg && x86RawReturnStackRegister(operand.Reg) {
					x86SourceStackSetNumericFlags(state, 0)
					return true // Source address arithmetic never defines numerical flags.
				}
			}
			x86SourceStackSetNumericFlags(state, mask&^effect.flagsKilled|effect.flagsDefined)
			return true
		}
	}
	name := string(op)
	if len(name) < 2 {
		return true
	}
	base := name[:len(name)-1]
	switch base {
	case "ADC", "SBB":
		return state.numericFlags
	case "ADD", "SUB", "AND", "OR", "XOR", "CMP", "TEST", "NEG":
		x86SourceStackSetNumericFlags(state, x86ByteFlagsAll)
		for _, operand := range ins.Args {
			if operand.Kind == OpReg && x86RawReturnStackRegister(operand.Reg) {
				x86SourceStackSetNumericFlags(state, 0)
			}
		}
	case "SHL", "SHR", "SAR":
		// Masked zero counts preserve prior flags; OF is undefined for larger
		// counts. They need a per-bit contract before serving as a new witness.
		x86SourceStackSetNumericFlags(state, 0)
	}
	return true
}

func x86SourceStackAddressStep(ins *Instr, state *x86SourceStackState, nativeMove Op, suffix string, word int64) bool {
	arch := "amd64"
	if word == 4 {
		arch = "386"
	}
	op := Op(normalizeInstructionOpcode(x86SourceMoveInstruction(*ins, arch).Op))
	lea := x86LEAWidth(ins.Op, arch) != 0
	if lea {
		if _, err := x86LEAOperandWidth(*ins, arch); err != nil {
			return false
		}
	}
	if form, recognized, err := x86ScalarExtensionProperties(op, *ins, arch); recognized {
		if err != nil || x86RawReturnStackRegister(form.result) ||
			form.source.Kind == OpReg && x86RawReturnStackRegister(form.source.Reg) {
			return false
		}
	}
	if len(ins.Args) == 2 && op == nativeMove && ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpReg &&
		x86RawReturnStackRegister(ins.Args[0].Reg) && x86RawReturnStackRegister(ins.Args[1].Reg) {
		source, destination := ins.Args[0].Reg, ins.Args[1].Reg
		if source != SP && source != BP || destination != SP && destination != BP {
			return false
		}
		value := state.bp
		if source == SP {
			value = x86SourceStackAddress{offset: state.sp}
		}
		if destination == BP {
			state.bp = value
			return true
		}
		if value.original {
			return false
		}
		state.sp = value.offset
		return true
	}
	if len(ins.Args) == 2 && ins.Args[1].Kind == OpReg && ins.Args[1].Reg == SP {
		if ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
			value := int64(ins.Args[0].Imm)
			if word == 4 {
				value = int64(int32(value)) // Raw 386 immediates retain unsigned bits.
			}
			if value < -x86SourceStackLimit || value > x86SourceStackLimit {
				return false
			}
			switch op {
			case Op("ADD" + suffix):
				state.sp += value
				return true
			case Op("SUB" + suffix):
				state.sp -= value
				return true
			case Op("AND" + suffix):
				alignment := -value
				if alignment < 1 || alignment > word || alignment&(alignment-1) != 0 {
					return false // The Go entry contract proves native-word alignment only.
				}
				state.sp &= value
				return true
			}
		}
		if op == Op("LEA"+suffix) && ins.Args[0].Kind == OpMem {
			memory := ins.Args[0].Mem
			if memory.Index != "" || memory.Sym != "" || memory.Segment != "" ||
				memory.Off < -x86SourceStackLimit || memory.Off > x86SourceStackLimit || ins.x86AddressBits != 0 {
				return false
			}
			base := state.sp
			if memory.Base == BP && !state.bp.original {
				base = state.bp.offset
			} else if memory.Base != SP {
				return false
			}
			state.sp = base + memory.Off
			return true
		}
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpReg && x86RawReturnStackRegister(operand.Reg) {
			return false // No implicit narrowing, arithmetic, or address escape.
		}
		if lea && operand.Kind == OpMem && x86RawReturnStackMemory(operand.Mem) {
			return false // An owned stack address may not escape into an ordinary GP.
		}
	}
	return true
}

// Source pushes and pops must use the same byte-addressable SP as MOV/LEA/
// alignment. The legacy amd64 virtual value stack is intentionally unchanged
// for sources without this complete source-stack proof.
func (c *amd64Ctx) pushSourceStackValue(typ LLVMType, width int64, value string) error {
	sp, err := c.loadReg(SP)
	if err != nil {
		return err
	}
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %d\n", next, sp, width)
	if err := c.storeRegUnchecked(SP, "%"+next); err != nil {
		return err
	}
	ptr := c.ptrFromAddrI64("%" + next)
	fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", typ, value, ptr)
	return nil
}

func (c *amd64Ctx) popSourceStackValue(typ LLVMType, width int64) (string, error) {
	sp, err := c.loadReg(SP)
	if err != nil {
		return "", err
	}
	ptr := c.ptrFromAddrI64(sp)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", value, typ, ptr)
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", next, sp, width)
	if err := c.storeRegUnchecked(SP, "%"+next); err != nil {
		return "", err
	}
	return "%" + value, nil
}
