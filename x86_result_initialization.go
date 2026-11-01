package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

// CheckX86ABI0ResultInitialization checks only byte initialization of one or
// more scalar ABI0 result fields. It supplies no source authentication, native
// frame, caller-memory, return-continuation or translation permission. The
// caller must derive sig from the actual selected Go declaration and bind the
// complete original CPP source independently. Unknown effects fail closed.
func CheckX86ABI0ResultInitialization(fn Func, sig FuncSig, goarch string) error {
	return checkX86ABI0ResultInitialization(fn, sig, goarch, x86ResultTransfer, false)
}

func checkX86ABI0ResultInitialization(fn Func, sig FuncSig, goarch string,
	transfer func(Instr, *x86ResultState, []bool, int64, string) bool, scalarViews bool) error {
	return checkX86ABI0ResultInitializationAtSource(fn, sig, goarch,
		func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
			return transfer(ins, state, owned, resultOffset, arch)
		}, scalarViews)
}

// The source ordinal is retained across TEXT/label removal. It does not itself
// authorize an effect; a private observer may join it to an exact source fact.
func checkX86ABI0ResultInitializationAtSource(fn Func, sig FuncSig, goarch string,
	transfer func(int, Instr, *x86ResultState, []bool, int64, string) bool, scalarViews bool) error {
	return checkX86ABI0ResultInitializationWithTrapOnly(fn, sig, goarch, transfer, scalarViews, false, false)
}

func checkX86ABI0ResultInitializationWithTrapOnly(fn Func, sig FuncSig, goarch string,
	transfer x86ResultSourceTransfer, scalarViews, trapOnly, privateStack bool) error {
	fail := func(reason string) error {
		return fmt.Errorf("%w: result initialization: %s", ErrProbeNeedsContext, reason)
	}
	privateVoid := scalarViews && sig.Ret == Void && len(sig.Frame.Results) == 0
	canonicalBool := scalarViews && x86ABI0BoolResultNeedsProof(sig, goarch)
	if canonicalBool && !x86ABI0LogicalBoolFrameRole(fn, sig, goarch) {
		return fail("bool byte requires its complete ordinary bounded logical ABI0 role")
	}
	mixedBool := scalarViews && x86MixedBoolResultNeedsCanonicalRole(sig, sig.Frame.Results)
	if mixedBool && !x86OrdinaryMixedBoolResultRole(fn, sig, goarch) {
		return fail("mixed bool requires its complete ordinary bounded logical ABI0 role")
	}
	// Go's file-local <> marker keeps ABI0; explicit entry selectors do not
	// inherit this ordinary scalar-frame observation from their spelling.
	if goarch != "amd64" && goarch != "386" || strings.Contains(strings.TrimSuffix(fn.Sym, "<>"), "<") ||
		len(sig.ArgRegs) != 0 || sig.ARMEntry != nil || sig.WASMContext != "" ||
		len(sig.Frame.Results) == 0 && !privateVoid {
		return fail("requires an ordinary x86 scalar ABI0 declaration")
	}
	resultOffset := int64(0)
	resultTypes := []LLVMType{sig.Ret}
	if !privateVoid {
		resultOffset = sig.Frame.Results[0].Offset
	}
	if len(sig.Frame.Results) > 1 {
		var valid bool
		resultTypes, valid = parseLiteralStructFields(sig.Ret)
		if !valid || len(resultTypes) != len(sig.Frame.Results) {
			return fail("result fields disagree with the return type")
		}
	}
	frame := 0
	for index, slot := range sig.Frame.Results {
		width := x86ResultScalarBytes(slot.Type, goarch)
		if width == 0 || slot.Type != resultTypes[index] || slot.Index != index || slot.Field != -1 || len(slot.Fields) != 0 ||
			slot.Offset < 0 || slot.Offset > 4096-width || slot.Offset < resultOffset {
			return fail("result layout is not bounded scalar fields")
		}
		if end := int(slot.Offset + width); end > frame {
			frame = end
		}
	}
	if privateVoid {
		// A private scalar-view query can check inputs and effects without a
		// result. Its entire logical extent comes from the typed parameters;
		// placing the write boundary at the end permits no incoming FP store.
		for _, slot := range sig.Frame.Params {
			width := x86FrameScalarBytes(slot.Type, goarch)
			if width == 0 || slot.Offset < 0 || slot.Offset > 4096-width {
				return fail("void parameter layout is not bounded scalar fields")
			}
			if end := int(slot.Offset + width); end > frame {
				frame = end
			}
		}
		resultOffset = int64(frame)
	}
	initial := x86ResultState{fp: make([]bool, frame), pointerFP: make(map[int64]bool)}
	if scalarViews && x86X87ValueFlowNeeded(fn) {
		initial.x87 = new(x86ResultX87State)
		if x86X87WordStateNeeded(fn) {
			initial.x87.word = &x86ResultX87WordState{layout: &x86X87WordLayout{parameters: make(map[int64]bool)}}
		}
	}
	if scalarViews && fn.x86ContinuationFlow != nil {
		view := fn.x86ContinuationFlow
		if !view.bind(fn, sig, goarch) {
			return fail("coalesced source/declaration identity changed")
		}
		initial.continuation = &x86ContinuationResultState{flow: view, tablesValid: true,
			written: make([]bool, view.graph.cells)}
	}
	if canonicalBool || mixedBool {
		initial.canonicalFP = make([]bool, frame)
	}
	if mixedBool {
		transfer = x86MixedBoolCanonicalTransfer(transfer)
	}
	if canonicalBool {
		initial.boolFrameSlots = append(append([]FrameSlot(nil), sig.Frame.Params...), sig.Frame.Results...)
		initial.boolCalls = fn.x86BoolCalls
		initial.boolReadonlyInputs = fn.x86BoolReadonlyInputs
		if initial.boolCalls != nil && len(initial.boolCalls.bytes) != 0 {
			initial.boolOutgoing = make([]bool, x86ResultPointerWord(goarch)+1)
			initial.boolOutgoingCanonical = make([]bool, x86ResultPointerWord(goarch)+1)
		}
		if x86ABI0BoolFrameAliasNeeded(fn, goarch) {
			initial.boolFrameGP = new([16]x86ResultSlotAddress)
		}
		transfer = x86ABI0CanonicalBoolTransfer(transfer)
	}
	ordinaryResultAddress := scalarViews && x86OrdinaryResultAddressRole(fn, sig, goarch)
	if scalarViews && (fn.x86DirectTailRoot != nil || ordinaryResultAddress) {
		for _, slot := range sig.Frame.Results {
			if x86IntegerResultSlot(slot) || ordinaryResultAddress && x86OrdinaryNumericAddressSlot(slot) {
				initial.resultAddressSlots = append(initial.resultAddressSlots, x86ResultSlotAddress{
					start: slot.Offset, end: slot.Offset + x86ResultScalarBytes(slot.Type, goarch), valid: true})
			}
		}
		if region, valid := x86DirectTailResultRegion(fn, sig, goarch); valid {
			initial.resultAddressSlots = []x86ResultSlotAddress{region}
		}
	}
	// TEXT may include ABI0 allocation padding beyond the declared logical end.
	// It cannot add owned/initialized bytes or extend an AMD64 field allocation.
	if scalarViews && x86OrdinaryParameterAddressRole(fn, sig, goarch) &&
		fn.ArgSize >= int64(frame) && fn.ArgSize <= 4096 {
		initial.logicalFrameParameters = true
		if goarch == "386" {
			initial.resultAddressSlots = []x86ResultSlotAddress{{start: 0, end: int64(frame), valid: true}}
		} else {
			for _, slot := range sig.Frame.Params {
				initial.resultAddressSlots = append(initial.resultAddressSlots, x86ResultSlotAddress{
					start: slot.Offset, end: slot.Offset + x86FrameScalarBytes(slot.Type, goarch), valid: true})
			}
		}
	}
	initial.callerAddressFP = initial.pointerFP // Immutable actual typed entry layout.
	if privateStack {
		stack, err := x86ResultPrivateFlagsSource(fn, goarch)
		if err != nil {
			return err
		}
		initial.valueStack = stack
	}
	autoExtent, scopedControl := 0, false
	if scalarViews {
		autoExtent, scopedControl = x86X87ScopedControlScratchExtent(fn, goarch)
	}
	if !scopedControl {
		var autoErr error
		autoExtent, autoErr = x86ResultAUTOExtentWithPrivateStack(fn, goarch, initial.valueStack != nil)
		if autoErr != nil {
			return autoErr
		}
	}
	initial.auto = make([]bool, autoExtent)
	owned := make([]bool, frame)
	for _, slot := range sig.Frame.Results {
		for offset := slot.Offset; offset < slot.Offset+x86ResultScalarBytes(slot.Type, goarch); offset++ {
			if owned[offset] {
				return fail("overlapping result fields")
			}
			owned[offset] = true
		}
	}
	parameterRoles := make(map[string]bool)
	for _, slot := range sig.Frame.Params {
		// Actual gc layout includes pointer storage even when no numeric
		// instruction consumes it. Occupancy prevents overlap, but pointer
		// bytes are deliberately not a numerical input or pointee witness.
		bytes := x86FrameScalarBytes(slot.Type, goarch)
		if bytes == 0 || slot.Offset < 0 || slot.Offset > int64(frame)-bytes || slot.Offset+bytes > resultOffset {
			return fail("parameter bytes or result boundary are not closed")
		}
		role, valid := x86ResultParameterRole(sig.Args, slot)
		if !valid || parameterRoles[role] {
			return fail("parameter leaf type/index disagrees with its actual argument")
		}
		parameterRoles[role] = true
		if initial.x87 != nil && initial.x87.word != nil && slot.Type == I16 {
			initial.x87.word.layout.parameters[slot.Offset] = true
		}
		for offset := int(slot.Offset); offset < int(slot.Offset+bytes); offset++ {
			if owned[offset] {
				return fail("overlapping typed frame slots")
			}
			owned[offset], initial.fp[offset] = true, slot.Type != Ptr
			if (canonicalBool || mixedBool) && slot.Type == I1 {
				initial.canonicalFP[offset] = true // The logical entry is actual I1, not an arbitrary NUM byte.
			}
		}
		if slot.Type == Ptr {
			// Both observers may transport an incoming opaque identity while
			// proving an independent numerical result. Neither marks these
			// bytes numerical or infers initialized pointee/native storage.
			initial.pointerFP[slot.Offset] = true
		}
	}
	// Go's omitted suffix is unknown, not an explicit zero-sized argument
	// frame. The independently checked declaration above still bounds inputs.
	if (fn.ArgSize != 0 || privateVoid && !x86TEXTArgumentsUnspecified(fn)) &&
		(fn.ArgSize < int64(frame) || fn.ArgSize > 4096) {
		return fail("TEXT argument extent disagrees with the typed result")
	}
	return checkX86ResultSourceFlowWithTrapOnly(fn, initial, owned, resultOffset, goarch, transfer,
		func(state x86ResultState, pc int) error {
			if state.x87 != nil && (state.x87.invalid || state.x87.depth != 0) {
				return fail("logical x87 value stack is not balanced at RET")
			}
			if trapOnly {
				return fail("trap-only logical shadow reaches an ordinary RET")
			}
			if state.continuation != nil && !state.continuation.checkReturn() {
				return fail("initializer does not write every code-table cell on every RET")
			}
			for offset := int(resultOffset); offset < frame; offset++ {
				if owned[offset] && !state.fp[offset] {
					return fail(fmt.Sprintf("result byte %d is not written on every path to RET %d", offset, pc))
				}
			}
			if canonicalBool || mixedBool {
				for _, slot := range sig.Frame.Results {
					if slot.Type == I1 && !state.canonicalFP[slot.Offset] {
						return fail(fmt.Sprintf("bool result byte %d is not canonical zero/one on every path to RET %d", slot.Offset, pc))
					}
				}
			}
			return nil
		}, trapOnly)
}

type x86ResultSourceTransfer func(int, Instr, *x86ResultState, []bool, int64, string) bool

type x86ResultFlowBudget struct {
	visits, bytes int
}

// The ABI owns entry bytes and the required return bytes. Instruction effects,
// dead-source validation, joins and fixed-point budgets are shared, so a new
// entry role cannot weaken the existing ABI0 result proof.
func checkX86ResultSourceFlow(fn Func, initial x86ResultState, owned []bool, resultOffset int64, goarch string,
	transfer x86ResultSourceTransfer, checkReturn func(x86ResultState, int) error) error {
	return checkX86ResultSourceFlowWithTrapOnly(fn, initial, owned, resultOffset, goarch, transfer, checkReturn, false)
}

func checkX86ResultSourceFlowWithTrapOnly(fn Func, initial x86ResultState, owned []bool, resultOffset int64, goarch string,
	transfer x86ResultSourceTransfer, checkReturn func(x86ResultState, int) error, trapOnly bool) error {
	originalTransfer := transfer
	var repeatEmptyBranch func(int, Instr, *x86ResultState) bool
	transfer = func(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
		if !x86ResultValueStackContinuation(ins, state, arch) {
			return false
		}
		popped := x86ResultPoppedWord{}
		var poppedOrigins [32]uint8
		if state.valueStack != nil {
			popped = state.valueStack.popped
			state.valueStack.popped = x86ResultPoppedWord{}
			if correlation := state.valueStack.correlation; correlation != nil {
				poppedOrigins = correlation.popped
				correlation.popped = [32]uint8{}
			}
		}
		spec, stack, _ := x86StackWidthProperties(ins, arch)
		popFlags := stack && spec.mode == amd64StackPopFlags
		if popFlags {
			// An independently accepted restore supplies no saved DF fact.
			// The actual checked private-stack transfer may establish a new
			// fact below, but must not inherit the pre-restore direction.
			state.direction = x86ResultDirectionUnknown
		}
		if !isAMD64ConditionalBranch(ins.Op) {
			state.bitScanPending = x86ResultBitScanPending{}
		}
		before := state.callerAddressGP
		origins := state.callerAddressOrigin
		predicate := state.predicate
		stringCount := state.stringCount
		ordinaryStep := false
		defer func() {
			if !ordinaryStep {
				state.shiftBits = x86ResultShiftBits{} // A private-stack/control transfer cannot preserve adjacency.
			}
		}()
		handled := false
		if state.continuation != nil {
			accepted, known := x86ContinuationResultStep(ordinal, ins, state, owned, arch)
			if known {
				if !accepted {
					return false
				}
				handled = true
			} else {
				if !x86ContinuationOrdinaryUses(ins, state, arch) {
					return false
				}
				defer x86ContinuationRevokeOverwrites(ins, state, arch)
			}
		}
		ordinary := func(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
			ordinaryStep = true
			if repeatEmptyBranch != nil && repeatEmptyBranch(ordinal, ins, state) {
				return true // Same empty result on both edges, never invented FLAGS.
			}
			return originalTransfer(ordinal, ins, state, owned, resultOffset, arch)
		}
		step := ordinary
		if state.valueStack != nil && state.valueStack.correlation != nil {
			step = func(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
				if accepted, known := x86ResultPrivateStackXORStep(ins, popped, poppedOrigins, state, owned, resultOffset, arch); known {
					return accepted
				}
				return ordinary(ordinal, ins, state, owned, resultOffset, arch)
			}
		}
		if popped.valid {
			previous := step
			step = func(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
				if accepted, known := x86ResultPoppedWordMaskStep(ins, popped, state, owned, resultOffset, arch); known {
					return accepted
				}
				return previous(ordinal, ins, state, owned, resultOffset, arch)
			}
		}
		if !handled && !x86DirectTailResultAddressTransfer(ins, state, owned, resultOffset, arch, step, ordinal) {
			return false
		}
		x86ResultX87After(ins, state, arch)
		if state.valueStack != nil && !x86ResultPreservesPrivateStorage(ins, arch) {
			state.valueStack.id = false
		}
		state.callerAddressGP = x86ResultCallerAddressesAfterTransfer(ins, before, state.callerAddressGP, state.callerAddressFP, arch)
		state.callerAddressOrigin = x86ResultCallerOriginsAfter(ins, origins, state.callerAddressGP, state.callerAddressFP, arch)
		state.predicate = x86ResultPredicateAfter(ins, predicate, arch)
		state.stringCount = x86ResultStringCountAfter(ins, stringCount, state.stringCount, arch)
		if !popFlags {
			state.direction = x86ResultDirectionAfterSource(ins, state.direction, arch)
		}
		x86ResultFlagsCorrelationAfter(ins, state, arch)
		return true
	}
	fail := func(reason string) error {
		return fmt.Errorf("%w: result initialization: %s", ErrProbeNeedsContext, reason)
	}
	labels := make(map[string]int)
	var instructions []Instr
	var ordinals []int
	for ordinal, ins := range fn.Instrs {
		if ins.Op == OpTEXT {
			continue
		}
		if ins.Op == OpLABEL {
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpLabel {
				return fail("malformed label")
			}
			if _, duplicate := labels[ins.Args[0].Sym]; duplicate {
				return fail("duplicate label")
			}
			labels[ins.Args[0].Sym] = len(instructions)
			continue
		}
		instructions = append(instructions, ins)
		ordinals = append(ordinals, ordinal)
	}
	if fn.x86DirectTailRoot != nil {
		instructions = fn.x86DirectTailRoot.instructions
		ordinals = fn.x86DirectTailRoot.ordinals
	}
	if fn.x86ContinuationFlow != nil {
		instructions = fn.x86ContinuationFlow.instructions
		ordinals = fn.x86ContinuationFlow.ordinals
	}
	if len(instructions) == 0 || len(instructions) > 4096 {
		return fail("missing or oversized source CFG")
	}
	// Discover private value-stack effects in the same complete, already
	// selected CFG used below, including source-bound private helpers.
	flagProjection := false
	for _, ins := range instructions {
		if spec, known, _ := x86StackWidthProperties(ins, goarch); known {
			if initial.valueStack == nil {
				initial.valueStack = new(x86ResultValueStack)
			}
			flagProjection = flagProjection || spec.mode == amd64StackPushFlags
		}
	}
	// One logical byte-work envelope includes FP/AUTO, numerical GP/Z/K,
	// canonical FP/GP bytes, status/DF, opaque GP and caller-address identities, and the source-shape discriminator. It is
	// not a bound on Go's heap/struct overhead. pointerFP is immutable shared
	// layout metadata, not a state payload copied at each CFG successor.
	// AUTO states do not obtain an independent frame or iteration budget.
	byteState := len(initial.fp) + len(initial.canonicalFP) + len(initial.auto) +
		len(initial.boolOutgoing) + len(initial.boolOutgoingCanonical) + len(initial.gp) + len(initial.canonicalGP) +
		8*len(initial.xmm) + len(initial.nativeMMX) + len(initial.masks) + 1 + len(initial.pointerGP) + len(initial.callerAddressGP) +
		2*len(initial.callerAddressOrigin) + 1 + 2 + 3 + 1 + 1 // Native string counter must-fact.
	byteState += 2  // One adjacent LEA register/byte-mask observation, never pointer/NUM bytes.
	byteState += 12 // One adjacent shift's input-byte bits and four typed byte fields.
	if len(initial.resultAddressSlots) != 0 {
		byteState += len(initial.resultAddressGP)*25 + 2
	}
	if initial.boolFrameGP != nil {
		byteState += len(initial.boolFrameGP) * 25
	}
	if initial.valueStack != nil {
		// Bit masks, two-byte depth, invalid join, ID and the ten-byte
		// transient popped register/validity/eight-byte initialized-bit view.
		byteState += x86ResultValueStackLimit(goarch) + 14
		// Pointer cell endpoints use complete bitmap words spanning the
		// bounded byte domain: 64 logical bytes on AMD64, 32 on mode32.
		byteState += ((x86ResultValueStackLimit(goarch) + 63) / 64) * 8
		if goarch == "amd64" {
			byteState += 8 // Existing W/Q source-cell identity; unused in mode32.
		}
		if flagProjection {
			byteState += x86ResultValueStackLimit(goarch) // Exact source-position refinement masks.
		}
		if initial.valueStack.correlation != nil {
			byteState += 8*x86ResultValueStackLimit(goarch) + 64
		}
	}
	if initial.continuation != nil {
		byteState += 16*48 + len(initial.continuation.written) + 2
	}
	if initial.x87 != nil {
		byteState += 1 + 1 + 1 + 2 + 2*len(initial.x87.gp) // slots, depth, invalid, status, captured bits.
		byteState += len(initial.x87.integer)              // Source signed bounds, not numerical representation.
		if initial.x87.word != nil {
			byteState += 2 // Control knownness only; actual parameter layout is immutable metadata.
		}
	}
	const byteWorkLimit = 64 << 20
	byteWork := len(instructions) * byteState
	if trapOnly {
		byteWork += len(instructions) * 16 // One bounded reverse-CFG termination check, not a per-state payload.
	}
	boundedWork := len(initial.auto) != 0 || len(initial.canonicalFP) != 0 ||
		len(initial.resultAddressSlots) != 0 || fn.x86DirectTailRoot != nil || initial.valueStack != nil ||
		initial.continuation != nil || initial.x87 != nil || trapOnly
	if boundedWork && byteWork > byteWorkLimit/8 {
		return fail("combined FP/AUTO source-CFG byte budget exhausted")
	}
	if budget := fn.x86ResultFlowBudget; budget != nil {
		budget.bytes += byteWork
		if budget.bytes > byteWorkLimit/8 {
			return fail("combined source-graph byte budget exhausted")
		}
	}
	// Validate effects and all static successors source-wide. Definedness is
	// proved below only for reachable paths; dead instructions must not hide
	// unknown effects, malformed branches or external entry requirements.
	top := initial.clone()
	top.shapeOnly = true
	for offset := range top.fp {
		top.fp[offset] = initial.fp[offset] || owned[offset] && int64(offset) >= resultOffset
	}
	for offset := range top.auto {
		top.auto[offset] = true
	}
	for offset := range top.boolOutgoing {
		top.boolOutgoing[offset], top.boolOutgoingCanonical[offset] = true, true
	}
	for index := range top.gp {
		top.gp[index] = 0xff
	}
	for index := range top.xmm {
		top.xmm[index] = 0xffff
		top.vectorUpper[index] = ^uint64(0xffff)
	}
	for index := range top.masks {
		top.masks[index] = true
	}
	top.flags = x86ByteFlagsAll
	edges := make([][]int, len(instructions))
	terminals := make([]bool, len(instructions))
	hasRepeat := false
	for pc, ins := range instructions {
		hasRepeat = hasRepeat || ins.Op == "REP" || ins.Op == "REPN"
		control := fn.x86DirectTailRoot.privateCallTransition(pc)
		if ins.Op == OpRET && !control {
			if len(ins.Args) != 0 {
				return fail("nonordinary return")
			}
			continue
		}
		if _, terminal, err := x86UndefinedTrapProperties(ins.Op, ins, goarch); !control && terminal && err == nil {
			terminals[pc] = true
			continue // A complete architectural trap has no input effects or normal successor.
		}
		shape := top.clone()
		if !control && !transfer(ordinals[pc], ins, &shape, owned, resultOffset, goarch) {
			return fail(fmt.Sprintf("unclosed source effect at instruction %d: %s", pc, ins.Raw))
		}
		next := []int{pc + 1}
		if fn.x86DirectTailRoot != nil {
			next = fn.x86DirectTailRoot.edges[pc]
		} else if fn.x86ContinuationFlow != nil {
			next = fn.x86ContinuationFlow.edges[pc]
		} else if ins.Op == OpJMP || isAMD64ConditionalBranch(ins.Op) {
			args := x86DirectTailBranchArgs(ins)
			if len(args) != 1 {
				return fail("unbound branch operands")
			}
			arg := args[0]
			label := arg.Sym
			if arg.Kind == OpIdent {
				label = arg.Ident
			}
			target, found := labels[label]
			if arg.Kind == OpMem {
				// Named Go n(PC) counts source instructions, just as the
				// emitter's flat block positions do. No raw/indirect address
				// or external target may acquire this ordinary CFG edge.
				memory := arg.Mem
				found = x86ResultNamedPredicateInstruction(ins) &&
					reflect.DeepEqual(memory, MemRef{Base: "PC", Off: memory.Off}) &&
					memory.Off >= -int64(pc) && memory.Off < int64(len(instructions)-pc)
				if found {
					target = pc + int(memory.Off)
				}
			} else {
				found = found && (arg.Kind == OpLabel || arg.Kind == OpIdent)
			}
			if !found {
				return fail("indirect, external or unresolved branch")
			}
			if ins.Op == OpJMP {
				next = []int{target}
			} else {
				next = append(next, target)
			}
		}
		for _, target := range next {
			if target < 0 || target >= len(instructions) {
				return fail("source falls outside its continuation")
			}
		}
		edges[pc] = next
	}
	states := map[int]x86ResultState{0: initial}
	queue := []int{0}
	returned := false
	trapped := false
	visits, sourceWork := 0, byteWork
	repeatEmptyUsed := false
	if hasRepeat && fn.x86DirectTailRoot == nil && fn.x86ContinuationFlow == nil {
		positions, previous := make(map[int]int), make([]int, len(instructions))
		for pc, ordinal := range ordinals {
			positions[ordinal], previous[pc] = pc, -1
		}
		for from, successors := range edges {
			for _, to := range successors {
				if previous[to] == -1 {
					previous[to] = from
				} else if previous[to] != from {
					previous[to] = -2
				}
			}
		}
		repeatEmptyBranch = func(ordinal int, ins Instr, state *x86ResultState) bool {
			required := x86ByteBranchFlags(ins.Op)
			if required == 0 || state.flags&required == required || state.shapeOnly ||
				state.valueStack != nil || state.x87 != nil || !isAMD64ConditionalBranch(ins.Op) {
				return false
			}
			pc, found := positions[ordinal]
			if !found {
				return false
			}
			accepted, steps := x86ResultRepeatEmptyBranch(instructions, edges, previous, pc, owned, resultOffset, goarch)
			visits, sourceWork = visits+steps, sourceWork+steps*byteState
			if budget := fn.x86ResultFlowBudget; budget != nil {
				budget.visits, budget.bytes = budget.visits+steps, budget.bytes+steps*byteState
				accepted = accepted && budget.visits < 16384 && budget.bytes <= byteWorkLimit
			}
			accepted = accepted && visits < 16384 && sourceWork <= byteWorkLimit
			repeatEmptyUsed = repeatEmptyUsed || accepted
			return accepted
		}
	}
	for ; len(queue) != 0; visits++ {
		if visits >= 16384 {
			return fail("must-defined fixed-point budget exhausted")
		}
		if budget := fn.x86ResultFlowBudget; budget != nil {
			budget.visits++
			budget.bytes += 8 * byteState
			if budget.visits > 16384 || budget.bytes > byteWorkLimit {
				return fail("combined source-graph must-defined budget exhausted")
			}
		}
		// A later dead-external-input proof shares this function's actual
		// visits and byte work, including normally unbounded scalar views.
		sourceWork += 8 * byteState
		if repeatEmptyUsed && sourceWork > byteWorkLimit {
			return fail("empty-repeat source-CFG byte budget exhausted")
		}
		if boundedWork {
			byteWork += 8 * byteState // conservative bound for copies and joins
			if byteWork > byteWorkLimit {
				return fail("combined FP/AUTO must-defined byte budget exhausted")
			}
		}
		pc := queue[0]
		queue = queue[1:]
		state := states[pc].clone()
		ins := instructions[pc]
		if fn.x86DirectTailRoot != nil && fn.x86DirectTailRoot.externalTails[pc] {
			if state.valueStack != nil && (state.valueStack.invalid || len(state.valueStack.bytes) != 0) {
				return fail("external terminal cannot consume the private value stack")
			}
			if state.resultAddressWritten {
				return fail("external terminal could observe a prior logical result write")
			}
			returned = true
			continue // Exact independent callee return, no invented root FP bytes.
		}
		control := fn.x86DirectTailRoot.privateCallTransition(pc)
		if ins.Op == OpRET && !control {
			if len(ins.Args) != 0 {
				return fail("nonordinary return")
			}
			returned = true
			continue // Check results after the complete fixed point, never early.
		}
		if terminals[pc] {
			trapped = true
			continue // Earlier reachable instructions have already consumed their original state.
		}
		if control {
			// Real registers/FLAGS flow through the original helper body. These
			// source-adjacency observations cannot cross CALL or its private RET.
			state.shiftBits = x86ResultShiftBits{}
			state.bitScanPending = x86ResultBitScanPending{}
			state.nativeLEAAddressBits = x86NativeLEAAddressBits{}
		} else if !transfer(ordinals[pc], ins, &state, owned, resultOffset, goarch) {
			return fail(fmt.Sprintf("unknown effect or undefined input at instruction %d: %s", pc, ins.Raw))
		}
		for edge, target := range edges[pc] {
			nextState := x86ResultPredicateEdge(state, ins, edge)
			if previous, visited := states[target]; visited {
				merged := previous.intersect(nextState)
				if reflect.DeepEqual(previous, merged) {
					continue
				}
				states[target] = merged
			} else {
				states[target] = nextState.clone()
			}
			queue = append(queue, target)
		}
	}
	if err := x86ResultCheckDeadExternalInputs(fn, instructions, ordinals, edges, states,
		owned, resultOffset, goarch, transfer, &visits, &sourceWork, byteState); err != nil {
		return err
	}
	if trapOnly && !x86ResultAllPathsTerminateInTrap(instructions, edges, states, goarch) {
		return fail("trap-only logical shadow has a reachable non-trap continuation or cycle")
	}
	if !returned && !trapped {
		return fail("no ordinary reachable RET")
	}
	for pc, state := range states {
		if instructions[pc].Op != OpRET || fn.x86DirectTailRoot.privateCallTransition(pc) {
			continue
		}
		if state.valueStack != nil && (state.valueStack.invalid || len(state.valueStack.bytes) != 0) {
			return fail("private value stack is not balanced at RET")
		}
		if err := checkReturn(state, pc); err != nil {
			return err
		}
	}
	return nil
}

func x86ResultScalarBytes(typ LLVMType, arch string) int64 {
	if typ == Ptr {
		return 0 // Initialized pointer bits do not close a Go result/GC contract.
	}
	return x86FrameScalarBytes(typ, arch)
}

type x86ResultState struct {
	fp   []bool
	auto []bool
	gp   [16]uint8
	// Canonical FP is allocated only for the independent bounded ABI0 bool
	// role. It neither replaces numerical initialization nor extends FP slots.
	canonicalFP                         []bool
	boolFrameSlots                      []FrameSlot               // Immutable declared logical fields, not native backing.
	boolFrameGP                         *[16]x86ResultSlotAddress // Separate alias domain; never resultAddressGP/caller/native.
	boolCalls                           *x86ABI0BoolCallPlan      // Immutable original call-site/declaration observations.
	boolOutgoing, boolOutgoingCanonical []bool
	boolReadonlyInputs                  bool // Only the independent readonly callee proof.
	// Used by the independent register/ABI0 bool-result contracts.
	// A set bit means that physical byte is exactly 0/1, not merely initialized.
	canonicalGP [16]uint8
	xmm         [32]uint16 // high banks are consumed only by validated mode-bound forms
	nativeMMX   [8]uint8   // Only a source-bound actual native region may transfer this bank.
	// The disjoint upper 48 byte bits share the same physical X/Y/Z bank.
	// Existing low-X effects preserve these bits unless their typed encoding
	// explicitly clears the upper aliases.
	vectorUpper          [32]uint64
	masks                [8]bool // used only by the private scalar bit-view transfer
	flags                uint8
	direction            x86ResultDirection          // DF only; no numerical/status/pointer permission.
	stringCount          x86ResultStringCount        // Full native CX zero/nonzero; never NUM or a memory role.
	valueStack           *x86ResultValueStack        // Private numerical storage; never physical SP or an entry slot.
	x87                  *x86ResultX87State          // Private logical availability; never hardware entry/control state.
	continuation         *x86ContinuationResultState // Separate opaque control/table identities, never NUM/native storage.
	bitScanPending       x86ResultBitScanPending
	predicate            x86ResultPredicate
	nativeLEAAddressBits x86NativeLEAAddressBits
	shiftBits            x86ResultShiftBits

	// Incoming pointer identities are not numerical register bytes. This is
	// only an initialization observation, never a pointee/backing permission.
	pointerFP map[int64]bool // immutable after deriving the actual ABI0 layout
	pointerGP [16]bool
	// A separate actual typed-entry address-bit domain. SDK literal/OR
	// carriers never seed it; no numerical GP or memory facts follow.
	callerAddressFP        map[int64]bool // immutable shared entry layout
	callerAddressGP        [16]bool
	callerAddressOrigin    [16]uint16
	resultAddressSlots     []x86ResultSlotAddress // Immutable root-local scalar layout.
	resultAddressGP        [16]x86ResultSlotAddress
	resultAddressWritten   bool // May-write join, not an initialized-result fact.
	logicalFrameParameters bool // Immutable private numeric parameter-copy role; never caller storage.
	shapeOnly              bool // source-wide effect validation, never a reaching state

	// Temporary numerical inputs for one guarded transfer. The consumer
	// independently binds the actual DATA; these facts cannot establish a
	// caller, raw-return, pointer or declaration-only query permission.
	// Clear them before any state escapes into the CFG.
	loweredStaticReads   map[x86StaticSBAddress]int64
	goReadOnlyRead       *goReadOnlyRead
	literalMemoryOperand *Operand
	literalMemoryBytes   int64
}

func (state x86ResultState) clone() x86ResultState {
	state.fp = append([]bool(nil), state.fp...)
	state.canonicalFP = append([]bool(nil), state.canonicalFP...)
	state.boolOutgoing = append([]bool(nil), state.boolOutgoing...)
	state.boolOutgoingCanonical = append([]bool(nil), state.boolOutgoingCanonical...)
	if state.boolFrameGP != nil {
		aliases := *state.boolFrameGP
		state.boolFrameGP = &aliases
	}
	state.auto = append([]bool(nil), state.auto...)
	if state.x87 != nil {
		copy := *state.x87
		state.x87 = &copy
		if state.x87.word != nil {
			word := *state.x87.word
			state.x87.word = &word
		}
	}
	if state.valueStack != nil {
		stack := *state.valueStack
		stack.bytes = append([]uint8(nil), stack.bytes...)
		stack.refinable = append([]uint8(nil), stack.refinable...)
		if stack.correlation != nil {
			copy := *stack.correlation
			copy.bytes = append([][8]uint8(nil), copy.bytes...)
			stack.correlation = &copy
		}
		state.valueStack = &stack
	}
	if state.continuation != nil {
		copy := *state.continuation
		copy.written = append([]bool(nil), copy.written...)
		state.continuation = &copy
	}
	state.loweredStaticReads = nil
	state.goReadOnlyRead = nil
	state.literalMemoryOperand, state.literalMemoryBytes = nil, 0
	return state
}

func (state x86ResultState) intersect(other x86ResultState) x86ResultState {
	merged := state.clone()
	if merged.shiftBits != other.shiftBits {
		merged.shiftBits = x86ResultShiftBits{}
	}
	if merged.x87 == nil && other.x87 != nil {
		merged.x87 = &x86ResultX87State{invalid: true}
	} else if merged.x87 != nil {
		if other.x87 == nil || merged.x87.invalid || other.x87.invalid || merged.x87.depth != other.x87.depth {
			// An unknown value-stack shape revokes hardware facts, not the
			// same immutable ABI layout independently present on both edges.
			sharedLayout := other.x87 != nil && merged.x87.word != nil && other.x87.word != nil &&
				merged.x87.word.layout != nil && merged.x87.word.layout == other.x87.word.layout
			merged.x87.revoke()
			if !sharedLayout {
				merged.x87.word = nil
			}
		} else {
			merged.x87.slots &= other.x87.slots
			merged.x87.status &= other.x87.status
			for index := range merged.x87.integer {
				if merged.x87.slots&(1<<uint(index)) == 0 || merged.x87.integer[index] == 0 || other.x87.integer[index] == 0 {
					merged.x87.integer[index] = 0
				} else if other.x87.integer[index] > merged.x87.integer[index] {
					merged.x87.integer[index] = other.x87.integer[index]
				}
			}
			for index := range merged.x87.gp {
				merged.x87.gp[index] &= other.x87.gp[index]
			}
			if merged.x87.word != nil && other.x87.word != nil && merged.x87.word.layout == other.x87.word.layout {
				merged.x87.word.control &= other.x87.word.control
			} else if merged.x87.word != nil || other.x87.word != nil {
				*merged.x87 = x86ResultX87State{invalid: true}
			}
		}
	}
	if merged.continuation == nil && other.continuation != nil {
		copy := other.clone()
		merged.continuation = copy.continuation
		merged.continuation.invalid = true
	}
	if merged.continuation != nil && (other.continuation == nil || merged.continuation.flow != other.continuation.flow ||
		len(merged.continuation.written) != len(other.continuation.written) || merged.continuation.invalid || other.continuation.invalid) {
		merged.continuation.invalid = true
		merged.continuation.gp = [16]x86ContinuationAddress{}
		merged.continuation.tablesValid = false
		for index := range merged.continuation.written {
			merged.continuation.written[index] = false
		}
	} else if merged.continuation != nil {
		for index := range merged.continuation.gp {
			left, right := merged.continuation.gp[index], other.continuation.gp[index]
			if left != right {
				if left.kind == 2 && right.kind == 2 && left.root != "" && left.root == right.root {
					// Every finite helper successor is already part of this root's
					// authenticated CFG. Preserve only that shared opaque role.
					merged.continuation.gp[index] = x86ContinuationAddress{kind: 2, root: left.root}
				} else {
					merged.continuation.gp[index] = x86ContinuationAddress{}
				}
			}
		}
		for index := range merged.continuation.written {
			merged.continuation.written[index] = merged.continuation.written[index] && other.continuation.written[index]
		}
		merged.continuation.tablesValid = merged.continuation.tablesValid && other.continuation.tablesValid
	}
	for index := range merged.boolOutgoing {
		merged.boolOutgoing[index] = index < len(other.boolOutgoing) && merged.boolOutgoing[index] && other.boolOutgoing[index]
		merged.boolOutgoingCanonical[index] = index < len(other.boolOutgoingCanonical) && merged.boolOutgoingCanonical[index] && other.boolOutgoingCanonical[index]
	}
	for index := range merged.fp {
		merged.fp[index] = merged.fp[index] && other.fp[index]
	}
	for index := range merged.canonicalFP {
		merged.canonicalFP[index] = index < len(other.canonicalFP) && merged.canonicalFP[index] && other.canonicalFP[index]
	}
	if merged.boolFrameGP != nil {
		for index := range merged.boolFrameGP {
			if other.boolFrameGP == nil || merged.boolFrameGP[index] != other.boolFrameGP[index] {
				merged.boolFrameGP[index] = x86ResultSlotAddress{}
			}
		}
	}
	for index := range merged.auto {
		merged.auto[index] = merged.auto[index] && other.auto[index]
	}
	for index := range merged.gp {
		merged.gp[index] &= other.gp[index]
		merged.canonicalGP[index] &= other.canonicalGP[index]
		merged.pointerGP[index] = merged.pointerGP[index] && other.pointerGP[index]
		merged.callerAddressGP[index] = merged.callerAddressGP[index] && other.callerAddressGP[index]
		if merged.callerAddressOrigin[index] != other.callerAddressOrigin[index] || !merged.callerAddressGP[index] {
			merged.callerAddressOrigin[index] = 0
		}
		if merged.resultAddressGP[index] != other.resultAddressGP[index] {
			merged.resultAddressGP[index] = x86ResultSlotAddress{}
		}
	}
	for index := range merged.xmm {
		merged.xmm[index] &= other.xmm[index]
		merged.vectorUpper[index] &= other.vectorUpper[index]
	}
	for index := range merged.nativeMMX {
		merged.nativeMMX[index] &= other.nativeMMX[index]
	}
	for index := range merged.masks {
		merged.masks[index] = merged.masks[index] && other.masks[index]
	}
	merged.flags &= other.flags
	merged.direction = state.direction.intersect(other.direction)
	if merged.stringCount != other.stringCount {
		merged.stringCount = x86StringCountUnknown
	}
	if merged.valueStack != nil {
		if other.valueStack == nil || merged.valueStack.invalid || other.valueStack.invalid ||
			len(merged.valueStack.bytes) != len(other.valueStack.bytes) ||
			merged.valueStack.wordCells != other.valueStack.wordCells {
			merged.valueStack.bytes, merged.valueStack.invalid = nil, true
			merged.valueStack.refinable = nil
			merged.valueStack.wordCells = 0
			merged.valueStack.pointerCells = [8]uint64{}
		} else {
			for index := range merged.valueStack.pointerCells {
				merged.valueStack.pointerCells[index] &= other.valueStack.pointerCells[index]
			}
			if merged.valueStack.refinable != nil || other.valueStack.refinable != nil {
				left, right := merged.valueStack.refinable, other.valueStack.refinable
				if left == nil {
					left = merged.valueStack.bytes
				}
				if right == nil {
					right = other.valueStack.bytes
				}
				merged.valueStack.refinable = make([]uint8, len(merged.valueStack.bytes))
				for index := range merged.valueStack.refinable {
					merged.valueStack.refinable[index] = left[index] & right[index]
				}
			}
			for index := range merged.valueStack.bytes {
				merged.valueStack.bytes[index] &= other.valueStack.bytes[index]
			}
			merged.valueStack.id = merged.valueStack.id && other.valueStack.id
		}
		if other.valueStack == nil || merged.valueStack.invalid ||
			merged.valueStack.popped.register != other.valueStack.popped.register ||
			!merged.valueStack.popped.valid || !other.valueStack.popped.valid {
			merged.valueStack.popped = x86ResultPoppedWord{}
		} else {
			merged.valueStack.popped.bits &= other.valueStack.popped.bits
		}
		x86ResultIntersectFlagsCorrelation(merged.valueStack, other.valueStack)
	}
	if merged.bitScanPending != other.bitScanPending {
		merged.bitScanPending = x86ResultBitScanPending{}
	}
	if merged.predicate != other.predicate {
		merged.predicate = x86ResultPredicate{}
	}
	if merged.nativeLEAAddressBits != other.nativeLEAAddressBits {
		merged.nativeLEAAddressBits = x86NativeLEAAddressBits{}
	}
	merged.resultAddressWritten = state.resultAddressWritten || other.resultAddressWritten
	return merged
}

// A logical source view never imports a physical stack/frame role. BP is an
// ordinary GP in mode32; explicit native-frame bindings remain separate.
func x86LogicalSourceFrameRegister(reg Reg, arch string) bool {
	return reg == SP || reg == BP && arch != "386"
}

func x86ResultGP(reg Reg, width int64, arch string) (int, uint8, bool) {
	root, valid := x86CallerGP(reg)
	// This observer admits only ABI0. Its R14 entry bytes are undefined,
	// unlike ABIInternal's opaque g identity; only explicit source writes can
	// initialize them. No caller/source-stack/native permissions are changed.
	// BP is an ordinary caller-clobbered GP in mode32. Its entry bytes are
	// still unknown; only the existing typed writes can define NUM or opaque
	// pointer facts. Physical source-stack/fixed-local roles remain separate.
	if !valid || x86LogicalSourceFrameRegister(root, arch) || width == 8 && arch == "386" {
		return 0, 0, false
	}
	if width != 1 && root != reg || width == 1 && !isGoYmbRegisterForArch(reg, arch) {
		return 0, 0, false
	}
	for index, candidate := range []Reg{AX, CX, DX, BX, SP, BP, SI, DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
		if root == candidate && (arch != "386" || index < 8) {
			mask := x86CallerByteMask(reg, width)
			return index, mask, mask != 0
		}
	}
	return 0, 0, false
}

func x86ResultRead(arg Operand, width int64, state *x86ResultState, owned []bool, arch string) bool {
	if state.literalMemoryOperand != nil && width > 0 && width <= state.literalMemoryBytes && reflect.DeepEqual(arg, *state.literalMemoryOperand) {
		return true
	}
	if address, valid := x86StaticSBReadAddress(arg, arch); valid {
		return width > 0 && state.loweredStaticReads[address] >= width || state.goReadOnlyRead.allows(arg, width)
	}
	switch arg.Kind {
	case OpImm:
		return arg.ImmRaw == "" && !arg.ImmIsFloat
	case OpReg:
		if width == 16 {
			index, valid := amd64ParseXReg(arg.Reg)
			return valid && index < 16 && (arch != "386" || index < 8) && state.xmm[index] == 0xffff
		}
		index, mask, valid := x86ResultGP(arg.Reg, width, arch)
		return valid && state.gp[index]&mask == mask
	case OpFP:
		if arg.FPOffset < 0 || width > int64(len(owned)) || arg.FPOffset > int64(len(owned))-width {
			return false
		}
		for offset := arg.FPOffset; offset < arg.FPOffset+width; offset++ {
			if !owned[offset] || !state.fp[offset] {
				return false
			}
		}
		return true
	case OpMem:
		offset, valid := x86ResultAUTOOffset(arg, width, len(state.auto))
		if !valid {
			return false // An initialized pointer does not initialize its pointee.
		}
		for index := offset; index < offset+int(width); index++ {
			if !state.auto[index] {
				return false
			}
		}
		return true
	}
	return false
}

func x86ResultStore(arg Operand, width int64, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
	if arg.Kind == OpMem {
		offset, valid := x86ResultAUTOOffset(arg, width, len(state.auto))
		if !valid {
			return false
		}
		for index := offset; index < offset+int(width); index++ {
			state.auto[index] = true
		}
		return true
	}
	if arg.Kind == OpReg {
		if width == 16 {
			index, valid := amd64ParseXReg(arg.Reg)
			if !valid || index >= 16 || arch == "386" && index >= 8 {
				return false
			}
			state.xmm[index] = 0xffff
			return true
		}
		index, mask, valid := x86ResultGP(arg.Reg, width, arch)
		if valid {
			state.pointerGP[index] = false
			state.gp[index] |= mask
			if width == 4 || width == 8 {
				state.gp[index] = 0xff
			}
		}
		return valid
	}
	if arg.Kind != OpFP || arg.FPOffset < resultOffset || width > int64(len(owned)) || arg.FPOffset > int64(len(owned))-width {
		return false
	}
	for offset := arg.FPOffset; offset < arg.FPOffset+width; offset++ {
		if !owned[offset] {
			return false
		}
	}
	for offset := arg.FPOffset; offset < arg.FPOffset+width; offset++ {
		state.fp[offset] = true
	}
	return true
}

func x86ResultTransfer(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
	if accepted, known := x86ResultAlternatingFloatStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultRoundStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultVSIBStep(ins, state, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultImplicitMaskMoveStep(ins, state, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultImmediateBlendStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultNamedHalfStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedPrecisionStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultBlendMinposStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultXLATStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultFourSourceStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultFMA3Step(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultScalarPrecisionStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedAbsSignStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultScalarReciprocalStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedReciprocalStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultUnalignedLoadStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultMoveHalfStep(ins, state, owned, resultOffset, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedReductionStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultDuplicateMoveStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultSegmentQueryStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultIntegerMinMaxStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultMaskBlendStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultFloatingHelperStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedAlignStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultSqrtStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultSADStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultScalarBitFieldStep(ins, state, owned, resultOffset, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedNarrowStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultSingleSourceNarrowStep(ins, state, owned, resultOffset, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultSignedPackedFloatStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedWordMultiplyStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultPackedAverageStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultPackedBitCountStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultGFNIStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultIndexedPermuteStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultIFMAStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultPackedDotStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPermute128Step(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultElementPermuteStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultQwordLookupStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if form, oldInput, known, err := x86FixedVectorValueProperties(ins, arch); known {
		return err == nil && x86ResultFixedVectorInputs(ins, form, oldInput, state, owned, arch)
	}
	if accepted, known := x86ResultCompactExpandStep(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if accepted, known := x86ResultByteSwapStep(ins, state, arch); known {
		return accepted
	}
	if accepted, known := x86ResultValueStackStep(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if accepted, known := x86ResultSignedIntegerFloatStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultUnsignedIntegerFloatStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedStringStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultDirectionStep(ins, state, arch); known {
		return accepted
	}
	if accepted, known := x86ResultVectorTestStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultBitScanStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultNumericalReadStep(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if accepted, known := x86ResultPackedZeroExtendStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedSignExtendStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultVectorArithmeticStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultByteShuffleStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultPackedUnpackStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultImmediateShuffleStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultPackedFloatShuffleStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultPackedLowMultiplyStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultMoveMaskStep(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if accepted, known := x86ResultPackedConversionStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultCOMIStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultScalarFloatIntegerStep(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if _, known, err := x86DirectiveProperties(ins); known {
		return err == nil // Numerical only; never native layout/caller authority.
	}
	if accepted, known := x86ResultTernaryLogicStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultVectorCompareStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultPackedTestMaskStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if form, known, err := x86VectorZeroProperties(ins, arch); known {
		if err != nil {
			return false
		}
		zeroed := ^x86CallerVectorByteMask(int64(form.spec.firstByte))
		for register := 0; register < form.registers; register++ {
			state.writeVector(register, 64, state.vectorBytes(register)|zeroed, false)
		}
		return true
	}
	if accepted, known := x86ResultPackedShiftStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultCLMULStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultBroadcastStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultSwapStep(ins, state, arch); known {
		return accepted
	}
	// Share validated source move effects through a local value. The original
	// operand direction, mode and native certificates remain independently
	// checked; no source spelling acquires the other move's operand grammar.
	ins = x86SourceMoveInstruction(ins, arch)
	if form, known, err := x86GPSIMDTransferProperties(ins, arch); known &&
		len(ins.Args) == 2 && ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpReg {
		// Share numerical register effects, not the private observer's
		// separate FP/AUTO/SB memory roles or any native/caller permission.
		return err == nil && x86ResultGPSIMDTransfer(ins, form, state, owned, resultOffset, arch)
	}
	if accepted, recognized := x86ResultScalarLaneStep(ins, state, owned, resultOffset, arch); recognized {
		return accepted
	}
	if accepted, known := x86ResultSHAStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultAESStep(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultCallerAddressTest(ins, state, owned, arch); known {
		return accepted
	}
	if accepted, known := x86ResultCallerAddressDifferenceStep(ins, state, arch); known {
		return accepted
	}
	if accepted, known := x86ResultPointerResidueStep(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if accepted, known := x86ResultCallerPointerAdvanceStep(ins, state, arch); known {
		return accepted
	}
	if accepted, recognized := x86ResultIncomingPointerTransfer(ins, state, owned, arch); recognized {
		return accepted
	}
	if ins.Op == OpJMP {
		return true // The CFG checks its complete target independently.
	}
	if accepted, known := x86ResultCounterControlStep(ins, state, owned, arch); known {
		return accepted
	}
	if isAMD64ConditionalBranch(ins.Op) {
		required := x86ByteBranchFlags(ins.Op)
		return required != 0 && state.flags&required == required
	}
	if ins.Op == "NOP" {
		return len(ins.Args) == 0
	}
	if form, recognized, err := x86ConditionalSetProperties(ins.Op, ins, arch); recognized {
		required := x86ByteConditionFlags(form.condition)
		return err == nil && required != 0 && state.flags&required == required && x86ResultStore(form.destination, 1, state, owned, resultOffset, arch)
	}
	if effect, recognized, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); recognized {
		if err != nil || effect.dynamicMemory || state.flags&effect.flagsRead != effect.flagsRead {
			return false
		}
		// Read all ordered inputs before any overwrite. A three-operand
		// multiply does not read its old result, unlike two-operand IMUL.
		for _, operand := range effect.operands {
			if operand.read && !x86ResultRead(operand.operand, operand.width, state, owned, arch) {
				return false
			}
		}
		for _, operand := range effect.operands {
			if operand.write && !x86ResultStore(operand.operand, operand.width, state, owned, resultOffset, arch) {
				return false
			}
		}
		state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
		return true
	}
	if width := x86RawReturnScalarMoveBytes(ins.Op); width != 0 {
		return !(width == 8 && arch == "386") && len(ins.Args) == 2 && !(ins.Args[0].Kind == OpFP && ins.Args[1].Kind == OpFP) &&
			x86ResultRead(ins.Args[0], width, state, owned, arch) &&
			x86ResultStore(ins.Args[1], width, state, owned, resultOffset, arch)
	}
	if accepted, known := x86ResultLegacyScalarMoveStep(ins, state, owned, resultOffset, arch, false); known {
		return accepted
	}
	// Registered scalar RMW instructions are handled by the typed effect above.
	// Comparisons share the emitter's complete grammar and physical byte views.
	comparison, recognized, err := x86ScalarCompareProperties(ins.Op, ins, arch)
	if !recognized || err != nil {
		return false
	}
	width := int64(comparison.bits / 8)
	if !x86ResultRead(comparison.args[0], width, state, owned, arch) || !x86ResultRead(comparison.args[1], width, state, owned, arch) {
		return false
	}
	state.flags = x86ByteFlagsAll
	if comparison.test {
		state.flags &^= x86ByteFlagAF // The architecture leaves AF undefined.
	}
	return true
}
