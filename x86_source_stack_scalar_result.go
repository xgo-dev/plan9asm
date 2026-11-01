package plan9asm

import (
	"reflect"
	"strings"
)

// This state belongs only to the already bounded physical source-stack CFG.
// It grants neither ordinary logical ABI0 entry nor caller/native memory. NUM
// and canonical bytes stay independent, including intermediate raw 2/3 values.
type x86SourceStackScalarState struct {
	bytes           x86ResultState
	owned           []bool // Immutable actual scalar layout.
	result          int64
	width           int64
	canonicalResult bool
}

type x86SourceStackScalarProof struct {
	owner             *x86SourceStackProof
	minimum           int64
	word              int64
	stackIdentity     [32]byte
	countedIterations [4]int
	signature         [32]byte
	function          [32]byte
	original          []Instr
	normalized        []Instr
}

// A cost/denial predicate only. A stack-unobserved raw RET still transports
// physical ABI0 bool bytes; omitting explicit SP syntax cannot bypass the
// independent producer. Zero-argument/custom/native entries remain separate.
func x86SourceStackBoolCandidate(fn Func, sig FuncSig) bool {
	return fn.FrameSize == 0 && !strings.Contains(fn.Sym, "<") && sig.Ret == I1 &&
		len(sig.Args) != 0 && len(sig.ArgRegs) == 0 && len(sig.Frame.Results) == 1 && sig.Frame.Results[0].Type == I1
}

func x86SourceStackScalarArch(arch string) string {
	if arch == "" {
		return "amd64" // The existing ArchAMD64 renderer default, not an Options/source rewrite.
	}
	return arch
}

func x86SourceStackScalarInitial(fn Func, sig FuncSig, arch string) *x86SourceStackScalarState {
	arch = x86SourceStackScalarArch(arch)
	if (arch != "386" && arch != "amd64") || fn.FrameSize != 0 || strings.Contains(fn.Sym, "<") || fn.ArgSize > 4096 ||
		!x86SourceStackScalarABI0(sig, fn.ArgSize, arch) || sig.ARMEntry != nil ||
		sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.WASMContext != "" || sig.WASMNative ||
		sig.x86CallerRegions != nil || sig.x86FixedLocal != nil || sig.x86BorrowedBoolTail {
		return nil
	}
	result := sig.Frame.Results[0]
	width := x86FrameScalarBytes(result.Type, arch)
	if result.Index != 0 || result.Field != -1 || len(result.Fields) != 0 || result.Offset < 0 ||
		width <= 0 || result.Offset > 4096-width {
		return nil
	}
	state := &x86SourceStackScalarState{result: result.Offset, width: width, canonicalResult: sig.Ret == I1,
		owned: make([]bool, result.Offset+width)}
	state.bytes.fp = make([]bool, len(state.owned))
	state.bytes.canonicalFP = make([]bool, len(state.owned))
	for offset := result.Offset; offset < result.Offset+width; offset++ {
		state.owned[offset] = true
	}
	for _, slot := range sig.Frame.Params {
		width := x86FrameScalarBytes(slot.Type, arch)
		if slot.Offset < 0 || slot.Offset > result.Offset-width {
			return nil
		}
		for offset := slot.Offset; offset < slot.Offset+width; offset++ {
			if state.owned[offset] {
				return nil
			}
			state.owned[offset], state.bytes.fp[offset] = true, true
			state.bytes.canonicalFP[offset] = slot.Type == I1
		}
	}
	return state
}

func (state *x86SourceStackScalarState) clone() *x86SourceStackScalarState {
	if state == nil {
		return nil
	}
	copy := *state
	copy.bytes = state.bytes.clone()
	return &copy
}

// Run only after the existing physical SP/BP, access and FLAGS producer has
// checked this exact instruction. Its access annotations are not public FP
// permission: only this local byte-effect copy uses their exact slot offsets.
func (state *x86SourceStackScalarState) step(ins Instr, arch string) bool {
	arch = x86SourceStackScalarArch(arch)
	if ins.Op == OpTEXT || ins.Op == OpLABEL {
		return true
	}
	if _, stack := amd64StackWidthSpecs[ins.Op]; stack {
		return true // Its saved NUM/canonical/FLAGS payload was transported together.
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpReg && x86RawReturnStackRegister(operand.Reg) {
			// The producer allows only its exact SP/BP control effects here.
			// Physical address arithmetic cannot define numerical status bits.
			if effect, known, _ := x86TypedInstructionByteEffect(ins.Op, ins, arch); known {
				state.bytes.flags &^= effect.flagsDefined | effect.flagsKilled
			}
			return true
		}
	}
	local := ins
	local.Args = append([]Operand(nil), ins.Args...)
	for index, offset := range ins.x86SourceStackFP {
		if index < 0 || index >= len(local.Args) || local.Args[index].Kind != OpMem {
			return false
		}
		local.Args[index] = Operand{Kind: OpFP, FPOffset: offset}
	}
	beforeFP, beforeGP := state.bytes.canonicalFP, state.bytes.canonicalGP
	next := state.bytes.clone()
	if arch == "amd64" && x86RawDwordLiteralInput(ins) {
		// The decoder-bound four-byte input belongs to this instruction
		// only. Typed MOVL/MOVLQSX effects retain their distinct extension;
		// the raw-return guard separately checks the actual DATA object.
		next.literalMemoryOperand, next.literalMemoryBytes = &ins.Args[0], 4
	}
	accepted := x86ResultTransfer(local, &next, state.owned, state.result, arch)
	next.literalMemoryOperand, next.literalMemoryBytes = nil, 0
	if !accepted {
		// An unobserved nontrapping scratch result may remain unknown. This
		// does not excuse later result, store, address or FLAGS observations.
		next = state.bytes.clone()
		if !x86LoweredPureGPUnknownTransfer(local, &next, arch) {
			return false
		}
	}
	state.bytes = next
	state.bytes.canonicalFP, state.bytes.canonicalGP = x86ABI0CanonicalBytesAfter(local, beforeFP, beforeGP, arch)
	for offset := range state.bytes.canonicalFP {
		state.bytes.canonicalFP[offset] = state.bytes.canonicalFP[offset] && state.bytes.fp[offset]
	}
	for index := range state.bytes.canonicalGP {
		state.bytes.canonicalGP[index] &= state.bytes.gp[index]
	}
	return true
}

func (state *x86SourceStackScalarState) complete() bool {
	for offset := state.result; offset < state.result+state.width; offset++ {
		if !state.bytes.fp[offset] || state.canonicalResult && !state.bytes.canonicalFP[offset] {
			return false
		}
	}
	return true
}

// Only acyclic, fully checked scalar source CFGs use this must-fact join.
// Physical stack shape, opaque BP/g cells and immutable layout stay exact.
// Numerical/canonical bytes and FLAGS can only lose knowledge at a join.
func x86SourceStackScalarMerge(left, right x86SourceStackState) (x86SourceStackState, bool) {
	result := left
	if left.scalarResult == nil || right.scalarResult == nil || left.sp != right.sp || left.bp != right.bp ||
		left.callers != nil || right.callers != nil || left.known != nil || right.known != nil ||
		left.vectors != nil || right.vectors != nil || left.masks != nil || right.masks != nil || len(left.cells) != len(right.cells) {
		return result, false
	}
	a, b := left.scalarResult, right.scalarResult
	if a.result != b.result || a.width != b.width || a.canonicalResult != b.canonicalResult || !reflect.DeepEqual(a.owned, b.owned) {
		return result, false
	}
	result.cells = append([]x86SourceStackCell(nil), left.cells...)
	for index, first := range left.cells {
		second := right.cells[index]
		first.known, second.known = 0, 0
		first.canonical, second.canonical = 0, 0
		first.scalarFlags, second.scalarFlags = 0, 0
		first.numericFlags, second.numericFlags = false, false
		first.partialNumericFlags, second.partialNumericFlags = 0, 0
		if !reflect.DeepEqual(first, second) {
			return result, false
		}
		cell := &result.cells[index]
		cell.known &= right.cells[index].known
		cell.canonical &= right.cells[index].canonical
		cell.scalarFlags &= right.cells[index].scalarFlags
		mask := x86SourceStackNumericFlagMask(&x86SourceStackState{
			numericFlags: cell.numericFlags, partialNumericFlags: cell.partialNumericFlags}) &
			x86SourceStackNumericFlagMask(&x86SourceStackState{
				numericFlags: right.cells[index].numericFlags, partialNumericFlags: right.cells[index].partialNumericFlags})
		cell.numericFlags, cell.partialNumericFlags = mask == x86ByteFlagsAll, 0
		if !cell.numericFlags {
			cell.partialNumericFlags = mask
		}
	}
	value := *a
	value.bytes = a.bytes.intersect(b.bytes)
	result.scalarResult = &value
	x86SourceStackSetNumericFlags(&result, x86SourceStackNumericFlagMask(&left)&x86SourceStackNumericFlagMask(&right))
	result.gOriginal = left.gOriginal && right.gOriginal
	return result, true
}

func sealX86SourceStackScalar(fn, original Func, sig FuncSig, stack *x86SourceStackProof) *x86SourceStackScalarProof {
	function, err := x86CallerSourceFingerprint(fn)
	if err != nil {
		return nil
	}
	signature, err := x86CallerSourceFingerprint(sig)
	if err != nil {
		return nil
	}
	raw := original.Instrs
	if replay := original.x86RawReplay; replay != nil {
		if replay.validate(original, replay.goarch) != nil {
			return nil
		}
		raw = replay.original
	}
	return &x86SourceStackScalarProof{owner: stack, minimum: stack.minimum, word: stack.word,
		stackIdentity: stack.normalized, countedIterations: stack.countedIterations, signature: signature, function: function,
		original: cloneX86ReplayInstrs(raw), normalized: cloneX86ReplayInstrs(fn.Instrs)}
}

func (c *amd64Ctx) checkSourceStackScalarResultInitialization() error {
	fn, sig, stack := c.fpScalarSource, c.fpSourceSig, c.sourceStack
	fail := func() error {
		return goAMD64FrameContext("physical source-stack scalar result lost its complete source/declaration/numerical proof")
	}
	if stack == nil || fn.x86SourceStack != stack || stack.scalarResult == nil || stack.word != x86ResultPointerWord(c.goarch) ||
		fn.FrameSize != 0 || c.frameSize != fn.FrameSize || x86SourceStackScalarInitial(fn, sig, c.goarch) == nil {
		return fail()
	}
	proof := stack.scalarResult
	if proof.owner != stack || proof.minimum != stack.minimum || proof.word != stack.word || stack.caller != nil ||
		proof.stackIdentity != stack.normalized || proof.countedIterations != stack.countedIterations {
		return fail()
	}
	function, err := x86CallerSourceFingerprint(fn)
	if err != nil || function != proof.function || !reflect.DeepEqual(fn.Instrs, proof.normalized) {
		return fail()
	}
	signature, err := x86CallerSourceFingerprint(sig)
	if err != nil || signature != proof.signature || fn.x86RawReplay == nil ||
		x86SourceStackScalarArch(fn.x86RawReplay.goarch) != x86SourceStackScalarArch(c.goarch) ||
		fn.x86RawReplay.validate(fn, fn.x86RawReplay.goarch) != nil || !reflect.DeepEqual(fn.x86RawReplay.original, proof.original) {
		return fail()
	}
	emitted := c.sig
	if sig.Attrs == "" && emitted.Attrs == c.fpFeatureAttrs {
		emitted.Attrs = "" // Only the renderer's separate, exact inference handoff.
	}
	if !reflect.DeepEqual(emitted, sig) {
		return fail()
	}
	return nil
}
