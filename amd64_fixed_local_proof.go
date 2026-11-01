package plan9asm

import (
	"errors"
	"fmt"
	"math"
	"reflect"
)

var errFixedLocalLayoutJoin = goAMD64FrameContext("fixed local CFG address identity disagrees")

// Local offsets are from the observed post-prologue Go SP, not incoming FP,
// saved BP/return slots, a caller allocation or an arbitrary native address.
type x86FixedLocalProof struct {
	binding  *x86FixedLocalBinding
	frame    int64
	function [32]byte
	accesses map[int]map[int]x86FixedLocalAccess
	ordinal  int // private builder cursor; never trusted by a consumer
}

type x86FixedLocalAccess struct {
	owner       *x86FixedLocalProof
	shape       [32]byte
	width       int64
	write       bool
	nativeInput bool     // Typed source address, not a private extent/alignment proof.
	offset      [8]int64 // The first access; a counted loop retains its complete series below.
	ordinal     int
	// Counted iterations and private layouts retain a complete stable series.
	iterationOffsets [][8]int64
}

type x86FixedLocalState struct {
	pointers     map[Reg]int64
	opaque       map[Reg]x86FixedLocalOrigins
	opaqueCells  map[int64]x86FixedLocalOrigins
	booleans     map[Reg]uint8
	booleanBytes x86FixedLocalByteSet
	constants    map[Reg]int64
	ranges       map[Reg]x86UnsignedRange
	comparison   x86FixedLocalComparison
	known        map[Reg]uint8
	vectors      map[Reg]uint64
	masks        map[Reg]bool
	bytes        x86FixedLocalByteSet
	addresses    map[int64]int64
	results      map[int]bool
	flags        uint8
	savedBP      *x86FixedLocalSavedBP // Immutable facts for the active observed leaf call.
}

func cloneFixedLocalState(input x86FixedLocalState) x86FixedLocalState {
	clone := input
	clone.pointers = make(map[Reg]int64, len(input.pointers))
	clone.opaque = cloneFixedLocalOrigins(input.opaque)
	clone.opaqueCells = cloneFixedLocalOrigins(input.opaqueCells)
	clone.booleans = x86CloneCallerKnown(input.booleans)
	clone.booleanBytes = append(x86FixedLocalByteSet(nil), input.booleanBytes...)
	clone.constants = make(map[Reg]int64, len(input.constants))
	clone.ranges = cloneFixedLocalRanges(input.ranges)
	clone.addresses = make(map[int64]int64, len(input.addresses))
	clone.results = make(map[int]bool, len(input.results))
	for key, value := range input.pointers {
		clone.pointers[key] = value
	}
	for key, value := range input.constants {
		clone.constants[key] = value
	}
	for key, value := range input.addresses {
		clone.addresses[key] = value
	}
	for key, value := range input.results {
		clone.results[key] = value
	}
	clone.known = x86CloneCallerKnown(input.known)
	clone.vectors, clone.masks = x86CloneCallerVectorState(input.vectors, input.masks)
	clone.bytes = append(x86FixedLocalByteSet(nil), input.bytes...)
	return clone
}

func proveX86FixedLocal(fn Func, sig FuncSig) (Func, error) {
	if view := fn.x86DirectTailRoot; view != nil {
		if view.graph == nil || view.graph.revoked.Load() || view.graph.fixedLocal != sig.x86FixedLocal {
			return fn, goAMD64FrameContext("private leaf CFG has a foreign root/frame owner")
		}
		root := view.graph.roots[fn.Sym]
		if root == nil || root.graph != view.graph || root.text != view.text {
			return fn, goAMD64FrameContext("private leaf CFG has a foreign root/frame owner")
		}
		proven, err := proveX86FixedLocalBody(fixedLocalProofFunction(fn), sig)
		if err != nil {
			return fn, err
		}
		copy := *view
		copy.instructions = proven.Instrs
		fn.x86DirectTailRoot, fn.x86FixedLocal = &copy, proven.x86FixedLocal
		return fn, nil
	}
	return proveX86FixedLocalBody(fn, sig)
}

func proveX86FixedLocalBody(fn Func, sig FuncSig) (Func, error) {
	voidReturn := sig.Ret == Void && len(sig.Frame.Results) == 0
	valueReturn := sig.Ret != "" && sig.Ret != Void && len(sig.Frame.Results) > 0 && len(sig.Frame.Results) <= 4096
	if fn.FrameSize <= 0 || fn.FrameSize > 64<<10 || fn.FrameSize%8 != 0 ||
		len(fn.Instrs) == 0 || len(fn.Instrs) > 8192 ||
		len(fn.X86RawText) != 0 || len(sig.ArgRegs) != 0 || sig.ARMEntry != nil ||
		sig.ARM64GoRegisterABI != nil || sig.x86CallerRegions != nil || !voidReturn && !valueReturn {
		return fn, goAMD64FrameContext("fixed local source has an unbound frame or entry contract")
	}
	budget := x86FixedLocalBudget{steps: 1 << 18, bytes: 64 << 20}
	proven, err := proveX86FixedLocalAttempt(fn, sig, &budget, false)
	if errors.Is(err, errFixedLocalLayoutJoin) {
		return proveX86FixedLocalAttempt(fn, sig, &budget, true)
	}
	return proven, err
}

// Only a private-layout join retries the complete residue/final replay, once,
// with the remaining budget. Ordinary sources retain their original schedule.
func proveX86FixedLocalAttempt(fn Func, sig FuncSig, budget *x86FixedLocalBudget, partitioned bool) (Func, error) {
	copyFn := fn
	copyFn.Instrs = append([]Instr(nil), fn.Instrs...)
	proof := &x86FixedLocalProof{binding: sig.x86FixedLocal, frame: fn.FrameSize, accesses: make(map[int]map[int]x86FixedLocalAccess)}
	for index := range copyFn.Instrs {
		copyFn.Instrs[index].Args = append([]Operand(nil), fn.Instrs[index].Args...)
		copyFn.Instrs[index].x86FixedLocalMemory = nil
	}
	effects, err := fixedLocalEffectPlan(copyFn, proof.binding)
	if err != nil {
		return fn, err
	}
	var layouts *x86FixedLocalLayoutGraph
	if partitioned {
		layouts = &x86FixedLocalLayoutGraph{}
	}
	for residue := 0; residue < 8; residue++ {
		if err := replayX86FixedLocal(&copyFn, sig, proof, residue, budget, effects, layouts); err != nil {
			return fn, err
		}
	}
	// Independent final replay must recreate exactly the same access set and
	// offset in every possible word-aligned original Go SP congruence class.
	final := copyFn
	final.Instrs = append([]Instr(nil), copyFn.Instrs...)
	for index := range final.Instrs {
		final.Instrs[index].x86FixedLocalMemory = nil
	}
	effects, err = fixedLocalEffectPlan(final, proof.binding)
	if err != nil {
		return fn, err
	}
	var firstLayouts []x86FixedLocalLayoutNode
	if layouts != nil {
		firstLayouts = layouts.nodes
		*layouts = x86FixedLocalLayoutGraph{retained: int64(cap(firstLayouts))*32 + layouts.series}
	}
	for residue := 0; residue < 8; residue++ {
		if err := replayX86FixedLocal(&final, sig, proof, residue, budget, effects, layouts); err != nil {
			return fn, err
		}
	}
	if layouts != nil && !reflect.DeepEqual(firstLayouts, layouts.nodes) {
		return fn, goAMD64FrameContext("fixed local final layout replay changed")
	}
	for index := range final.Instrs {
		if !reflect.DeepEqual(final.Instrs[index].x86FixedLocalMemory, copyFn.Instrs[index].x86FixedLocalMemory) {
			return fn, goAMD64FrameContext("fixed local final access replay changed")
		}
		if len(final.Instrs[index].x86FixedLocalMemory) != 0 {
			proof.accesses[index] = cloneX86ReplayFixedLocalMemory(final.Instrs[index].x86FixedLocalMemory)
		}
	}
	if err := fixedLocalRelocationAliases(proof.accesses); err != nil {
		return fn, err
	}
	proof.function, err = x86CallerSourceFingerprint(final)
	if err != nil {
		return fn, goAMD64FrameContext("fixed local normalized function cannot be bound: %v", err)
	}
	final.x86FixedLocal = proof
	return final, nil
}

// This call-local plan holds forms and immutable DATA byte dependencies, never
// a live source verification result. Each independent eight-residue replay
// constructs its own plan under the original binding's complete lifetime guards.
func fixedLocalEffectPlan(fn Func, binding *x86FixedLocalBinding) (map[int]x86TypedByteEffect, error) {
	var effects map[int]x86TypedByteEffect
	for index, ins := range fn.Instrs {
		if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86AddressBits != 0 || ins.x86SegmentPrefix != 0 {
			return nil, goAMD64FrameContext("fixed local source contains raw/native effects")
		}
		if fn.x86DirectTailRoot.privateCallTransition(index) {
			continue // Complete private source graph owns only this control edge.
		}
		if effect, known, err := fixedLocalVectorByteEffect(ins); known {
			if err != nil {
				return nil, err
			}
			if effects == nil {
				effects = make(map[int]x86TypedByteEffect)
			}
			effects[index] = fixedLocalLogicalLiteralEffect(ins, effect, binding)
		} else {
			shape := ins
			if x86LEAWidth(ins.Op, "amd64") != 0 && len(ins.Args) == 2 && ins.Args[0].Kind == OpMem {
				address, err := fixedLocalMemoryAddress(ins, 0, fn.FrameSize)
				if err != nil {
					return nil, err
				}
				shape.Args = append([]Operand(nil), ins.Args...)
				shape.Args[0].Mem = address
			}
			if !fixedLocalInstructionShape(shape) {
				return nil, goAMD64FrameContext("fixed local complete source has an unregistered instruction shape: %s", ins.Op)
			}
		}
	}
	return effects, nil
}

// Every reachable access, including initialization stores and private address
// spills, contributes all its bytes. Each original residue must induce a
// bijection on those bytes: equal bytes remain equal and distinct bytes stay
// distinct. Different distances between permanently disjoint accesses are
// unobservable because the source cannot expose numeric addresses or flags.
func fixedLocalRelocationAliases(accesses map[int]map[int]x86FixedLocalAccess) error {
	var forward, reverse [8]map[int64]int64
	for residue := range forward {
		forward[residue] = make(map[int64]int64)
		reverse[residue] = make(map[int64]int64)
	}
	var total int64
	for _, operands := range accesses {
		for _, access := range operands {
			offsets := access.iterationOffsets
			if len(offsets) == 0 {
				offsets = [][8]int64{access.offset}
			}
			if access.width <= 0 || access.width > ((1<<20)-total)/int64(len(offsets)) {
				return goAMD64FrameContext("fixed local complete access-byte budget exceeded")
			}
			total += access.width * int64(len(offsets))
			if access.nativeInput {
				continue // Native input addresses are never relocated.
			}
			for _, offset := range offsets {
				for byteIndex := int64(0); byteIndex < access.width; byteIndex++ {
					original := offset[0] + byteIndex
					for residue := range forward {
						current := offset[residue] + byteIndex
						if mapped, found := forward[residue][original]; found && mapped != current {
							return goAMD64FrameContext("fixed local overlapping-byte identity depends on original SP residue")
						}
						if mapped, found := reverse[residue][current]; found && mapped != original {
							return goAMD64FrameContext("fixed local distinct-byte identity depends on original SP residue")
						}
						forward[residue][original] = current
						reverse[residue][current] = original
					}
				}
			}
		}
	}
	return nil
}

func fixedLocalInstructionShape(ins Instr) bool {
	if form, known, err := x86GPSIMDTransferProperties(ins, "amd64"); known {
		return err == nil && !form.mmx && !form.spec.rawOnly
	}
	if _, _, known, err := x86SwapProperties(ins, "amd64"); known {
		return err == nil
	}
	if form, known, err := fixedLocalConversionProperties(ins); known {
		return err == nil && !form.mmx
	}
	if _, known, err := fixedLocalScalarLaneProperties(ins); known {
		return err == nil
	}
	if _, known, err := x86ConditionalSetProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if ins.x86NumericalRead != nil {
		_, valid := x86NumericalReadEffect(ins, "amd64")
		return valid
	}
	if _, known, err := amd64PackedVectorMoveProperties(ins, "amd64"); known {
		return err == nil
	}
	if form, known, err := x86NonTemporalVectorProperties(ins.Op, ins, "amd64"); known {
		return err == nil && !form.trap
	}
	if _, known, err := x86OrderingHintProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if _, known, err := x86VectorZeroProperties(ins, "amd64"); known {
		return err == nil
	}
	if _, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if _, known := amd64MaskMoveSpecs[ins.Op]; known {
		return amd64MaskMoveOperandsValid(ins, "amd64")
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpReg && amd64VectorByteWidth(operand.Reg) != 0 {
			index, valid := amd64VectorRegisterIndex(operand.Reg, 16)
			if !valid || index > 15 {
				return false
			}
		}
	}
	if ins.Op == OpTEXT || ins.Op == OpLABEL {
		return true // Parser/complete CFG separately binds TEXT and label operands.
	}
	if ins.Op == OpRET {
		return len(ins.Args) == 0
	}
	if isAMD64ConditionalBranch(ins.Op) || ins.Op == OpJMP {
		_, named := fixedLocalBranchLabel(ins)
		return named
	}
	if x86RawReturnScalarMoveBytes(x86SourceMoveInstruction(ins, "amd64").Op) != 0 {
		return len(ins.Args) == 2
	}
	if _, address := fixedLocalStaticAddress(ins); address {
		return true
	}
	if effect, known, err := fixedLocalGPByteEffect(ins); known {
		return err == nil && !effect.dynamicMemory
	}
	if _, known, err := x86SHAProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if form, known, err := x86AESProperties(ins.Op, ins, "amd64"); known {
		return err == nil && form.byteWidth == 16
	}
	if _, known, err := fixedLocalVectorByteEffect(ins); known {
		return err == nil
	}
	if form, known, err := x86FloatCompareProperties(ins, "amd64"); known {
		return err == nil && form.legacy && !form.scalar && form.byteWidth == 16
	}
	return false
}

func fixedLocalBranchLabel(ins Instr) (string, bool) {
	if len(ins.Args) != 1 {
		return "", false
	}
	operand := ins.Args[0]
	if operand.Kind == OpLabel && operand.Sym != "" {
		return operand.Sym, true
	}
	if operand.Kind == OpIdent && operand.Ident != "" {
		return operand.Ident, true
	}
	return "", false
}

func fixedLocalEdges(fn Func) (map[int][]int, []int, error) {
	if view := fn.x86DirectTailRoot; view != nil {
		if len(fn.Instrs) != len(view.points) || len(view.edges) != len(view.points) {
			return nil, nil, goAMD64FrameContext("private leaf CFG instruction inventory differs")
		}
		edges, instructions := make(map[int][]int, len(view.edges)), make([]int, len(view.points))
		for pc, targets := range view.edges {
			instructions[pc], edges[pc] = pc, targets
		}
		return edges, instructions, nil
	}
	labels := make(map[string]int)
	var instructions []int
	for index, ins := range fn.Instrs {
		if ins.Op == OpLABEL {
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpLabel {
				return nil, nil, goAMD64FrameContext("malformed local label")
			}
			name := ins.Args[0].Sym
			if _, exists := labels[name]; exists {
				return nil, nil, goAMD64FrameContext("duplicate local label")
			}
			labels[name] = len(instructions)
		} else {
			instructions = append(instructions, index)
		}
	}
	if len(instructions) == 0 || len(instructions) > 8192 {
		return nil, nil, goAMD64FrameContext("fixed local CFG lacks a bounded instruction inventory")
	}
	edges := make(map[int][]int)
	for pc, index := range instructions {
		ins := fn.Instrs[index]
		if ins.Op == OpRET {
			continue
		}
		next := []int{pc + 1}
		if ins.Op == OpJMP || isAMD64ConditionalBranch(ins.Op) {
			label, named := fixedLocalBranchLabel(ins)
			if !named {
				return nil, nil, goAMD64FrameContext("fixed local branch needs a complete named target")
			}
			target, found := labels[label]
			if !found || target >= len(instructions) {
				return nil, nil, goAMD64FrameContext("fixed local branch target is missing an instruction")
			}
			if ins.Op == OpJMP {
				next = []int{target}
			} else {
				next = append(next, target)
			}
		}
		edges[pc] = next
	}
	return edges, instructions, nil
}

// All congruence classes and the independent final replay share these limits.
// A cyclic source cannot obtain an unbounded analysis or a partial certificate.
type x86FixedLocalBudget struct {
	steps int
	bytes int64
}

func (budget *x86FixedLocalBudget) consume(frame int64) error {
	if budget.steps <= 0 || frame > budget.bytes {
		return goAMD64FrameContext("fixed local CFG work/byte bound exceeded")
	}
	budget.steps--
	budget.bytes -= frame
	return nil
}

func (budget *x86FixedLocalBudget) consumeOrigins(bytes int64) error {
	if bytes > budget.bytes {
		return goAMD64FrameContext("fixed local opaque state byte bound exceeded")
	}
	budget.bytes -= bytes
	return nil
}

// Partitioned replay charges actual state payload at copies and meets. This
// saturating logical charge includes map entries, not allocator/RSS overhead.
func fixedLocalStateWork(state x86FixedLocalState) int64 {
	const limit int64 = 64 << 20
	var bytes int64
	if state.savedBP != nil {
		bytes = 128
	}
	for _, group := range []struct {
		unit   int64
		counts []int
	}{
		{8, []int{len(state.bytes), len(state.booleanBytes)}},
		{64, []int{len(state.pointers), len(state.opaque), len(state.opaqueCells), len(state.booleans),
			len(state.constants), len(state.ranges), len(state.known), len(state.vectors), len(state.masks),
			len(state.addresses), len(state.results)}},
	} {
		for _, count := range group.counts {
			if int64(count) > (limit-bytes)/group.unit {
				return limit + 1
			}
			bytes += int64(count) * group.unit
		}
	}
	return bytes
}

// Only the existing closed vector plan calls this cost projection. The step
// debit remains mandatory; this grants no input or storage permission.
func fixedLocalVectorRegisterWork(effect x86TypedByteEffect) bool {
	if effect.dynamicMemory || effect.vector.memoryAlignment <= 0 ||
		effect.vector.upperWrite != x86TypedVectorUpperPreserve && effect.vector.upperWrite != x86TypedVectorUpperZero {
		return false
	}
	for _, operand := range effect.operands {
		if operand.operand.Kind != OpReg && operand.operand.Kind != OpImm {
			return false
		}
	}
	return true
}

// Cost only: the ordinary transfer still owns pointer, FLAGS and input facts.
// Keep original address syntax conservative even if its effect becomes Regs.
func fixedLocalGPRegisterWork(ins Instr) (x86TypedByteEffect, bool) {
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return x86TypedByteEffect{}, false
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg && operand.Kind != OpImm {
			return x86TypedByteEffect{}, false
		}
	}
	effect, known, err := fixedLocalGPByteEffect(ins)
	if !known || err != nil || effect.dynamicMemory {
		return x86TypedByteEffect{}, false
	}
	for _, operand := range effect.operands {
		if operand.operand.Kind != OpReg && operand.operand.Kind != OpImm {
			return x86TypedByteEffect{}, false
		}
	}
	return effect, true
}

func replayX86FixedLocal(fn *Func, sig FuncSig, proof *x86FixedLocalProof, residue int, budget *x86FixedLocalBudget,
	effects map[int]x86TypedByteEffect, layouts *x86FixedLocalLayoutGraph) error {
	edges, instructions, err := fixedLocalEdges(*fn)
	if err != nil {
		return err
	}
	linear := fixedLocalLinearEdges(*fn, edges, instructions)
	err = replayX86FixedLocalCFG(fn, sig, proof, residue, budget, effects, edges, instructions, linear, nil, layouts)
	if err == nil {
		return nil // A stronger loop model must not reject existing generic CFG proofs.
	}
	loops := fixedLocalCountedLoops(*fn, edges, instructions)
	if len(loops) == 0 {
		return err
	}
	// Failed attempts publish no access annotations. Reuse the original source,
	// transfer and remaining budget; this is not recursive translation or caching.
	countedErr := replayX86FixedLocalCFG(fn, sig, proof, residue, budget, effects, edges, instructions, linear, loops, layouts)
	if layouts == nil && errors.Is(err, errFixedLocalLayoutJoin) && countedErr != nil {
		return fmt.Errorf("%w; counted replay: %v", err, countedErr)
	}
	return countedErr
}

// Keep states at control-flow boundaries. A sole fallthrough predecessor has
// no meet: its private transfer state can flow directly to the next instruction.
// Count all CFG predecessors, including unreachable edges and repeated targets;
// branch destinations and PC zero retain their independent entry state.
func fixedLocalLinearEdges(fn Func, edges map[int][]int, instructions []int) []bool {
	predecessors := make([]int, len(instructions))
	for _, targets := range edges {
		for _, target := range targets {
			if target >= 0 && target < len(predecessors) {
				predecessors[target]++
			}
		}
	}
	linear := make([]bool, len(instructions))
	for pc, targets := range edges {
		op := fn.Instrs[instructions[pc]].Op
		linear[pc] = op != OpJMP && op != OpRET && op != OpCALL && !isAMD64ConditionalBranch(op) &&
			len(targets) == 1 && targets[0] == pc+1 && pc+1 < len(instructions) && predecessors[pc+1] == 1
	}
	return linear
}

// A nil linear mask retains the all-instruction reference schedule. Both paths
// use the same transfer, meet, work budgets and final access publication.
func replayX86FixedLocalCFG(fn *Func, sig FuncSig, proof *x86FixedLocalProof, residue int, budget *x86FixedLocalBudget,
	effects map[int]x86TypedByteEffect, edges map[int][]int, instructions []int, linear []bool,
	loops map[int]x86FixedLocalCountedLoop, graph *x86FixedLocalLayoutGraph) error {
	if proof.frame <= 0 || proof.frame > 1<<20 {
		return goAMD64FrameContext("fixed local retained state storage budget exceeded")
	}
	state := x86FixedLocalState{
		pointers: map[Reg]int64{SP: 0}, constants: make(map[Reg]int64), known: make(map[Reg]uint8),
		opaque: make(map[Reg]x86FixedLocalOrigins), opaqueCells: make(map[int64]x86FixedLocalOrigins), booleans: make(map[Reg]uint8),
		booleanBytes: newFixedLocalByteSet(proof.frame),
		vectors:      make(map[Reg]uint64), masks: make(map[Reg]bool),
		bytes: newFixedLocalByteSet(proof.frame), addresses: make(map[int64]int64), results: make(map[int]bool),
	}
	// All GP entry bytes except the private SP origin remain unknown. ABI0
	// does not supply an initialized R14/g value; the observed nonzero-frame
	// prologue/epilogue independently preserves BP. Explicit definitions may
	// use either register without importing its entry value or native role.
	states := map[int]x86FixedLocalState{0: state}
	work := []int{0}
	queued := map[int]bool{0: true}
	accesses := make(map[int]map[int]x86FixedLocalAccess)
	var layouts *x86FixedLocalLayouts
	var observations map[int]map[int]map[int]x86FixedLocalAccess
	returned := false
	retainedBytes := proof.frame
	if graph != nil {
		current := newFixedLocalLayouts(graph.nodes)
		layouts = &current
		observations = make(map[int]map[int]map[int]x86FixedLocalAccess)
		retainedBytes += graph.retained + graph.series + int64(len(layouts.nodes))*fixedLocalLayoutNodeBytes
	}
	if retainedBytes > 1<<20 {
		return goAMD64FrameContext("fixed local retained state storage budget exceeded")
	}
	for head := 0; head < len(work); head++ {
		node := work[head]
		pc, alternative := node, false
		currentAccesses := accesses
		if layouts != nil {
			pc = layouts.nodes[node].pc
			alternative = node != layouts.at[pc][0]
			currentAccesses = make(map[int]map[int]x86FixedLocalAccess)
		}
		queued[node] = false
		if pc < 0 || pc >= len(instructions) {
			return goAMD64FrameContext("fixed local fallthrough lacks a source return")
		}
		copyWork := fixedLocalOriginStorage(states[node])
		if layouts != nil {
			copyWork = 2 * fixedLocalStateWork(states[node])
		}
		if err := budget.consumeOrigins(copyWork); err != nil {
			return err
		}
		current := cloneFixedLocalState(states[node])
		var active *x86FixedLocalCountedLoop
		var number uint64
		iteration := 0
		var targets []int
		for {
			effect, planned := effects[instructions[pc]]
			var gp *x86TypedByteEffect
			workBytes := proof.frame
			if layouts != nil && planned && fixedLocalVectorRegisterWork(effect) {
				workBytes = 0
			} else if layouts != nil && !planned {
				if parsed, cheap := fixedLocalGPRegisterWork(fn.Instrs[instructions[pc]]); cheap {
					workBytes, gp = 0, &parsed
				}
			}
			if err := budget.consume(workBytes); err != nil {
				return err
			}
			if active == nil {
				if loop, found := loops[pc]; found {
					if value, known := loop.number(&current); known {
						active, number = &loop, value
					}
				}
			}
			// Transfer a private instruction copy: provisional loop states must
			// never publish accesses, including certificates from another residue.
			ins := fn.Instrs[instructions[pc]]
			ins.x86FixedLocalMemory = nil
			proof.ordinal = instructions[pc]
			var err error
			transition := fn.x86DirectTailRoot.privateCallTransition(pc)
			if transition {
				err = fixedLocalFrameTransition(fn.x86DirectTailRoot, pc, &current)
			} else if planned {
				err = fixedLocalTypedByteStep(&ins, &current, FuncSig{}, proof, residue, effect)
			} else {
				err = fixedLocalStepWithGP(&ins, &current, sig, proof, residue, gp)
			}
			if err != nil {
				return fmt.Errorf("%s: %q: %w", fn.Sym, ins.Raw, err)
			}
			if active != nil {
				if pc == active.update {
					number, err = active.next(number)
					if err != nil {
						return err
					}
				}
				if value, known := active.number(&current); !known || value != number {
					return goAMD64FrameContext("fixed local counted-loop counter changed outside its unique update")
				}
				if err := fixedLocalCountedAccesses(currentAccesses[pc], ins.x86FixedLocalMemory, iteration); err != nil {
					return err
				}
			}
			if alternative {
				retainedBytes += fixedLocalLayoutAccessBytes(ins.x86FixedLocalMemory) - fixedLocalLayoutAccessBytes(currentAccesses[pc])
				if retainedBytes > 1<<20 {
					return goAMD64FrameContext("fixed local retained state storage budget exceeded")
				}
			}
			if layouts == nil || len(ins.x86FixedLocalMemory) != 0 {
				currentAccesses[pc] = ins.x86FixedLocalMemory
			}
			returned = returned || ins.Op == OpRET && !transition
			if active != nil {
				if pc == active.latch {
					if active.continues(number) {
						iteration++
						pc = active.header
						continue
					}
					targets = edges[pc][:1] // The actual known comparison has reached the false latch.
					break
				}
				pc++
				continue
			}
			if linear == nil || !linear[pc] {
				break
			}
			pc++
		}
		if targets == nil {
			targets = edges[pc]
		}
		if alternative {
			for _, old := range observations[node] {
				retainedBytes -= fixedLocalLayoutAccessBytes(old)
			}
		}
		if layouts != nil {
			observations[node] = currentAccesses
			layouts.nodes[node].end = pc
			layouts.nodes[node].targets = [2]int{-1, -1}
		}
		for edge, target := range targets {
			if edge >= 2 || target < 0 || target >= len(instructions) {
				return goAMD64FrameContext("fixed local fallthrough lacks a source return")
			}
			next := current
			if isAMD64ConditionalBranch(fn.Instrs[instructions[pc]].Op) {
				var feasible bool
				next, feasible = fixedLocalRangeEdge(current, fn.Instrs[instructions[pc]].Op, edge == 1)
				if !feasible {
					continue
				}
				comparison := current.comparison
				if comparison.literal.symbol != "" && !next.opaque[comparison.register].equal(current.opaque[comparison.register]) {
					if err := budget.consumeOrigins(fixedLocalOriginMapStorage(next.opaque)); err != nil {
						return err
					}
				}
			}
			terminal := fn.Instrs[instructions[target]]
			if terminal.Op == OpRET && !fn.x86DirectTailRoot.privateCallTransition(target) {
				// A final return has no successor that could consume dead local
				// identities. Check every incoming SP/result state independently;
				// a helper return still resumes its caller through the usual CFG.
				if err := budget.consume(proof.frame); err != nil {
					return err
				}
				if err := fixedLocalStep(&terminal, &next, sig, proof, residue); err != nil {
					return fmt.Errorf("%s: %q: %w", fn.Sym, terminal.Raw, err)
				}
				returned = true
				if layouts != nil {
					layouts.nodes[node].targets[edge] = -2
				}
				continue
			}
			if layouts != nil {
				previousNodes := len(layouts.nodes)
				var err error
				target, err = layouts.target(states, node, edge, target, next, budget)
				if err != nil {
					return err
				}
				retainedBytes += int64(len(layouts.nodes)-previousNodes) * fixedLocalLayoutNodeBytes
			}
			changed := true
			if previous, found := states[target]; found {
				if layouts != nil {
					if err := budget.consumeOrigins(2*fixedLocalStateWork(previous) + fixedLocalStateWork(next)); err != nil {
						return err
					}
				}
				var err error
				changed, err = mergeFixedLocalState(&previous, next)
				if err != nil {
					return err
				}
				states[target] = previous
			} else {
				// Only control-flow boundaries retain complete frame states.
				// Keep the original frame-state product cap on actual storage;
				// the independent per-instruction work budgets remain unchanged.
				originBytes := fixedLocalOriginStorage(next)
				if proof.frame+originBytes > (1<<20)-retainedBytes {
					return goAMD64FrameContext("fixed local retained state storage budget exceeded")
				}
				retainedBytes += proof.frame + originBytes
				copyWork := originBytes
				if layouts != nil {
					copyWork = 2 * fixedLocalStateWork(next)
				}
				if err := budget.consumeOrigins(copyWork); err != nil {
					return err
				}
				states[target] = cloneFixedLocalState(next)
			}
			if changed && !queued[target] {
				queued[target] = true
				work = append(work, target)
			}
		}
	}
	if !returned {
		return goAMD64FrameContext("fixed local source has no reachable return")
	}
	// Each node contributes only its final transfer, in frozen edge identity
	// order. Counted iterations remain ordered within that node's observations.
	var seriesBytes int64
	if layouts != nil {
		if err := layouts.finish(); err != nil {
			return err
		}
		var err error
		accesses, seriesBytes, err = collectFixedLocalLayoutAccesses(len(layouts.nodes), observations, (1<<20)-retainedBytes)
		if err != nil {
			return err
		}
	}
	// An empty worklist means each retained transfer consumed the final input
	// state: every changed meet requeued its consumer. Publish those local
	// annotations only now, without repeating every instruction in a DAG.
	// Entry state remains a predecessor of PC zero, including backedges.
	for pc, index := range instructions {
		current, reachable := accesses[pc]
		if !reachable {
			continue
		}
		previous := fn.Instrs[index].x86FixedLocalMemory
		if residue != 0 && len(previous) != len(current) {
			return goAMD64FrameContext("fixed local access inventory depends on original SP residue")
		}
		for operand, access := range current {
			if residue == 0 {
				continue
			}
			prior, found := previous[operand]
			if !found || !fixedLocalAccessShapeEqual(prior, access) ||
				len(prior.iterationOffsets) != len(access.iterationOffsets) {
				return goAMD64FrameContext("fixed local access shape depends on original SP residue")
			}
			prior.offset[residue] = access.offset[residue]
			prior.iterationOffsets = append([][8]int64(nil), prior.iterationOffsets...)
			for index, offset := range access.iterationOffsets {
				prior.iterationOffsets[index][residue] = offset[residue]
			}
			current[operand] = prior
		}
	}
	for pc, current := range accesses {
		fn.Instrs[instructions[pc]].x86FixedLocalMemory = current
	}
	if graph != nil {
		graph.nodes, graph.series = layouts.nodes, seriesBytes
	}
	return nil
}

func mergeFixedLocalState(previous *x86FixedLocalState, current x86FixedLocalState) (bool, error) {
	// Private relocation identities must agree. Incoming origins are a separate
	// must-domain: losing one leaves unknown bytes, never numerical knowledge.
	if !reflect.DeepEqual(previous.pointers, current.pointers) || !reflect.DeepEqual(previous.addresses, current.addresses) {
		if err := fixedLocalLayoutRoles(*previous, current); err != nil {
			return false, err
		}
		return false, errFixedLocalLayoutJoin
	}
	changed, err := mergeFixedLocalSavedBP(previous, current)
	if err != nil {
		return false, err
	}
	changed = intersectFixedLocalOrigins(previous.constants, current.constants) || changed
	changed = mergeFixedLocalRanges(previous, current) || changed
	merged, err := mergeFixedLocalOrigins(previous.opaque, current.opaque)
	if err != nil {
		return false, err
	}
	changed = changed || merged
	merged, err = mergeFixedLocalOrigins(previous.opaqueCells, current.opaqueCells)
	if err != nil {
		return false, err
	}
	changed = changed || merged
	flags := previous.flags & current.flags
	changed = changed || flags != previous.flags
	previous.flags = flags
	for reg, bits := range previous.known {
		value := bits & current.known[reg]
		changed = changed || value != bits
		previous.known[reg] = value
	}
	for reg, bits := range previous.booleans {
		value := bits & current.booleans[reg]
		changed = changed || value != bits
		previous.booleans[reg] = value
	}
	for reg, bits := range previous.vectors {
		value := bits & current.vectors[reg]
		changed = changed || value != bits
		previous.vectors[reg] = value
	}
	for reg, known := range previous.masks {
		value := known && current.masks[reg]
		changed = changed || value != known
		previous.masks[reg] = value
	}
	changed = previous.bytes.intersect(current.bytes) || changed
	changed = previous.booleanBytes.intersect(current.booleanBytes) || changed
	for index, written := range previous.results {
		value := written && current.results[index]
		changed = changed || value != written
		previous.results[index] = value
	}
	return changed, nil
}

func fixedLocalMemory(ins *Instr, index int, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int, width, alignment int64, write, pointer bool) (int64, error) {
	if index < 0 || index >= len(ins.Args) || ins.Args[index].Kind != OpMem || width <= 0 {
		return 0, goAMD64FrameContext("fixed local access lacks native memory")
	}
	memory, err := fixedLocalMemoryAddress(*ins, index, proof.frame)
	if err != nil {
		return 0, err
	}
	offset, found := fixedLocalPrivateOffset(memory, state)
	if !found {
		return 0, goAMD64FrameContext("fixed local access has unknown/escaping address provenance")
	}
	if offset < 0 || offset > proof.frame || width > proof.frame-offset || alignment <= 0 ||
		(int64(residue*8)+offset)%alignment != 0 {
		return 0, goAMD64FrameContext("fixed local access crosses storage or has residue-dependent native alignment")
	}
	if !write && !pointer {
		if !state.bytes.all(offset, width) {
			return 0, goAMD64FrameContext("fixed local native read contains uninitialized or address bytes")
		}
	}
	return offset, fixedLocalRecordAccess(ins, index, proof, residue, width, write, false, offset)
}

// Native input addresses retain ordinary faulting memory semantics. Their Go
// pointer type proves only provenance, never a pointee extent or alignment.
func fixedLocalMemoryAccess(ins *Instr, index int, state *x86FixedLocalState, proof *x86FixedLocalProof,
	residue int, width, alignment int64, write, pointer bool) (int64, x86FixedLocalMemoryRole, error) {
	if index >= 0 && index < len(ins.Args) && ins.Args[index].Kind == OpMem {
		memory := ins.Args[index].Mem
		if origins, input := state.opaque[memory.Base]; input {
			root, valid := x86CallerGP(memory.Base)
			displacement, known, numerical := fixedLocalNativeDisplacement(memory, state)
			if !valid || !origins.valid() || root != memory.Base || root == SP || width <= 0 || alignment <= 0 || pointer || !numerical {
				return 0, x86FixedLocalNativeInput, goAMD64FrameContext("fixed local native address requires a full typed base and numerical index")
			}
			if !fixedLocalOriginOwners(origins, proof) || write && origins.readonly() {
				return 0, x86FixedLocalNativeInput, goAMD64FrameContext("fixed local native address lacks its original storage or write role")
			}
			if literal, exact := origins.literal(); exact && known {
				literal.offset += displacement
				if !fixedLocalLiteralRange(proof.binding, literal, width, alignment) {
					return 0, x86FixedLocalLiteralMemory, goAMD64FrameContext("fixed local exact DATA read exceeds original identity, extent or alignment")
				}
			}
			return 0, x86FixedLocalNativeInput, fixedLocalRecordAccess(ins, index, proof, residue, width, write, true, 0)
		}
	}
	offset, err := fixedLocalMemory(ins, index, state, proof, residue, width, alignment, write, pointer)
	return offset, x86FixedLocalPrivateMemory, err
}

func fixedLocalRecordAccess(ins *Instr, index int, proof *x86FixedLocalProof, residue int,
	width int64, write, nativeInput bool, offset int64) error {
	if ins.x86FixedLocalMemory == nil {
		ins.x86FixedLocalMemory = make(map[int]x86FixedLocalAccess)
	}
	shape, err := fixedLocalInstructionDigest(*ins)
	if err != nil {
		return err
	}
	access, found := ins.x86FixedLocalMemory[index]
	if !found {
		access = x86FixedLocalAccess{owner: proof, shape: shape, width: width, write: write, nativeInput: nativeInput, ordinal: proof.ordinal}
	}
	if access.owner != proof || access.shape != shape || access.width != width || access.write != write || access.nativeInput != nativeInput {
		return goAMD64FrameContext("fixed local access shape changed")
	}
	access.offset[residue] = offset
	ins.x86FixedLocalMemory[index] = access
	return nil
}

func fixedLocalStep(ins *Instr, state *x86FixedLocalState, sig FuncSig, proof *x86FixedLocalProof, residue int) error {
	return fixedLocalStepWithGP(ins, state, sig, proof, residue, nil)
}

func fixedLocalStepWithGP(ins *Instr, state *x86FixedLocalState, sig FuncSig, proof *x86FixedLocalProof, residue int,
	gp *x86TypedByteEffect) error {
	fail := func() error {
		return goAMD64FrameContext("unproved fixed local width/initialization/address/control effect: %s", ins.Op)
	}
	if ins.Op == OpTEXT {
		return nil
	}
	if _, known, err := x86OrderingHintProperties(ins.Op, *ins, "amd64"); known {
		return err // Exact native fences change no byte, pointer or FLAGS facts.
	}
	if form, known, err := x86VectorZeroProperties(*ins, "amd64"); known {
		if err != nil {
			return err
		}
		x86VectorZeroDefinedBytes(form, state.vectors)
		return nil
	}
	if ins.Op == OpRET {
		sp, found := state.pointers[SP]
		if len(ins.Args) != 0 || !found || sp != 0 {
			return fail()
		}
		for index := range sig.Frame.Results {
			if !state.results[index] {
				return fail()
			}
		}
		return nil
	}
	if _, counter := x86CounterControlPropertiesForOpcode(ins.Op); counter {
		return fail() // This storage owner supplies no numerical counter domain.
	}
	if isAMD64ConditionalBranch(ins.Op) {
		needed := x86ByteBranchFlags(ins.Op)
		if needed == 0 || state.flags&needed != needed {
			return fail()
		}
		return nil
	}
	if ins.Op == OpJMP {
		return nil
	}
	if known, err := fixedLocalNumericalReadStep(ins, state, proof, residue); known {
		return err
	}
	if known, err := fixedLocalStaticAddressStep(*ins, state, proof); known {
		return err
	}
	if known, err := fixedLocalGPSIMDTransferStep(ins, state, sig, proof, residue); known {
		return err
	}
	if known, err := fixedLocalPrivateAddressStep(*ins, state, proof); known {
		return err
	}
	if width := x86RawReturnScalarMoveBytes(x86SourceMoveInstruction(*ins, "amd64").Op); width != 0 {
		return fixedLocalMove(ins, state, sig, proof, residue, width)
	}
	if known, err := fixedLocalExchangeStep(ins, state, sig, proof, residue); known {
		return err
	}
	if known, err := fixedLocalConditionalSetStep(ins, state, sig, proof, residue); known {
		return err
	}
	if (ins.Op == "ADDQ" || ins.Op == "ANDQ") && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		reg := ins.Args[1].Reg
		value := ins.Args[0].Imm
		known := ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" && !ins.Args[0].ImmIsFloat
		if ins.Args[0].Kind == OpReg {
			value, known = state.constants[ins.Args[0].Reg]
		}
		if offset, pointer := state.pointers[reg]; pointer {
			if !known {
				return fail()
			}
			if ins.Op == "ANDQ" {
				// Only an exact power-of-two residue projection preserves the
				// same private address origin. No pointer bit becomes numeric.
				if value != -8 && value != -16 && value != -32 && value != -64 {
					return fail()
				}
				offset = (offset+int64(residue*8))&value - int64(residue*8)
			} else {
				if value > 0 && offset > math.MaxInt64-value || value < 0 && offset < math.MinInt64-value {
					return fail()
				}
				offset += value
			}
			if offset < -64 || offset > proof.frame {
				return fail()
			}
			state.pointers[reg] = offset
			state.flags = 0 // Relocated pointer arithmetic flags are opaque.
			state.comparison = x86FixedLocalComparison{}
			return nil
		}
	}
	if known, err := fixedLocalConditionalMoveStep(ins, state, sig, proof, residue); known {
		return err
	}
	if known, err := fixedLocalInputAddressStep(ins, state, sig, proof, residue); known {
		return err
	}
	var effect x86TypedByteEffect
	var err error
	known := gp != nil
	if known {
		effect = *gp
	} else {
		effect, known, err = fixedLocalGPByteEffect(*ins)
	}
	if known {
		if err != nil {
			return err
		}
		root, value, constant := fixedLocalConstantArithmetic(*ins, effect, state)
		rangeReg, bounds, comparison := fixedLocalRangeEffect(*ins, effect, state)
		if err := fixedLocalTypedByteStep(ins, state, sig, proof, residue, effect); err != nil {
			return err
		}
		if constant {
			state.constants[root] = value
			fixedLocalWriteBooleans(state, root, 8, fixedLocalConstantBooleans(value, 8))
		}
		if rangeReg != "" {
			state.setRange(rangeReg, bounds)
		}
		if comparison.register != "" {
			state.comparison = comparison
		}
		return nil
	}
	if known, err := fixedLocalSHAStep(ins, state, proof, residue); known {
		return err
	}
	if known, err := fixedLocalAESByteStep(ins, state, proof, residue); known {
		return err
	}
	if known, err := fixedLocalPackedMoveStep(ins, state, proof, residue); known {
		return err
	}
	if known, err := fixedLocalMaskMoveStep(ins, state, proof, residue); known {
		return err
	}
	if known, err := fixedLocalConversionStep(ins, state, proof, residue); known {
		return err
	}
	if known, err := fixedLocalScalarLaneStep(ins, state, proof, residue); known {
		return err
	}
	return fixedLocalVectorStep(ins, state, proof, residue)
}

func fixedLocalNumericRead(operand Operand, width int64, state *x86FixedLocalState) bool {
	if operand.Kind == OpImm {
		return operand.ImmRaw == "" && !operand.ImmIsFloat
	}
	if operand.Kind != OpReg {
		return false
	}
	root, valid := x86CallerGP(operand.Reg)
	_, pointer := state.pointers[root]
	_, opaque := state.opaque[root]
	mask := x86CallerByteMask(operand.Reg, width)
	return valid && root != SP && !pointer && !opaque && mask != 0 && state.known[root]&mask == mask
}

func fixedLocalMove(ins *Instr, state *x86FixedLocalState, sig FuncSig, proof *x86FixedLocalProof, residue int, width int64) error {
	if len(ins.Args) != 2 {
		return goAMD64FrameContext("unproved fixed local scalar move")
	}
	value, err := fixedLocalReadValue(ins, 0, state, sig, proof, residue, width, false)
	if err != nil {
		return err
	}
	return fixedLocalWriteValue(ins, 1, 0, value, state, sig, proof, residue, width)
}

func fixedLocalVectorStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) error {
	if effect, known, err := fixedLocalVectorByteEffect(*ins); known {
		if err != nil {
			return err
		}
		return fixedLocalTypedByteStep(ins, state, FuncSig{}, proof, residue, effect)
	}
	width := uint64(65535)
	first, second, destination, memory := 0, 1, 1, -1
	if form, known, err := x86FloatCompareProperties(*ins, "amd64"); known {
		if err != nil || !form.legacy || form.scalar || form.byteWidth != 16 {
			return goAMD64FrameContext("fixed local compare shape is not closed")
		}
		first, second, destination, memory = form.first, form.second, form.destination, form.memory
	} else {
		return goAMD64FrameContext("fixed local source has an unregistered typed vector effect: %s", ins.Op)
	}
	if state.vectors[x86CallerVectorRoot(ins.Args[second].Reg)]&width != width {
		return goAMD64FrameContext("fixed local vector operation reads undefined destination bytes")
	}
	if memory >= 0 {
		if _, _, err := fixedLocalReadMemory(ins, memory, state, proof, residue, 16, 16); err != nil {
			return err
		}
	} else if state.vectors[x86CallerVectorRoot(ins.Args[first].Reg)]&width != width {
		return goAMD64FrameContext("fixed local vector operation reads undefined source bytes")
	}
	state.vectors[x86CallerVectorRoot(ins.Args[destination].Reg)] |= width
	return nil
}

func (c *amd64Ctx) fixedLocalMemoryCertified(ins Instr, index int) bool {
	access, valid := c.fixedLocalMemoryAccess(ins, index)
	return valid && !access.nativeInput
}

func (c *amd64Ctx) fixedLocalMemoryAccess(ins Instr, index int) (x86FixedLocalAccess, bool) {
	access, found := ins.x86FixedLocalMemory[index]
	shape, err := fixedLocalInstructionDigest(ins)
	if !found || c.fixedLocal == nil || access.owner != c.fixedLocal || ins.x86Encoded ||
		ins.x86SourceRaw != nil || ins.x86AddressBits != 0 || ins.x86SegmentPrefix != 0 ||
		err != nil || access.shape != shape || access.width <= 0 {
		return x86FixedLocalAccess{}, false
	}
	expected, bound := c.fixedLocal.accesses[access.ordinal][index]
	return access, bound && reflect.DeepEqual(access, expected)
}
