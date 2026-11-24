package plan9asm

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/arch/arm64/arm64asm"
	"math"
	"math/bits"
	"reflect"
)

// --- arm64_raw_context_control.go ---
// The coarse general CFG intentionally merges helper inputs. For a checked
// raw zero-frame source, that can mix incoming pointers with disjoint private
// scratch. Reuse the independent call-context interpreter instead of granting
// alias permission to its mixed store. Nothing is published from a failed or
// partial proof, and ordinary/raw-native functions retain the coarse path.
func (c *arm64Ctx) rawZeroContextControlPlan(outer string) *arm64LocalControlPlan {
	if !c.unexposedCallFrame || c.sourceGoFrame.present ||
		!arm64CallFrameFreshEntry(c.sig) || c.sig.ARM64ClosureABI != nil {
		return nil
	}
	if c.sig.ARM64GoRegisterABI != nil && arm64ValidateGoRegisterABI(c.sig) != nil {
		return nil
	}
	if !reflect.DeepEqual(c.blocks, arm64SplitBlocks(c.normalizedSource)) {
		return nil
	}
	plan := &arm64LocalControlPlan{
		before:      make(map[[2]int]arm64ControlValue),
		stackBefore: make(map[[2]int]arm64ControlValue),
		linkBefore:  make(map[[2]int]arm64ControlValue),
		reachable:   make([]bool, len(c.blocks)),
		outer:       outer,
	}
	transport := &arm64PrivateFrameTransport{entry: c.sig, resolve: c.resolve, sigs: c.sigs}
	if !arm64RawZeroFrameProof(c.normalizedSource, transport, plan) {
		return nil
	}
	return plan
}

func (plan *arm64LocalControlPlan) recordRawZeroReturn(block, instruction int, state *arm64ControlState, entryLink string) {
	point := [2]int{block, instruction}
	link := arm64ControlFromMap(make(map[string]bool))
	for _, token := range arm64ControlKeys(arm64ControlRead(state.regs, "R30")) {
		if token == entryLink {
			token = "label:" + plan.outer
		}
		link = arm64ControlSetToken(link, token, true)
	}
	plan.before[point] = arm64ControlUnion(plan.before[point], link)
	plan.linkBefore[point] = arm64ControlUnion(plan.linkBefore[point], link)
	plan.stackBefore[point] = arm64ControlUnion(plan.stackBefore[point], arm64ControlRead(state.regs, SP))
}

// --- arm64_raw_pool_affine_mask.go ---
// AND is not affine. Keep its interval even when it is not an exact value.
// Only an exact result, such as [8,15] & 24 == 8, permits constant substitution.
func (flow *arm64RawPoolValues) affineMaskInterval(at int, word uint32) (arm64PoolInterval, bool) {
	if word&0xff800000 != 0x92000000 { // AND Xd, Xn, logical immediate.
		return arm64PoolInterval{}, false
	}
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	ins, err := arm64asm.Decode(code[:])
	if err != nil || ins.Op != arm64asm.AND {
		return arm64PoolInterval{}, false
	}
	source, ok := ins.Args[1].(arm64asm.Reg)
	if !ok || source < arm64asm.X0 || source > arm64asm.XZR {
		return arm64PoolInterval{}, false
	}
	var mask uint64
	switch operand := ins.Args[2].(type) {
	case arm64asm.Imm:
		mask = uint64(operand.Imm)
	case arm64asm.Imm64:
		mask = operand.Imm
	default:
		return arm64PoolInterval{}, false
	}
	if flow.maskConstants == nil {
		flow.maskConstants = make(map[int]uint64)
	}
	input := flow.integerInterval(at, source)
	if input.low > input.high {
		return arm64PoolUnknownInterval, false
	}
	result := arm64PoolMaskInterval(input, mask)
	if result.low == result.high {
		flow.maskConstants[at] = result.low
	}
	return result, true
}

func arm64PoolMaskInterval(input arm64PoolInterval, mask uint64) arm64PoolInterval {
	if input.low > input.high {
		return arm64PoolUnknownInterval
	}
	// Partition into aligned power-of-two blocks. Each block has independent
	// low bits, so its masked extrema are exact. Union at most 128 blocks;
	// treating every bit below the endpoints' common prefix as free would
	// incorrectly include zero in [8,19] & 24 and lose loop termination proof.
	result := arm64PoolInterval{math.MaxUint64, 0}
	for low := input.low; ; {
		remaining := input.high - low
		width := bits.TrailingZeros64(low)
		if remaining != math.MaxUint64 {
			if available := bits.Len64(remaining+1) - 1; available < width {
				width = available
			}
		}
		varying := uint64(1)<<uint(width) - 1
		if minimum := low & mask; minimum < result.low {
			result.low = minimum
		}
		if maximum := (low | varying) & mask; maximum > result.high {
			result.high = maximum
		}
		if varying == remaining {
			return result
		}
		low += varying + 1
	}
}

// --- arm64_raw_pool_affine_residual.go ---
// q = scale*guard + remainder. The remainder can be an independent bounded
// value, notably the relocated pool origin. Prove it at this exact program
// point rather than treating an unrelated register as a constant by name.
func (flow *arm64RawPoolValues) affineConstraintBound(at int, query arm64PoolAffine, constraint arm64PoolConstraint) (arm64PoolInterval, bool) {
	if constraint.mask != 0 || constraint.after != 0 {
		return arm64PoolInterval{}, false
	}
	if bound, ok := query.constrainedBy(constraint); ok {
		return bound, true
	}
	if flow.affineDirect {
		return arm64PoolInterval{}, false
	}
	// An almost-full-width NE/range guard cannot independently bound a pool
	// footprint through an unrelated residual. Recursing on it repeatedly
	// consumes the shared budget in loops. Keep the direct fact above, and
	// defer decomposition until guard intersection narrows the interval.
	if constraint.interval.high-constraint.interval.low > math.MaxInt64 {
		return arm64PoolInterval{}, false
	}
	for index, coefficient := range constraint.expression.coefficient {
		if coefficient == 0 || query.coefficient[index] == 0 || query.coefficient[index]%coefficient != 0 {
			continue
		}
		scale := query.coefficient[index] / coefficient
		remainder := query
		if !remainder.add(constraint.expression, -scale) {
			continue
		}
		// The eliminated coefficient makes this a strictly different query.
		// Recursive proof budgets and active-query detection still apply.
		residual := flow.invariantInterval(at, remainder)
		if residual == arm64PoolUnknownInterval {
			// If only part of the guard was eliminated, recursively bounding
			// its remaining operands chases the same dependency cycle. A known
			// invariant above is fine; otherwise defer until definitions have
			// normalized all guard operands out of the remainder.
			if remainder.registerMask()&constraint.expression.registerMask() != 0 {
				continue
			}
			residual = flow.affineInterval(at, remainder)
		}
		if residual == arm64PoolUnknownInterval {
			continue
		}
		bound := arm64PoolIntervalImage(constraint.interval, scale, residual.low)
		width := residual.high - residual.low
		if bound.high > math.MaxUint64-width {
			continue
		}
		bound.high += width
		return bound, true
	}
	return arm64PoolInterval{}, false
}

// --- arm64_raw_pool_affine_state.go ---
// Transfer helpers still receive the complete value state. Only this proof's
// queue and visited table use an exact, query-local constraint-set identity.
type arm64PoolAffineStateKey struct {
	at         int
	expression arm64PoolAffine
	bound      arm64PoolInterval
	set        int
	count      int
}

// A bucket is not a constraint identity. Omitting coefficients makes the lookup
// smaller, but all candidates still require complete array equality below.
// Inactive slots, ordering and historical flag positions remain significant.
type arm64PoolConstraintBucket [8]struct {
	constant    uint64
	relocations int64
	interval    arm64PoolInterval
	mask        uint64
	after       int
}

func arm64PoolConstraintBucketFor(constraints *[8]arm64PoolConstraint) arm64PoolConstraintBucket {
	var bucket arm64PoolConstraintBucket
	for n := range constraints {
		constraint := &constraints[n]
		bucket[n].constant = constraint.expression.constant
		bucket[n].relocations = constraint.expression.relocations
		bucket[n].interval = constraint.interval
		bucket[n].mask = constraint.mask
		bucket[n].after = constraint.after
	}
	return bucket
}

type arm64PoolAffineStateSets struct {
	sets    [][8]arm64PoolConstraint
	buckets map[arm64PoolConstraintBucket][]int
}

func (sets *arm64PoolAffineStateSets) identity(constraints *[8]arm64PoolConstraint) int {
	// Zero is the exact all-zero array, not merely an empty active prefix.
	if *constraints == [8]arm64PoolConstraint{} {
		return 0
	}
	bucket := arm64PoolConstraintBucketFor(constraints)
	for _, identity := range sets.buckets[bucket] {
		if sets.sets[identity-1] == *constraints {
			return identity
		}
	}
	if sets.buckets == nil {
		sets.buckets = make(map[arm64PoolConstraintBucket][]int)
	}
	// Copy the entire array. A later transfer cannot mutate a stored set or any
	// previously queued/visited state, and expansion returns another value copy.
	sets.sets = append(sets.sets, *constraints)
	identity := len(sets.sets)
	sets.buckets[bucket] = append(sets.buckets[bucket], identity)
	return identity
}

func (sets *arm64PoolAffineStateSets) compact(state *arm64PoolAffineState) arm64PoolAffineStateKey {
	return arm64PoolAffineStateKey{
		at: state.at, expression: state.expression, bound: state.bound,
		set: sets.identity(&state.constraints), count: state.count,
	}
}

func (sets *arm64PoolAffineStateSets) expand(key arm64PoolAffineStateKey) arm64PoolAffineState {
	state := arm64PoolAffineState{
		at: key.at, expression: key.expression, bound: key.bound, count: key.count,
	}
	if key.set != 0 {
		state.constraints = sets.sets[key.set-1]
	}
	return state
}

// --- arm64_raw_pool_guard.go ---
// edgeUpper proves an unsigned bound on the selected CFG edge, not on the
// branch instruction as a whole. Inspect both successors even when they merge:
// the opposite edge must never inherit the taken edge's bound.
func (flow *arm64RawPoolValues) edgeUpper(edge arm64RawPoolEdge, reg arm64asm.Reg) (uint64, bool) {
	index, ok := arm64RawPoolGP(reg)
	if !ok || edge.from < 0 {
		return 0, false
	}
	word := flow.words[edge.from]
	conditional := word&0xff000010 == 0x54000000
	zeroBranch := word&0x7e000000 == 0x34000000
	if !conditional && !zeroBranch {
		return 0, false
	}
	target := edge.from + int(int32(word<<8)>>13)
	if target == edge.from+1 || edge.to != target && edge.to != edge.from+1 {
		return 0, false
	}
	taken := edge.to == target
	if zeroBranch {
		// W comparisons do not constrain an X register's upper 32 bits.
		if int(word&31) != index || word>>31 == 0 && reg >= arm64asm.X0 {
			return 0, false
		}
		return 0, taken == (word&(1<<24) == 0)
	}

	// Require the immediately preceding CMP to dominate this branch. Merely
	// looking at adjacent bytes is unsound when another edge bypasses the CMP.
	predecessors := flow.before[edge.from]
	if len(predecessors) != 1 || predecessors[0] != edge.from-1 || edge.from == 0 {
		return 0, false
	}
	compare := flow.words[edge.from-1]
	if compare&0x7f80001f != 0x7100001f || int(compare>>5&31) != index ||
		compare>>31 == 0 && reg >= arm64asm.X0 {
		return 0, false
	}
	immediate := uint64(compare >> 10 & 4095)
	if compare&(1<<22) != 0 {
		immediate <<= 12
	}
	condition := word & 15
	if !taken {
		condition ^= 1
	}
	switch condition {
	case 0, 9: // EQ or LS.
		return immediate, true
	case 3: // LO. For CMP #0 this edge has no feasible machine state.
		if immediate == 0 {
			return 0, true
		}
		return immediate - 1, true
	default:
		// Signed comparisons admit negative indexes; flags such as overflow
		// and sign alone do not establish an unsigned interval.
		return 0, false
	}
}

// --- arm64_raw_pool_impossible_compare.go ---
// Remove only edges whose independently bounded incoming value cannot satisfy
// the unchanged CMP/CMN condition. This is proof-graph refinement, not deletion
// of executable branches. In particular, a larger VL can make an entire SVE
// path unreachable even though its unconstrained pool offsets do not fit.
func (flow *arm64RawPoolValues) refineConstantCompareEdges() {
	for at, word := range flow.words {
		if word&0xff000010 != 0x54000000 {
			continue
		}
		switch word & 15 {
		case 2, 3, 8, 9:
		default:
			continue
		}
		target := at + int(int32(word<<8)>>13)
		for _, next := range []int{at + 1, target} {
			if next < 0 || next >= len(flow.before) {
				continue
			}
			edge := arm64RawPoolEdge{at, next}
			guard, ok := flow.affineEdgeConstraint(edge)
			if !ok || guard.after != 0 || guard.mask != 0 {
				continue
			}
			numeric := flow.numericValues()
			input := numeric.affineInterval(at, guard.expression)
			if input.high < guard.interval.low || input.low > guard.interval.high {
				flow.excludeEdge(edge)
			}
		}
	}
}

// --- arm64_raw_pool_materialize.go ---
// Track overwritten bit fields back to an immediate seed. This is a finite
// definition walk, not a recursive value query, so a MOVK inside a changing
// loop cannot recursively ask itself for its own input. Covering every bit
// also proves a constant without an initial MOVZ/MOVN.
func (flow *arm64RawPoolValues) materializedConstant(at int, word uint32) (uint64, bool) {
	keep, value := uint64(math.MaxUint64), uint64(0)
	for steps := 0; steps < 64; steps++ {
		ins, decoded := arm64PoolDecodeWord(word)
		if !decoded {
			return 0, false
		}
		if ins.Op != arm64asm.MOVK {
			_, initial, affine := arm64PoolAffineDefinition(word)
			if affine && initial.isConstant() && initial.relocations == 0 {
				return value | initial.constant&keep, true
			}
			return 0, false
		}
		shift := (word >> 21 & 3) * 16
		mask := uint64(0xffff) << shift
		value |= uint64(word>>5&0xffff) << shift & keep
		keep &^= mask
		if word>>31 == 0 {
			keep &= math.MaxUint32
		}
		if keep == 0 {
			return value, true
		}
		_, previous, known := flow.valueDefinition(arm64PoolValuePoint{at, int(word & 31)})
		if !known {
			return 0, false
		}
		at, word = previous, flow.words[previous]
	}
	return 0, false
}

func (flow *arm64RawPoolValues) affineMoveKeepInterval(at int, word uint32) (arm64PoolInterval, bool) {
	if word&0x7f800000 != 0x72800000 || word&31 == 31 {
		return arm64PoolInterval{}, false
	}
	ins, ok := arm64PoolDecodeWord(word)
	if !ok || ins.Op != arm64asm.MOVK {
		return arm64PoolInterval{}, false
	}
	if constant, known := flow.materializedConstant(at, word); known {
		return arm64PoolInterval{constant, constant}, true
	}
	shift := (word >> 21 & 3) * 16
	mask := ^(uint64(0xffff) << shift)
	if word>>31 == 0 {
		mask &= math.MaxUint32 // A W write also clears the entire upper X half.
	}
	input := flow.integerInterval(at, arm64asm.X0+arm64asm.Reg(word&31))
	result := arm64PoolMaskInterval(input, mask)
	immediate := uint64(word>>5&0xffff) << shift
	// Both extrema have the replaced field cleared. OR is therefore an
	// exact addition of that field, with no carry into any preserved bit.
	result.low |= immediate
	result.high |= immediate
	return result, true
}

// --- arm64_raw_pool_relational_loop.go ---
// Prove the first comparison is equal on every external entry. This excludes
// only the nonzero backedge; it does not infer a general multi-iteration range.
// Rewind the compared expression, not independent ranges for its operands.
func (flow *arm64RawPoolValues) proveRelationalOneIterationLoop(latch int) {
	word := flow.words[latch]
	if word&0xff00001f != 0x54000001 {
		return
	}
	head := latch + int(int32(word<<8)>>13)
	if flow.excluded[arm64RawPoolEdge{latch, head}] || !flow.straightLineLoopBody(head, latch) {
		return
	}
	compare, _, after, known := flow.affineFlagSourceBefore(latch)
	if !known || after <= head || after > latch {
		return
	}
	_, expression, affine := flow.affineDefinition(compare &^ ((1 << 29) | 31))
	if !affine {
		return
	}
	for at := after - 2; at >= head; at-- {
		writes, _ := flow.gpWrites(flow.words[at])
		if affected := writes & expression.registerMask(); affected != 0 {
			destination, value, valid := flow.affineDefinition(flow.words[at])
			if !valid || affected != 1<<uint(destination) || !expression.substitute(destination, value) {
				return
			}
		}
	}
	entry := flow.counterLoopEntry(head, latch)
	if entry == nil {
		return
	}
	entry = entry.numericValues()
	// Rewinding can introduce an invariant step (for example RDVL). Prove
	// its entry value independently; a prior enclosing iteration remains
	// opaque whenever it could have changed the queried register.
	for register, coefficient := range expression.coefficient {
		if coefficient == 0 {
			continue
		}
		bound := entry.invariantInterval(head, arm64PoolRegisterExpression(register))
		if bound.low == bound.high {
			if !expression.substitute(register, arm64PoolAffine{constant: bound.low}) {
				return
			}
		}
	}
	if entry.affineInterval(head, expression) == (arm64PoolInterval{0, 0}) {
		flow.excludeEdge(arm64RawPoolEdge{latch, head})
	}
}

// --- arm64_raw_pool_shift_guard.go ---
func arm64PoolShiftConstraint(word uint32, constraint arm64PoolConstraint) (arm64PoolConstraint, bool) {
	if constraint.after != 0 || constraint.mask != 0 || word>>31 == 0 || word&31 == 31 ||
		constraint.expression != arm64PoolRegisterExpression(int(word&31)) {
		return constraint, false
	}
	ins, decoded := arm64PoolDecodeWord(word)
	shift, immediate := ins.Args[2].(arm64asm.Imm)
	if !decoded || ins.Op != arm64asm.LSR || !immediate {
		return constraint, false
	}
	maximum := uint64(math.MaxUint64) >> shift.Imm
	if constraint.interval.high > maximum {
		constraint.interval.high = maximum
	}
	constraint.expression = arm64PoolRegisterExpression(int(word >> 5 & 31))
	if constraint.interval.low > constraint.interval.high {
		constraint.interval = arm64PoolInterval{1, 0}
		return constraint, true
	}
	constraint.interval.low <<= shift.Imm
	constraint.interval.high = constraint.interval.high<<shift.Imm | (uint64(1)<<shift.Imm - 1)
	return constraint, true
}

// --- arm64_raw_pool_sve_alias.go ---
// ADDVL/ADDPL preserve one relocated address. Their signed six-bit immediate
// scales the architectural VL (16..256 bytes) or PL (2..32 bytes), never merely
// the host's current value. RDVL produces a number, not an address alias.
func arm64RawPoolScalableAlias(form arm64RawSVEAddress, offset arm64RawPoolRange, bounds *arm64RawPoolBounds) (arm64RawPoolRange, bool) {
	if form.op == "RDVL" || form.destination == 31 || bounds == nil {
		return arm64RawPoolRange{}, false
	}
	if bounds.symbolic {
		// Numeric offsets are recovered from reaching definitions at every
		// dereference. Only a fixed architectural partition can model them.
		return arm64RawPoolRange{}, bounds.values.vectorBytes != 0
	}
	unit := int64(16)
	if form.op == "ADDPL" {
		unit = 2
	}
	low := int64(form.immediate) * unit
	high := low * 16
	if low > high {
		low, high = high, low
	}
	if offset.low < 0 || offset.high > bounds.size ||
		low < -offset.low || high > bounds.size-offset.high {
		return arm64RawPoolRange{}, false
	}
	return arm64RawPoolRange{offset.low + low, offset.high + high}, true
}

// --- arm64_raw_pool_sve_memory.go ---
// A scalable transfer is accepted only inside a fixed architectural VL
// partition. The caller proves all partitions. Predicate loads transfer VL/8
// bytes, whereas whole-vector loads transfer VL bytes; stores are never reads
// of a relocatable constant pool.
func (bounds *arm64RawPoolBounds) wholeScalableLoadInBounds(at int, form arm64RawSVELoadStore) bool {
	if !form.load || bounds == nil || !bounds.symbolic || bounds.values.vectorBytes == 0 || form.base == 31 {
		return false
	}
	width := bounds.values.vectorBytes
	if form.predicate {
		width /= 8
	}
	expression := arm64PoolRegisterExpression(form.base)
	expression.constant = uint64(int64(form.immediate) * width)
	return bounds.scalableFootprintInBounds(at, expression, width)
}

// Reuse the complete signed/unsigned scalar-base LD1 grammar, including
// widening arrangements. Gather, PN, first-fault and non-faulting operations
// have different address/state contracts and are not ordinary contiguous reads.
func arm64RawPoolContiguousLoad(word uint32) (arm64RawSVELoadRow, bool) {
	row, ok := arm64RawSVEUnsignedLoadRows[word&0xffe0e000]
	if !ok {
		row, ok = arm64RawSVELoadRows[word&0xffe0e000]
	}
	if !ok || row.address != arm64SVELoadRegister && row.address != arm64SVELoadImmediate {
		return arm64RawSVELoadRow{}, false
	}
	// In particular, Xm=31 and the high immediate bit are reserved, not
	// aliases of zero. The lowerer's decoder is the authority for these fields.
	_, valid := decodeARM64RawSVELoadAddress(word, row)
	return row, valid
}

func (bounds *arm64RawPoolBounds) contiguousScalableLoadInBounds(at int, word uint32, row arm64RawSVELoadRow) bool {
	base := int(word>>5) & 31
	if bounds == nil || !bounds.symbolic || bounds.values.vectorBytes == 0 || base == 31 {
		return false
	}
	spec := arm64SVEOrdinaryMemorySpecs[row.op]
	// Conservatively assume every predicate lane is active. Extending a
	// memory element changes the destination width, never the bytes accessed.
	width := bounds.values.vectorBytes * int64(spec.memoryBits) / int64(row.elementBits)
	expression := arm64PoolRegisterExpression(base)
	if row.address == arm64SVELoadRegister {
		index := int(word>>16) & 31
		expression.add(arm64PoolRegisterExpression(index), row.scale)
	} else {
		immediate := int64(word>>16) & 15
		if immediate >= 8 {
			immediate -= 16
		}
		expression.constant = uint64(immediate * width)
	}
	return bounds.scalableFootprintInBounds(at, expression, width)
}

func (bounds *arm64RawPoolBounds) scalableFootprintInBounds(at int, expression arm64PoolAffine, width int64) bool {
	value := bounds.values.invariantInterval(at, expression)
	if value == arm64PoolUnknownInterval {
		value = bounds.values.affineInterval(at, expression)
	}
	return value.low <= value.high && value.high <= uint64(bounds.size) &&
		arm64RawPoolContains(int64(value.low), width, bounds.size) &&
		arm64RawPoolContains(int64(value.high), width, bounds.size)
}

// --- arm64_raw_pool_symbolic.go ---
func (bounds *arm64RawPoolBounds) withSymbolicOrigin(at int) *arm64RawPoolBounds {
	copy := *bounds
	copy.symbolic = true
	origins := bounds.origins
	if len(origins) == 0 {
		origins = map[int]uint64{at: uint64(bounds.offset)}
	}
	// Origins share one pool base but remain proof-local. Never reuse a cache
	// computed with a different pool basis or modify ordinary integer analysis.
	copy.values = &arm64RawPoolValues{
		vectorBytes: bounds.values.vectorBytes,
		words:       bounds.values.words, before: bounds.values.before,
		cache: make(map[arm64RawPoolValue]uint64), active: make(map[arm64RawPoolValue]bool),
		poolOrigins: origins,
		excluded:    bounds.values.excluded, loopBounds: bounds.values.loopBounds,
		loopLatches: bounds.values.loopLatches,
	}
	return &copy
}

func (bounds *arm64RawPoolBounds) offsetAt(at int, register arm64asm.Reg, fallback arm64RawPoolRange) (arm64RawPoolRange, bool) {
	if bounds == nil || !bounds.symbolic {
		return fallback, true
	}
	expression := arm64PoolRegisterExpression(int(register - arm64asm.X0))
	value := bounds.values.invariantInterval(at, expression)
	if value == arm64PoolUnknownInterval {
		value = bounds.values.affineInterval(at, expression)
	}
	if value.low > value.high || value.high > uint64(bounds.size) {
		return arm64RawPoolRange{}, false
	}
	return arm64RawPoolRange{int64(value.low), int64(value.high)}, true
}

func arm64RawPoolSymbolicAlias(word uint32, address int) (int, bool) {
	// Restrict this extension to MOV/ADD/SUB without flag writes. The affine
	// decoder excludes truncation and SP operands. Scaling or subtracting the
	// relocated address itself would change its relocation coefficient.
	if word&0xffe0ffe0 != 0xaa0003e0 && word&0xbf800000 != 0x91000000 && word&0xbf000000 != 0x8b000000 {
		return 0, false
	}
	destination, expression, ok := arm64PoolAffineDefinition(word)
	return destination, ok && expression.coefficient[address] == 1
}

// --- arm64_raw_scalar_register_effects.go ---
// This scalar physical operand grammar is shared by native GP/R27/NZCV
// observers. Go's obj7 cases 3 and 27 use these exact encoding classes,
// including aliases. It supplies effects only, never a frame or input fact.
type arm64RawScalarRegister struct {
	width                      int
	first, second, destination int
	extended                   bool
	flags                      bool
}

func decodeARM64RawScalarRegister(word uint32) (arm64RawScalarRegister, bool) {
	width := 32
	if word>>31 != 0 {
		width = 64
	}
	form := arm64RawScalarRegister{
		width: width, first: int(word>>5) & 31,
		second: int(word>>16) & 31, destination: int(word) & 31,
	}
	switch {
	case word&0x1f000000 == 0x0a000000:
		// Logical shifted register: all four shifts, both complement states,
		// and AND/OR/EOR/ANDS. W shifts must not set imm6's high bit.
		if int(word>>10&63) >= width {
			return arm64RawScalarRegister{}, false
		}
		form.flags = word>>29&3 == 3
	case word&0x1f200000 == 0x0b000000:
		// ADD/SUB shifted register: ROR is reserved, unlike logical shifts.
		if word>>22&3 == 3 || int(word>>10&63) >= width {
			return arm64RawScalarRegister{}, false
		}
		form.flags = word&(1<<29) != 0
	case word&0x1fe00000 == 0x0b200000:
		// ADD/SUB extended register: all eight extensions, shift 0..4.
		// Rm=31 is zero even where Rn or a non-S Rd=31 denotes SP.
		if word>>10&7 > 4 {
			return arm64RawScalarRegister{}, false
		}
		form.extended = true
		form.flags = word&(1<<29) != 0
	default:
		return arm64RawScalarRegister{}, false
	}
	return form, true
}

func (form arm64RawScalarRegister) gpEffects() (reads, writes uint32, stack bool) {
	if form.second != 31 {
		reads |= 1 << uint(form.second)
	}
	if form.first != 31 {
		reads |= 1 << uint(form.first)
	} else if form.extended {
		stack = true
	}
	if form.destination != 31 {
		writes |= 1 << uint(form.destination)
	} else if form.extended && !form.flags {
		stack = true
	}
	return reads, writes, stack
}

// --- arm64_raw_word_preflight.go ---
// Native-target preflights must not disguise malformed WORDs as missing
// target context. This is syntax-only: registered forms still require their
// original source, machine-entry, continuation and layout proofs later.
func arm64RawWordPreflightError(instruction Instr) error {
	if instruction.Op != OpWORD {
		return nil
	}
	word, err := arm64RawWordValue(instruction)
	if err != nil {
		return err
	}
	if arm64RawNativeConversion(word) {
		return nil
	}
	if _, valid := arm64RawContinuationEffectsForWord(word); valid {
		return nil
	}
	if _, valid := arm64RawSVEEffects(word); valid {
		return nil
	}
	// The placeholder only lets the decoder check PC-relative syntax. It is
	// never an edge or source-location witness consumed by translation.
	_, err = decodeARM64RawWordInstructionTarget(instruction, "preflight")
	return err
}

// Go's AWORD constant row is C_LCON, classified before case 14 truncates to
// uint32. Wide MOV/bitmask constants can satisfy that row; arbitrary C_VCON
// values cannot, even when their low word happens to encode a valid opcode.
func arm64RawWordValue(instruction Instr) (uint32, error) {
	for _, operand := range instruction.Args {
		if err := unresolvedSymbolicImmediateError(operand); err != nil {
			return 0, fmt.Errorf("arm64 WORD: %w", err)
		}
	}
	if len(instruction.Args) != 1 || instruction.Args[0].Kind != OpImm ||
		instruction.Args[0].ImmRaw != "" || instruction.Args[0].ImmIsFloat {
		return 0, fmt.Errorf("arm64 WORD expects exactly one resolved integer constant: %q", instruction.Raw)
	}
	value := instruction.Args[0].Imm
	if !arm64GoLCON(value) {
		return 0, fmt.Errorf("arm64 WORD constant does not satisfy Go's C_LCON operand class: %q", instruction.Raw)
	}
	return uint32(value), nil
}
