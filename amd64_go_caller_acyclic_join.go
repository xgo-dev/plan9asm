package plan9asm

import (
	"math"
	"reflect"
)

// A span is an abstract set of offsets from the same authenticated input.
// It is not an allocation extent or a promise that an unsafe read cannot fault.
func x86CallerPointerEnd(pointer x86CallerPointerValue) (int64, bool) {
	if pointer.span < 0 || pointer.offset > math.MaxInt64-pointer.span {
		return 0, false
	}
	end := pointer.offset + pointer.span
	return end, pointer.offset >= -x86SourceStackLimit && end <= x86SourceStackLimit
}

func x86CallerPointerShift(pointer x86CallerPointerValue, delta int64) (x86CallerPointerValue, bool) {
	if _, valid := x86CallerPointerEnd(pointer); !valid ||
		delta > 0 && pointer.offset > math.MaxInt64-delta ||
		delta < 0 && pointer.offset < math.MinInt64-delta {
		return pointer, false
	}
	pointer.offset += delta
	_, valid := x86CallerPointerEnd(pointer)
	return pointer, valid
}

func x86CloneCallerState(state x86SourceStackState) x86SourceStackState {
	if state.cells != nil {
		cells := make([]x86SourceStackCell, len(state.cells))
		copy(cells, state.cells)
		state.cells = cells
	}
	for index := range state.cells {
		if state.cells[index].bp != nil {
			value := *state.cells[index].bp
			state.cells[index].bp = &value
		}
		if state.cells[index].caller != nil {
			value := *state.cells[index].caller
			state.cells[index].caller = &value
		}
	}
	state.callers = x86CloneCallerPointers(state.callers)
	state.known = x86CloneCallerKnown(state.known)
	state.vectors, state.masks = x86CloneCallerVectorState(state.vectors, state.masks)
	return state
}

// Only numerical definedness and same-origin read-only input offsets merge.
// Neither a missing origin nor a fixed local, stack or continuation can borrow
// this domain. Return a fresh deep clone, never edit either predecessor.
func x86CallerAcyclicMerge(left, right x86SourceStackState, proof *x86GoCallerRegionProof) (x86SourceStackState, bool) {
	if proof == nil || left.sp != right.sp || left.bp != right.bp ||
		left.numericFlags != right.numericFlags || left.partialNumericFlags != right.partialNumericFlags || left.gOriginal != right.gOriginal ||
		!reflect.DeepEqual(left.cells, right.cells) || len(left.callers) != len(right.callers) {
		return x86SourceStackState{}, false
	}
	merged := x86CloneCallerState(left)
	for reg, a := range left.callers {
		b, present := right.callers[reg]
		if !present || a.argument != b.argument || a.argument < 0 || a.argument >= len(proof.arguments) {
			return x86SourceStackState{}, false
		}
		aEnd, aValid := x86CallerPointerEnd(a)
		bEnd, bValid := x86CallerPointerEnd(b)
		if !aValid || !bValid {
			return x86SourceStackState{}, false
		}
		if proof.arguments[a.argument].kind != x86CallerSliceInput {
			if a != b || a.span != 0 {
				return x86SourceStackState{}, false
			}
			continue
		}
		if b.offset < a.offset {
			a.offset = b.offset
		}
		if bEnd > aEnd {
			aEnd = bEnd
		}
		a.span = aEnd - a.offset // Both endpoints already have the 1 MiB bound.
		merged.callers[reg] = a
	}
	// Include absent facts as zero, including on a later predecessor. Retain
	// zero entries so replays do not depend on which predecessor arrived first.
	for reg, value := range right.known {
		merged.known[reg] = left.known[reg] & value
	}
	for reg, value := range left.known {
		merged.known[reg] = value & right.known[reg]
	}
	for reg, value := range right.vectors {
		merged.vectors[reg] = left.vectors[reg] & value
	}
	for reg, value := range left.vectors {
		merged.vectors[reg] = value & right.vectors[reg]
	}
	for reg, value := range right.masks {
		merged.masks[reg] = left.masks[reg] && value
	}
	for reg, value := range left.masks {
		merged.masks[reg] = value && right.masks[reg]
	}
	return merged, true
}

// A new merge cannot establish any cyclic invariant. This deliberately checks
// the entire reachable graph, not only the current edge or label's spelling.
func x86CallerReachableAcyclic(fn Func, instructions []int, labels map[string]int) bool {
	if len(instructions) == 0 || len(instructions) > 8192 {
		return false
	}
	edges := make(map[int][]int)
	seen := make(map[int]bool)
	work := []int{0}
	for len(work) != 0 {
		pc := work[0]
		work = work[1:]
		if pc < 0 || pc >= len(instructions) {
			return false
		}
		if seen[pc] {
			continue
		}
		seen[pc] = true
		ins := fn.Instrs[instructions[pc]]
		op := Op(normalizeInstructionOpcode(ins.Op))
		if op == OpRET {
			continue
		}
		next := []int{pc + 1}
		if op == OpJMP || isAMD64ConditionalBranch(op) {
			if len(ins.Args) != 1 {
				return false
			}
			operand := ins.Args[0]
			label := operand.Sym
			if operand.Kind == OpIdent {
				label = operand.Ident
			}
			target, valid := labels[label]
			if operand.Kind == OpMem && operand.Mem.Base == PC && operand.Mem.Index == "" &&
				operand.Mem.Sym == "" && operand.Mem.Off >= -int64(len(instructions)) && operand.Mem.Off <= int64(len(instructions)) {
				target, valid = pc+int(operand.Mem.Off), true
			} else if operand.Kind != OpLabel && operand.Kind != OpIdent {
				return false
			}
			if !valid {
				return false
			}
			if op == OpJMP {
				next = []int{target}
			} else {
				next = append(next, target)
			}
		}
		edges[pc] = next
		work = append(work, next...)
	}
	indegree := make(map[int]int, len(seen))
	for _, next := range edges {
		for _, pc := range next {
			indegree[pc]++
		}
	}
	work = work[:0]
	for pc := range seen {
		if indegree[pc] == 0 {
			work = append(work, pc)
		}
	}
	removed := 0
	for len(work) != 0 {
		pc := work[0]
		work = work[1:]
		removed++
		for _, next := range edges[pc] {
			indegree[next]--
			if indegree[next] == 0 {
				work = append(work, next)
			}
		}
	}
	return removed == len(seen)
}
