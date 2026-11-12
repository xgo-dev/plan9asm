package plan9asm

import "math"

// A syntax-only descriptor for an innermost, single-entry straight-line loop.
// Counter values, storage and all per-iteration effects are checked by the
// ordinary replay. Unknown or more general loops retain the existing CFG meet.
type x86FixedLocalCountedLoop struct {
	header, update, latch int
	counter               Reg
	delta                 int64
	bound                 uint64
}

func fixedLocalCountedLoops(fn Func, edges map[int][]int, instructions []int) map[int]x86FixedLocalCountedLoop {
	linear := fixedLocalLinearEdges(fn, edges, instructions)
	end := make([]int, len(instructions))
	for pc := len(instructions) - 1; pc >= 0; pc-- {
		end[pc] = pc
		if linear[pc] {
			end[pc] = end[pc+1]
		}
	}
	var loops map[int]x86FixedLocalCountedLoop
	for latch := 2; latch+1 < len(instructions); latch++ {
		targets := edges[latch]
		if len(targets) != 2 || targets[0] != latch+1 {
			continue
		}
		header := targets[1]
		if header <= 0 || header > latch-2 || end[header] != latch {
			continue // Full predecessor counts exclude side entries and nested branches.
		}
		condition := x86BranchCondition(fn.Instrs[instructions[latch]].Op)
		if condition != "CS" && condition != "HI" {
			continue
		}
		compare := fn.Instrs[instructions[latch-1]]
		cmp, recognized, err := x86ScalarCompareProperties(compare.Op, compare, "amd64")
		if !recognized || err != nil || cmp.test || cmp.bits != 64 ||
			cmp.args[0].Kind != OpReg || cmp.args[1].Kind != OpImm {
			continue
		}
		counter, valid := x86CallerGP(cmp.args[0].Reg)
		if !valid || counter != cmp.args[0].Reg || counter == SP {
			continue
		}
		// These straight-line bodies cannot overlap: another latch would
		// terminate end[header]. Their combined backwards scan stays O(N).
		// Replay checks that every other typed transfer preserves the counter.
		for update := latch - 2; update >= header; update-- {
			delta := fixedLocalCountedDelta(fn.Instrs[instructions[update]], counter)
			if delta == 0 || delta > 0 && condition != "CS" || delta < 0 && condition != "HI" {
				continue
			}
			if loops == nil {
				loops = make(map[int]x86FixedLocalCountedLoop)
			}
			loops[header] = x86FixedLocalCountedLoop{header, update, latch, counter, delta, uint64(cmp.args[1].Imm)}
			break
		}
	}
	return loops
}

func fixedLocalCountedDelta(ins Instr, counter Reg) int64 {
	form, recognized, err := x86LockScalarRMWProperties(ins.Op, ins, "amd64")
	if !recognized || err != nil || form.spec.bits != 64 ||
		form.destination.Kind != OpReg || form.destination.Reg != counter {
		return 0
	}
	switch form.spec.stem {
	case "ADD", "SUB":
		if form.source.Kind == OpImm {
			delta := form.source.Imm // The shared grammar applies encoded imm32 sign extension.
			if form.spec.stem == "SUB" {
				delta = -delta
			}
			return delta
		}
	case "INC":
		return 1
	case "DEC":
		return -1
	}
	return 0
}

func (loop x86FixedLocalCountedLoop) number(state *x86FixedLocalState) (uint64, bool) {
	value, known := state.constants[loop.counter]
	return uint64(value), known && fixedLocalNumericRead(Operand{Kind: OpReg, Reg: loop.counter}, 8, state)
}

func (loop x86FixedLocalCountedLoop) next(value uint64) (uint64, error) {
	if loop.delta > 0 {
		step := uint64(loop.delta)
		if value > math.MaxUint64-step {
			return 0, goAMD64FrameContext("fixed local counted-loop counter wraps")
		}
		return value + step, nil
	}
	step := uint64(-loop.delta)
	if value < step {
		return 0, goAMD64FrameContext("fixed local counted-loop counter wraps")
	}
	return value - step, nil
}

func (loop x86FixedLocalCountedLoop) continues(value uint64) bool {
	if loop.delta > 0 {
		return value < loop.bound
	}
	return value > loop.bound
}

// Keep every iteration, including early aliases. A fresh visit from an outer
// fixed point replaces the provisional series; it never appends stale visits.
func fixedLocalCountedAccesses(previous, current map[int]x86FixedLocalAccess, iteration int) error {
	if iteration != 0 && len(previous) != len(current) {
		return goAMD64FrameContext("fixed local counted-loop access inventory changed")
	}
	for operand, access := range current {
		if iteration == 0 {
			access.iterationOffsets = [][8]int64{access.offset}
		} else {
			prior, found := previous[operand]
			if !found || !fixedLocalAccessShapeEqual(prior, access) ||
				len(prior.iterationOffsets) != iteration {
				return goAMD64FrameContext("fixed local counted-loop access role changed")
			}
			prior.iterationOffsets = append(prior.iterationOffsets, access.offset)
			access = prior
		}
		current[operand] = access
	}
	return nil
}
