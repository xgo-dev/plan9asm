package plan9asm

import (
	"fmt"
	"reflect"
)

// Shape-only validation may assume register classes, never an external native
// address or a read mask. These operands retain their source-input obligations
// even when a constant selector, zero mask or unreachable result discards data.
// Logical FP/AUTO and independently bound SB/DATA keep their separate owners.
func x86ResultDeadExternalInputs(ins Instr, arch string) bool {
	externalMemory := func(operand Operand) bool {
		if operand.Kind != OpMem || operand.Mem.Sym != "" || x86LogicalSourceFrameRegister(operand.Mem.Base, arch) {
			return false
		}
		_, _, base := x86ResultGP(operand.Mem.Base, x86ResultPointerWord(arch), arch)
		_, _, index := x86ResultGP(operand.Mem.Index, x86ResultPointerWord(arch), arch)
		return base || index
	}
	if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known && err == nil {
		for _, operand := range effect.operands {
			if (operand.read || operand.write) && externalMemory(operand.operand) {
				return true
			}
			if _, mask := amd64ParseKReg(operand.operand.Reg); operand.read && mask {
				return true
			}
		}
		// Typed address calculations may spell OpMem in the source while
		// describing only GP inputs. Syntax alone must not invent a read.
		return false
	}
	for _, operand := range ins.Args {
		if externalMemory(operand) {
			return true
		}
	}
	// Families without a byte descriptor still expose their explicit K input
	// before the final output. A final write-only K result is not an input.
	for index, operand := range ins.Args {
		if index == len(ins.Args)-1 {
			break
		}
		if _, mask := amd64ParseKReg(operand.Reg); operand.Kind == OpReg && mask {
			return true
		}
	}
	return false
}

// This is a separate source-closure proof, never an executable CFG edge or an
// entry/backing permission. Reachable states and result checks remain unchanged.
// A dead region starts with the real poststate of its preceding verified source
// terminator. Its local CFG also checks source fallthrough after dead JMP/RET,
// so disconnected fragments cannot hide unknown external inputs. No dead state
// may flow back into a reachable block or borrow a later reachable producer.
func x86ResultCheckDeadExternalInputs(fn Func, instructions []Instr, ordinals []int, edges [][]int,
	reached map[int]x86ResultState, owned []bool, resultOffset int64, arch string,
	transfer x86ResultSourceTransfer, visits, work *int, byteState int) error {
	var targets []int
	for pc, ins := range instructions {
		if _, live := reached[pc]; !live && x86ResultDeadExternalInputs(ins, arch) {
			targets = append(targets, pc)
		}
	}
	if len(targets) == 0 {
		return nil // Pure dead register arithmetic retains its existing domain.
	}
	fail := func(reason string) error {
		return fmt.Errorf("%w: result initialization: dead external source %s", ErrProbeNeedsContext, reason)
	}
	if fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil {
		return fail("requires its own source-graph entry, not a neighboring function's state")
	}
	reserve := func(bytes int, visit bool) error {
		*work += bytes
		if visit {
			*visits = *visits + 1
		}
		if budget := fn.x86ResultFlowBudget; budget != nil {
			budget.bytes += bytes
			if visit {
				budget.visits++
			}
			if budget.bytes > 64<<20 || budget.visits > 16384 {
				return fail("exhausted the combined source-graph work budget")
			}
		}
		if *work > 64<<20 || *visits > 16384 {
			return fail("exhausted the combined function work budget")
		}
		return nil
	}
	// One bounded graph/queue observation, shared by all dead components.
	if err := reserve(64*len(instructions), false); err != nil {
		return err
	}
	successors := func(pc int, observe func(int, int)) {
		hasNext := false
		for edge, target := range edges[pc] {
			hasNext = hasNext || target == pc+1
			if _, live := reached[target]; !live {
				observe(edge, target)
			}
		}
		if target := pc + 1; !hasNext && target < len(instructions) {
			if _, live := reached[target]; !live {
				observe(len(edges[pc]), target)
			}
		}
	}
	reverse := make([][]int, len(instructions))
	for pc := range instructions {
		if _, live := reached[pc]; !live {
			successors(pc, func(_ int, target int) { reverse[target] = append(reverse[target], pc) })
		}
	}
	needed := make([]bool, len(instructions))
	for _, target := range targets {
		needed[target] = true
	}
	for cursor := 0; cursor < len(targets); cursor++ {
		for _, previous := range reverse[targets[cursor]] {
			if !needed[previous] {
				needed[previous] = true
				targets = append(targets, previous)
			}
		}
	}
	states := make(map[int]x86ResultState)
	var queue []int
	join := func(pc int, next x86ResultState) {
		if previous, exists := states[pc]; exists {
			merged := previous.intersect(next)
			if reflect.DeepEqual(previous, merged) {
				return
			}
			states[pc] = merged
		} else {
			states[pc] = next.clone()
		}
		queue = append(queue, pc)
	}
	for pc := range instructions {
		if !needed[pc] || pc == 0 {
			continue
		}
		if before, live := reached[pc-1]; live {
			if err := reserve(8*byteState, true); err != nil {
				return err
			}
			post := before.clone()
			if instructions[pc-1].Op != OpRET && !transfer(ordinals[pc-1], instructions[pc-1], &post, owned, resultOffset, arch) {
				return fail("lost its previously verified predecessor")
			}
			join(pc, post)
		}
	}
	for cursor := 0; cursor < len(queue); cursor++ {
		if err := reserve(8*byteState, true); err != nil {
			return err
		}
		pc := queue[cursor]
		state := states[pc].clone()
		ins := instructions[pc]
		if ins.Op != OpRET && !transfer(ordinals[pc], ins, &state, owned, resultOffset, arch) {
			return fail(fmt.Sprintf("has undefined context at instruction %d: %s", pc, ins.Raw))
		}
		successors(pc, func(edge, target int) {
			if needed[target] {
				join(target, x86ResultPredicateEdge(state, ins, edge))
			}
		})
	}
	for _, target := range targets {
		if _, closed := states[target]; !closed {
			return fail("has no source-bound component entry")
		}
	}
	return nil
}
