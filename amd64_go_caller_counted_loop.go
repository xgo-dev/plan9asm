package plan9asm

import (
	"fmt"
	"math"
	"reflect"
	"strings"
)

// This private plan partitions numerical low bits, not allocation bounds. It
// never supplies a pointer, initial GP value, public option or serialized proof.
type x86CallerCountedPlan struct {
	edges                [][]int
	loops                []x86CallerCountedLoop
	headers, latches     map[int]int
	original, normalized [32]byte
}

type x86CallerCountedLoop struct {
	body                  map[int]bool
	header, latch, update int
	counter, bound        Reg
}

func x86CallerCountedEdges(fn Func, instructions []int, labels map[string]int) ([][]int, bool) {
	if len(instructions) == 0 || len(instructions) > 8192 {
		return nil, false
	}
	edges := make([][]int, len(instructions))
	for pc, index := range instructions {
		ins := fn.Instrs[index]
		op := Op(normalizeInstructionOpcode(ins.Op))
		if op == OpRET {
			continue
		}
		edges[pc] = []int{pc + 1}
		if op == OpJMP || isAMD64ConditionalBranch(op) {
			if len(ins.Args) != 1 {
				return nil, false
			}
			arg := ins.Args[0]
			label := arg.Sym
			if arg.Kind == OpIdent {
				label = arg.Ident
			}
			target, valid := labels[label]
			if arg.Kind == OpMem && arg.Mem.Base == PC && arg.Mem.Index == "" && arg.Mem.Sym == "" &&
				arg.Mem.Off >= -int64(len(instructions)) && arg.Mem.Off <= int64(len(instructions)) {
				target, valid = pc+int(arg.Mem.Off), true
			} else if arg.Kind != OpLabel && arg.Kind != OpIdent {
				return nil, false
			}
			if !valid {
				return nil, false
			}
			if op == OpJMP {
				edges[pc] = []int{target}
			} else {
				edges[pc] = append(edges[pc], target)
			}
		}
		for _, next := range edges[pc] {
			if next < 0 || next >= len(instructions) {
				return nil, false
			}
		}
	}
	return edges, true
}

// Each SCC must retain the original one-loop rule: one entry edge, one exact
// adjacent comparison/latch, an immutable bound and one unavoidable +1 update.
// Its remaining edges must be a DAG, not an inferred cyclic merge invariant.
func deriveX86CallerCountedLoop(fn Func, instructions []int, edges [][]int, reachable []bool,
	body map[int]bool, header, latchPC int) *x86CallerCountedLoop {
	plan := &x86CallerCountedLoop{body: body, header: header, latch: latchPC, update: -1}
	if plan.latch == 0 || !plan.body[plan.latch-1] {
		return nil
	}
	latch := fn.Instrs[instructions[plan.latch]]
	compare := fn.Instrs[instructions[plan.latch-1]]
	if latch.Op != "JNE" || len(edges[plan.latch]) != 2 || edges[plan.latch][1] != plan.header ||
		(compare.Op != "CMPL" && compare.Op != "CMPQ") || len(compare.Args) != 2 ||
		compare.Args[0].Kind != OpReg || compare.Args[1].Kind != OpReg {
		return nil
	}
	left, leftOK := x86CallerGP(compare.Args[0].Reg)
	right, rightOK := x86CallerGP(compare.Args[1].Reg)
	if !leftOK || !rightOK || left == right || left != compare.Args[0].Reg || right != compare.Args[1].Reg {
		return nil
	}
	entries, updates := 0, 0
	for pc, nexts := range edges {
		if !reachable[pc] {
			continue
		}
		for _, next := range nexts {
			if next == plan.latch && pc != plan.latch-1 {
				return nil // The latch must consume this exact adjacent comparison.
			}
			if !plan.body[pc] && plan.body[next] {
				if next != plan.header {
					return nil
				}
				entries++
			}
			if plan.body[pc] && !plan.body[next] && pc != plan.latch {
				return nil
			}
		}
		if !plan.body[pc] {
			continue
		}
		ins := fn.Instrs[instructions[pc]]
		if (ins.Op == "ADDL" || ins.Op == "ADDQ") && len(ins.Args) == 2 &&
			ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" && ins.Args[0].Imm == 1 &&
			ins.Args[1].Kind == OpReg && (ins.Args[1].Reg == left || ins.Args[1].Reg == right) {
			updates++
			plan.update, plan.counter = pc, ins.Args[1].Reg
		}
	}
	if entries != 1 || updates != 1 {
		return nil
	}
	plan.bound = left
	if plan.counter == left {
		plan.bound = right
	}
	// Every body path must pass the one update; both live values stay immutable
	// otherwise. Conservatively reject even an unmodeled read of these registers.
	for pc := range plan.body {
		ins := fn.Instrs[instructions[pc]]
		if pc == plan.update || ins.Op == "CMPL" || ins.Op == "CMPQ" || isAMD64ConditionalBranch(ins.Op) || ins.Op == OpJMP {
			continue
		}
		for _, arg := range ins.Args {
			if arg.Kind == OpReg {
				root, _ := x86CallerGP(arg.Reg)
				if root == plan.counter || root == plan.bound {
					return nil
				}
			}
		}
	}
	seen := map[int]bool{}
	work := []int{plan.header}
	for len(work) != 0 {
		pc := work[0]
		work = work[1:]
		if pc == plan.update || seen[pc] {
			continue
		}
		if pc == plan.latch {
			return nil
		}
		seen[pc] = true
		work = append(work, edges[pc]...)
	}
	return plan
}

type x86CallerCountedNumber struct {
	source, version int
	mask, value     uint64
	known           bool
}

type x86CallerCountedFlags struct {
	pc           int
	op           Op
	regs         [2]Reg
	versions     [2]int
	equal, known bool
}

type x86CallerCountedNumbers struct {
	regs             map[Reg]x86CallerCountedNumber
	flags            x86CallerCountedFlags
	source, sequence int
}

func (facts x86CallerCountedNumbers) clone() x86CallerCountedNumbers {
	copy := facts
	copy.regs = make(map[Reg]x86CallerCountedNumber, len(facts.regs))
	for reg, value := range facts.regs {
		copy.regs[reg] = value
	}
	return copy
}

// Relational evidence is independent of numericFlags. Unknown upper bits stay
// unknown; only a real readonly local-length load supplies the partition source.
func (facts *x86CallerCountedNumbers) step(pc, residue int, ins Instr, before x86SourceStackState, proof *x86GoCallerRegionProof) {
	op := Op(normalizeInstructionOpcode(x86SourceMoveInstruction(ins, "amd64").Op))
	if effect, known, err := x86TypedCounterControlByteEffect(ins.Op, ins, "amd64"); known {
		if err != nil {
			for register := range facts.regs {
				delete(facts.regs, register)
			}
			facts.flags = x86CallerCountedFlags{}
			facts.sequence++
			return
		}
		for _, operand := range effect.operands {
			if operand.write && operand.operand.Kind == OpReg {
				facts.sequence++
				if register, valid := x86CallerGP(operand.operand.Reg); valid {
					delete(facts.regs, register)
				}
			}
		}
		return // Preserve actual FLAGS, but never retain a decremented exact value/version.
	}
	if op == OpTEXT || op == OpRET || op == OpJMP || isAMD64ConditionalBranch(op) {
		return
	}
	facts.sequence++
	if (op == "CMPL" || op == "CMPQ" || op == "TESTB" || op == "TESTW" || op == "TESTL" || op == "TESTQ") && len(ins.Args) == 2 {
		facts.flags = x86CallerCountedFlags{pc: pc, op: op}
		values := [2]x86CallerCountedNumber{}
		for index, arg := range ins.Args {
			if arg.Kind == OpImm && arg.ImmRaw == "" {
				values[index] = x86CallerCountedNumber{source: -1, value: uint64(arg.Imm), known: true}
			} else if arg.Kind == OpReg {
				root, valid := x86CallerGP(arg.Reg)
				if !valid || arg.Reg != root {
					return
				}
				var present bool
				values[index], present = facts.regs[root]
				if !present {
					return
				}
				facts.flags.regs[index], facts.flags.versions[index] = root, values[index].version
			} else {
				return
			}
		}
		if strings.HasPrefix(string(op), "TEST") {
			for index := range values {
				other := values[1-index]
				if !values[index].known && values[index].source == facts.source && facts.source >= 0 && other.known && other.value <= 3 {
					values[index].value, values[index].known = uint64(residue), true
				}
			}
			mask := uint64(math.MaxUint64)
			switch op {
			case "TESTB":
				mask = math.MaxUint8
			case "TESTW":
				mask = math.MaxUint16
			case "TESTL":
				mask = math.MaxUint32
			}
			facts.flags.equal = values[0].value&values[1].value&mask == 0
		} else {
			if op == "CMPL" {
				values[0].value, values[1].value = uint64(uint32(values[0].value)), uint64(uint32(values[1].value))
			}
			facts.flags.equal = values[0].value == values[1].value
		}
		facts.flags.known = values[0].known && values[1].known
		return
	}
	move := op == "MOVL" || op == "MOVQ"
	_, conditionalMove, conditionalMoveError := x86ConditionalMoveProperties(op, ins, "amd64")
	if !move && !(conditionalMove && conditionalMoveError == nil) && x86LEAWidth(op, "amd64") == 0 && op != "PUSHQ" && op != "POPQ" &&
		!strings.HasPrefix(string(op), "MOV") && !strings.HasPrefix(string(op), "VMOV") {
		facts.flags = x86CallerCountedFlags{}
	}
	if len(ins.Args) == 0 || ins.Args[len(ins.Args)-1].Kind != OpReg {
		return
	}
	arg := ins.Args[len(ins.Args)-1]
	reg, valid := x86CallerGP(arg.Reg)
	if !valid {
		return
	}
	old, oldPresent := facts.regs[reg]
	delete(facts.regs, reg)
	if arg.Reg != reg || len(ins.Args) != 2 {
		return
	}
	source := ins.Args[0]
	value := x86CallerCountedNumber{source: -1, version: facts.sequence}
	if move {
		switch source.Kind {
		case OpImm:
			if source.ImmRaw != "" || source.ImmIsFloat {
				return
			}
			value.value, value.known = uint64(source.Imm), true
		case OpReg:
			root, ok := x86CallerGP(source.Reg)
			if !ok || root != source.Reg {
				return
			}
			if root == reg {
				value = old
			} else {
				var present bool
				value, present = facts.regs[root]
				if !present {
					return
				}
			}
			if !oldPresent && root == reg {
				return
			}
		case OpMem:
			pointer, present := before.callers[source.Mem.Base]
			if op != "MOVQ" || !present || pointer.offset != 0 || pointer.span != 0 ||
				pointer.argument < 0 || pointer.argument >= len(proof.arguments) || proof.arguments[pointer.argument].kind != x86CallerLocalLength ||
				source.Mem.Off != 0 || source.Mem.Index != "" || source.Mem.Sym != "" || source.Mem.Segment != "" {
				return
			}
			value.source = pc
			if facts.source < 0 {
				facts.source = pc
			}
		default:
			return
		}
		if op == "MOVL" && value.known {
			value.value = uint64(uint32(value.value))
		}
	} else if (op == "XORL" || op == "XORQ") && source.Kind == OpReg && source.Reg == reg {
		value.value, value.known = 0, true
	} else if (op == "ANDL" || op == "ANDQ") && oldPresent && source.Kind == OpImm && source.ImmRaw == "" {
		value = old
		if old.known {
			value.value &= uint64(source.Imm)
		} else if old.source == facts.source && facts.source >= 0 && source.Imm > 0 && source.Imm <= 3 {
			value.mask, value.value, value.known = uint64(source.Imm), uint64(residue)&uint64(source.Imm), true
		} else {
			return
		}
	} else if (op == "ADDL" || op == "ADDQ") && oldPresent && old.known && source.Kind == OpImm && source.ImmRaw == "" {
		limit := uint64(math.MaxUint64)
		if op == "ADDL" {
			limit = math.MaxUint32
		}
		if source.Imm < 0 || old.value > limit || uint64(source.Imm) > limit-old.value {
			return
		}
		value.value, value.known = old.value+uint64(source.Imm), true
	} else {
		return
	}
	if (op == "ANDL" || op == "ADDL") && value.known {
		value.value = uint64(uint32(value.value))
	}
	value.version = facts.sequence
	facts.regs[reg] = value
}

type x86CallerCountedVisit struct {
	pc, residue, iteration, loop int
	state                        x86SourceStackState
	numbers                      x86CallerCountedNumbers
}

type x86CallerCountedWork struct {
	x86CallerCountedVisit
	bound x86CallerCountedNumber
	entry x86SourceStackState
}

func x86CallerCountedOrigins(entry, current x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if entry.sp != current.sp || entry.bp != current.bp || entry.gOriginal != current.gOriginal ||
		!reflect.DeepEqual(entry.cells, current.cells) || len(entry.callers) != len(current.callers) {
		return false
	}
	for reg, pointer := range entry.callers {
		other, present := current.callers[reg]
		if !present || pointer.argument != other.argument || pointer.argument < 0 || pointer.argument >= len(proof.arguments) {
			return false
		}
		if _, valid := x86CallerPointerEnd(other); !valid {
			return false
		}
		if proof.arguments[pointer.argument].kind != x86CallerSliceInput && pointer != other {
			return false
		}
	}
	return true
}

type x86CallerCountedTransfer func(int, *Instr, *x86SourceStackState) (bool, string)

// Each feasible path keeps a fresh state, so no predecessor can supply another
// path's permission. The finite visit cap fails; it never widens a loop state.
func replayX86CallerCountedPlan(plan *x86CallerCountedPlan, fn *Func, instructions []int, initial x86SourceStackState,
	proof *x86GoCallerRegionProof, transfer x86CallerCountedTransfer) ([]x86CallerCountedVisit, string) {
	var visits []x86CallerCountedVisit
	returned := 0
	for residue := 0; residue <= 3; residue++ {
		work := []x86CallerCountedWork{{x86CallerCountedVisit: x86CallerCountedVisit{
			residue: residue, iteration: -1, loop: -1, state: x86CloneCallerState(initial),
			numbers: x86CallerCountedNumbers{regs: map[Reg]x86CallerCountedNumber{}, source: -1},
		}}}
		for len(work) != 0 {
			if len(visits) >= 8192 {
				return nil, "counted-loop finite path budget exhausted"
			}
			item := work[0]
			work = work[1:]
			pc := item.pc
			if loopIndex, header := plan.headers[pc]; header {
				loop := plan.loops[loopIndex]
				bound, bOK := item.numbers.regs[loop.bound]
				counter, cOK := item.numbers.regs[loop.counter]
				if item.loop != -1 && item.loop != loopIndex {
					return nil, "counted-loop entry crosses an active SCC"
				}
				if item.loop == -1 {
					item.loop = loopIndex
					item.iteration, item.bound = 0, bound
					item.entry = x86CloneCallerState(item.state)
				}
				if !bOK || !cOK || !bound.known || !counter.known || bound.value == 0 || bound.value > 3 ||
					bound.source != item.numbers.source || bound.source < 0 || bound.mask == 0 || bound.mask > 3 ||
					!reflect.DeepEqual(bound, item.bound) || counter.value != uint64(item.iteration) || item.iteration >= 3 {
					return nil, "counted-loop entry lacks immutable bounded value and zero-based counter"
				}
			}
			visits = append(visits, item.x86CallerCountedVisit)
			state, numbers := x86CloneCallerState(item.state), item.numbers.clone()
			ins := &fn.Instrs[instructions[pc]]
			ins.x86CallerMemory, ins.x86SourceStackFP = nil, nil
			isReturn, reason := transfer(pc, ins, &state)
			if reason != "" {
				return nil, fmt.Sprintf("normalized instruction %d: %s", instructions[pc], reason)
			}
			if isReturn {
				if item.loop != -1 {
					return nil, "counted-loop return bypasses its exact latch"
				}
				returned++
				continue
			}
			numbers.step(pc, residue, *ins, item.state, proof)
			nexts := plan.edges[pc]
			if loopIndex, latch := plan.latches[pc]; latch {
				loop := plan.loops[loopIndex]
				flags, counter, bound := numbers.flags, numbers.regs[loop.counter], numbers.regs[loop.bound]
				if item.loop != loopIndex {
					return nil, "counted-loop latch lacks its original SCC entry"
				}
				if !flags.known || flags.pc != pc-1 || !counter.known || counter.value != uint64(item.iteration+1) ||
					!reflect.DeepEqual(bound, item.bound) || !x86CallerCountedOrigins(item.entry, state, proof) {
					return nil, "counted-loop latch lacks exact counter, bound and comparison versions"
				}
				for index, reg := range flags.regs {
					if (reg != loop.counter && reg != loop.bound) || flags.versions[index] != numbers.regs[reg].version {
						return nil, "counted-loop comparison observes stale operand versions"
					}
				}
			}
			if (ins.Op == "JE" || ins.Op == "JNE") && numbers.flags.known {
				taken := numbers.flags.equal == (ins.Op == "JE")
				if taken {
					nexts = nexts[1:]
				} else {
					nexts = nexts[:1]
				}
			}
			for _, next := range nexts {
				iteration, loopIndex := item.iteration, item.loop
				bound, entry := item.bound, item.entry
				if item.loop >= 0 {
					loop := plan.loops[item.loop]
					if pc == loop.latch && next == loop.header {
						iteration++
					} else if !loop.body[next] {
						if pc != loop.latch {
							return nil, "counted-loop exit bypasses its exact latch"
						}
						// Clear only this loop's control witness. All source origins,
						// initialized bytes, numerical versions and flags survive.
						iteration, loopIndex = -1, -1
						bound, entry = x86CallerCountedNumber{}, x86SourceStackState{}
					}
				}
				work = append(work, x86CallerCountedWork{x86CallerCountedVisit: x86CallerCountedVisit{
					pc: next, residue: residue, iteration: iteration, loop: loopIndex,
					state: x86CloneCallerState(state), numbers: numbers.clone(),
				}, bound: bound, entry: x86CloneCallerState(entry)})
			}
		}
	}
	if returned == 0 {
		return nil, "counted-loop replay has no original source return"
	}
	return visits, ""
}
