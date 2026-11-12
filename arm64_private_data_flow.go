package plan9asm

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
)

type arm64PrivateDataCompare struct {
	left, right       arm64PrivateDataValue
	leftReg, rightReg Reg
	valid             bool
}

type arm64PrivateDataState struct {
	regs        map[Reg]arm64PrivateDataValue
	cells       map[int64]arm64PoolInterval
	comparison  arm64PrivateDataCompare
	initialized map[int64]bool // present only for the bounded syscall collector
}

func newARM64PrivateDataState() *arm64PrivateDataState {
	return &arm64PrivateDataState{regs: make(map[Reg]arm64PrivateDataValue), cells: make(map[int64]arm64PoolInterval)}
}

func (state *arm64PrivateDataState) clone() *arm64PrivateDataState {
	copy := newARM64PrivateDataState()
	for reg, value := range state.regs {
		copy.regs[reg] = value
	}
	for offset, value := range state.cells {
		copy.cells[offset] = value
	}
	copy.comparison = state.comparison
	if state.initialized != nil {
		copy.initialized = make(map[int64]bool, len(state.initialized))
		for offset := range state.initialized {
			copy.initialized[offset] = true
		}
	}
	return copy
}

func (state *arm64PrivateDataState) merge(other *arm64PrivateDataState, widen bool) bool {
	old := state.clone()
	registers := make(map[Reg]bool, len(state.regs)+len(other.regs))
	for reg := range state.regs {
		registers[reg] = true
	}
	for reg := range other.regs {
		registers[reg] = true
	}
	for reg := range registers {
		state.regs[reg] = arm64PrivateDataUnion(state.value(reg), other.value(reg), widen)
	}
	for offset, value := range state.cells {
		incoming, present := other.cells[offset]
		if !present {
			delete(state.cells, offset)
			continue
		}
		joined := arm64PrivateDataUnion(arm64PrivateDataNumber(value), arm64PrivateDataNumber(incoming), widen)
		state.cells[offset] = joined.interval
	}
	if state.comparison != other.comparison {
		state.comparison = arm64PrivateDataCompare{}
	}
	for offset := range state.initialized {
		if !other.initialized[offset] {
			delete(state.initialized, offset)
		}
	}
	return !reflect.DeepEqual(old, state)
}

func (state *arm64PrivateDataState) addresses() arm64PrivateFrameAddresses {
	addresses := make(arm64PrivateFrameAddresses)
	for reg, value := range state.regs {
		if value.frame {
			addresses[reg] = arm64PrivateFrameAddress{
				offset: int64(value.interval.low), exact: !value.mixed && value.interval.low == value.interval.high,
			}
		}
	}
	return addresses
}

func (state *arm64PrivateDataState) consume(ins Instr, transport *arm64PrivateFrameTransport, internal bool) bool {
	addresses := state.addresses()
	if transport == nil || !transport.consume(ins, addresses, internal) {
		return false
	}
	if arm64ControlOp(ins) == OpRET {
		return true
	}
	name := strings.TrimSuffix(ins.Args[0].Sym, "(SB)")
	if transport.resolve != nil {
		name = transport.resolve(name)
	}
	sig, present := transport.sigs[name]
	if !present {
		return false
	}
	result := &arm64ControlState{regs: make(map[Reg]arm64ControlValue), memory: make(map[string]arm64ControlValue)}
	arm64ControlWriteCallResults(result, sig, strings.HasSuffix(ins.Args[0].Sym, "<ABIInternal>(SB)"), arm64ControlExternal())
	for reg := range result.regs {
		if isARM64GeneralOrZeroReg(reg) {
			state.assign(reg, arm64PrivateDataUnknown)
		}
	}
	// Typed callees cannot access an unescaped fresh private frame. Explicit
	// ABI0 result transport still overwrites its complete/overlapping cells.
	for key := range result.memory {
		var offset int64
		if len(key) < 4 || key[:3] != "sp:" {
			continue
		}
		var err error
		offset, err = strconv.ParseInt(key[3:], 10, 64)
		if err != nil {
			return false
		}
		for cell := range state.cells {
			if offset < cell+8 && cell < offset+8 {
				delete(state.cells, cell)
			}
		}
	}
	state.comparison = arm64PrivateDataCompare{}
	return true
}

func (state *arm64PrivateDataState) compare(ins Instr) bool {
	if string(ins.Op) != "CMP" && string(ins.Op) != "CMPW" || len(ins.Args) != 2 {
		return false
	}
	width := uint(64)
	if ins.Op == "CMPW" {
		width = 32
	}
	right, ok := state.operand(ins.Args[0], width)
	if !ok {
		return false
	}
	left, ok := state.operand(ins.Args[1], width)
	if !ok || left.frame != right.frame || left.frame && (left.mixed || right.mixed) {
		return false
	}
	state.comparison = arm64PrivateDataCompare{left: left, right: right, valid: true}
	if width == 32 {
		// Signed word comparisons need a signed interval domain. Losing this
		// optional narrowing cannot authorize an otherwise unbounded access.
		state.comparison.valid = false
	}
	if ins.Args[1].Kind == OpReg {
		state.comparison.leftReg = ins.Args[1].Reg
	}
	if ins.Args[0].Kind == OpReg {
		state.comparison.rightReg = ins.Args[0].Reg
	}
	return true
}

func (state *arm64PrivateDataState) branch(op Op, taken bool) (*arm64PrivateDataState, bool) {
	next := state.clone()
	comparison := state.comparison
	if !comparison.valid {
		return next, true
	}
	for _, input := range []struct {
		reg   Reg
		value arm64PrivateDataValue
	}{{comparison.leftReg, comparison.left}, {comparison.rightReg, comparison.right}} {
		if input.reg != "" && state.value(input.reg) != input.value {
			// A whole-CFG may-frame join can weaken a disjunct's register
			// category without changing its old flag snapshot. Optional
			// narrowing must not restore that stale exact address/value.
			return next, true
		}
	}
	// Signed comparisons of unknown integers and addresses do not acquire an
	// unsigned range merely because their current extrema look convenient.
	signed := op == "BGE" || op == "BLT" || op == "BGT" || op == "BLE"
	if signed && (comparison.left.frame || comparison.left.interval.high > math.MaxInt64 || comparison.right.interval.high > math.MaxInt64) {
		return next, true
	}
	relation := ""
	switch op {
	case "BHI", "BGT":
		relation = ">"
	case "BLS", "BLE":
		relation = "<="
	case "BHS", "BCS", "BGE":
		relation = ">="
	case "BLO", "BCC", "BLT":
		relation = "<"
	case "BEQ":
		relation = "=="
	case "BNE":
		relation = "!="
	default:
		return next, true
	}
	if !taken {
		relation = map[string]string{">": "<=", "<=": ">", ">=": "<", "<": ">=", "==": "!=", "!=": "=="}[relation]
	}
	left, right := comparison.left.interval, comparison.right.interval
	if relation == "<" || relation == "<=" {
		comparison.left, comparison.right = comparison.right, comparison.left
		comparison.leftReg, comparison.rightReg = comparison.rightReg, comparison.leftReg
		left, right = right, left
		if relation == "<" {
			relation = ">"
		} else {
			relation = ">="
		}
	}
	switch relation {
	case ">", ">=":
		delta := uint64(0)
		if relation == ">" {
			delta = 1
		}
		if left.high < right.low || delta == 1 && left.high == right.low {
			return nil, false
		}
		if right.low <= math.MaxUint64-delta && left.low < right.low+delta {
			left.low = right.low + delta
		}
		if left.high >= delta && right.high > left.high-delta {
			right.high = left.high - delta
		}
	case "==":
		if left.low < right.low {
			left.low = right.low
		}
		if left.high > right.high {
			left.high = right.high
		}
		if left.low > left.high {
			return nil, false
		}
		right = left
	case "!=":
		if left.low == left.high && right.low == right.high && left.low == right.low {
			return nil, false
		}
	}
	for _, item := range []struct {
		reg   Reg
		value arm64PrivateDataValue
		bound arm64PoolInterval
	}{{comparison.leftReg, comparison.left, left}, {comparison.rightReg, comparison.right, right}} {
		if item.reg == "" || item.reg == ZR || arm64StackReg(item.reg) {
			continue
		}
		value := item.value
		if value.frame && value.stride != 0 {
			residue := value.interval.low % value.stride
			lowDelta := (residue + value.stride - item.bound.low%value.stride) % value.stride
			if lowDelta > item.bound.high-item.bound.low {
				return nil, false
			}
			item.bound.low += lowDelta
			item.bound.high -= (item.bound.high%value.stride + value.stride - residue) % value.stride
		}
		value.interval = item.bound
		next.regs[item.reg] = value
	}
	return next, true
}

// The small disjunctive prefix retains bounded shift/count correlations.
// Afterwards numeric widening guarantees termination; private intervals are
// never widened into an external category. The global work budget fails closed.
func arm64PrivateDataProof(fn Func, transport *arm64PrivateFrameTransport) (map[[2]int]arm64PrivateDataSpan, bool) {
	stores, err := arm64PrivateDataProofDetails(fn, transport)
	return stores, err == nil
}

func arm64PrivateDataProofDetails(fn Func, transport *arm64PrivateFrameTransport) (map[[2]int]arm64PrivateDataSpan, error) {
	if transport == nil || fn.FrameSize < 0 || fn.FrameSize > arm64MaxLocalStackSpan || arm64HasRawFrameCode(fn) {
		return nil, fmt.Errorf("private data proof needs a bounded named source and explicit transport")
	}
	if proof := transport.nanosleep; proof != nil {
		if !reflect.DeepEqual(proof.source, fn) || !reflect.DeepEqual(proof.sig, transport.entry) ||
			proof.identity != nil && !proof.matchesSource(fn, transport.entry, proof.target) {
			return nil, fmt.Errorf("private nanosleep replay has a changed source, declaration or certificate")
		}
	}
	blocks := arm64SplitBlocks(fn)
	indices := make(map[string]int, len(blocks))
	for index, block := range blocks {
		indices[block.name] = index
	}
	stores := make(map[[2]int]arm64PrivateDataSpan)
	type work struct {
		block int
		state *arm64PrivateDataState
	}
	queue := []work{}
	before := make([][]*arm64PrivateDataState, len(blocks))
	compressed := make([]bool, len(blocks))
	propagate := func(index int, state *arm64PrivateDataState) {
		if index < 0 || index >= len(blocks) {
			return
		}
		if compressed[index] {
			if before[index][0].merge(state, true) {
				queue = append(queue, work{index, before[index][0].clone()})
			}
			return
		}
		for _, old := range before[index] {
			if reflect.DeepEqual(old, state) {
				return
			}
		}
		if len(before[index]) < 8 {
			before[index] = append(before[index], state.clone())
			queue = append(queue, work{index, state.clone()})
			return
		}
		joined := before[index][0].clone()
		for _, old := range before[index][1:] {
			joined.merge(old, false)
		}
		joined.merge(state, false)
		before[index], compressed[index] = []*arm64PrivateDataState{joined}, true
		queue = append(queue, work{index, joined.clone()})
	}
	steps := 0
	for seed := range blocks {
		if len(before[seed]) != 0 || len(blocks[seed].instrs) == 0 {
			// An unreferenced empty label has no effect to audit. Inventing
			// an entry there would contaminate a reachable successor with
			// unrelated unknown registers; nonempty dead source still runs.
			continue
		}
		initial := newARM64PrivateDataState()
		if transport.nanosleep != nil && transport.nanosleep.identity == nil {
			initial.initialized = make(map[int64]bool)
		}
		propagate(seed, initial)
		for len(queue) != 0 {
			current := queue[0]
			queue = queue[1:]
			steps++
			if steps > 16384 {
				return nil, fmt.Errorf("private data CFG proof exhausted its convergence budget")
			}
			state := current.state
			// Disjunction preserves numeric correlations, not an exemption for
			// mixed address origins. Every predecessor participates in the
			// may-frame category even before numeric states are compacted.
			origins := before[current.block][0].clone()
			for _, previous := range before[current.block][1:] {
				origins.merge(previous, false)
			}
			for reg, value := range origins.regs {
				if value.frame && value.mixed {
					state.regs[reg] = value
				}
			}
			terminated := false
			for ii, ins := range blocks[current.block].instrs {
				op := arm64ControlOp(ins)
				if op == "SVC" && transport.nanosleep != nil {
					// No native result/flags observation is authorized. This first
					// contract ends in the ordinary source RET in the same block.
					if ii+2 != len(blocks[current.block].instrs) ||
						arm64ControlOp(blocks[current.block].instrs[ii+1]) != OpRET ||
						len(blocks[current.block].instrs[ii+1].Args) != 0 ||
						!transport.nanosleep.consume(state, fn, [2]int{current.block, ii}, ins) {
						return nil, fmt.Errorf("private nanosleep input/terminal contract is unproved at %q", ins.Raw)
					}
					continue
				}
				if op == "ADR" || op == "ADRP" || op == OpWORD || op == "DWORD" || op == arm64RawDataOp || op == "BLR" {
					return nil, fmt.Errorf("private data proof rejects native/raw address effects at %q", ins.Raw)
				}
				if op == "CALL" || op == "BL" || op == OpRET {
					if !state.consume(ins, transport, strings.HasSuffix(fn.Sym, "<ABIInternal>")) {
						return nil, fmt.Errorf("private data proof needs exact nonescaping transport at %q", ins.Raw)
					}
					if op != OpRET {
						propagate(current.block+1, state)
					}
					terminated = true
					break
				}
				if op == "B" || op == "JMP" || arm64IsConditionalBranch(op) {
					if len(ins.Args) == 0 {
						return nil, fmt.Errorf("private data proof rejects an empty branch")
					}
					name, known := arm64BranchTarget(ins.Args[len(ins.Args)-1])
					target, local := indices[name]
					if !known || !local {
						return nil, fmt.Errorf("private data proof needs a source-local branch at %q", ins.Raw)
					}
					branch, possible := state.branch(op, true)
					if possible {
						propagate(target, branch)
					}
					if arm64IsConditionalBranch(op) {
						branch, possible = state.branch(op, false)
						if possible {
							propagate(current.block+1, branch)
						}
					}
					terminated = true
					break
				}
				span, valid := state.transfer(ins, current.block*65536+ii, fn.FrameSize)
				if !valid {
					inputs := make(map[Reg]arm64PrivateDataValue)
					for _, operand := range ins.Args {
						for _, reg := range []Reg{operand.Reg, operand.Mem.Base, operand.Mem.Index} {
							if reg != "" {
								inputs[reg] = state.value(reg)
							}
						}
					}
					return nil, fmt.Errorf("private data extent/effects are unproved at %q (inputs %v)", ins.Raw, inputs)
				}
				if span != nil {
					key := [2]int{current.block, ii}
					if old, present := stores[key]; present {
						if old.low < span.low {
							span.low = old.low
						}
						if old.end > span.end {
							span.end = old.end
						}
					}
					stores[key] = *span
				}
			}
			if !terminated {
				propagate(current.block+1, state)
			}
		}
	}
	return stores, nil
}
