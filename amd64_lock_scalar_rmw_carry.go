package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

// This domain proves only the source of the CF value consumed by a named
// locked ADC/SBB. It grants no register, memory, frame or caller permission.
// GP byte facts prevent a default-zero alloca or an empty flags stack from
// becoming an incoming carry. The ordinary consumers still check operands.
type x86LockCarryState struct {
	carry        bool
	gp           [16]uint8
	stack        []x86LockCarryCell
	stackUnbound bool
}

type x86LockCarryCell struct {
	bits       int
	valueKnown bool
	carryKnown bool
}

func (state x86LockCarryState) clone() x86LockCarryState {
	state.stack = append([]x86LockCarryCell(nil), state.stack...)
	return state
}

func (state x86LockCarryState) intersect(other x86LockCarryState) x86LockCarryState {
	state = state.clone()
	state.carry = state.carry && other.carry
	state.stackUnbound = state.stackUnbound || other.stackUnbound
	for index := range state.gp {
		state.gp[index] &= other.gp[index]
	}
	if len(state.stack) != len(other.stack) {
		state.stack = nil
		state.stackUnbound = true
	} else {
		for index := range state.stack {
			if state.stack[index].bits != other.stack[index].bits {
				state.stack = nil
				state.stackUnbound = true
				break
			}
			state.stack[index].valueKnown = state.stack[index].valueKnown && other.stack[index].valueKnown
			state.stack[index].carryKnown = state.stack[index].carryKnown && other.stack[index].carryKnown
		}
	}
	if state.stackUnbound {
		state.stack = nil
	}
	return state
}

func (c *amd64Ctx) lockCarryRead(operand Operand, width int64, state x86LockCarryState) bool {
	if operand.Kind == OpFP {
		for _, slot := range c.sig.Frame.Params {
			bytes := x86FrameScalarBytes(slot.Type, c.goarch)
			if bytes > 0 && operand.FPOffset >= slot.Offset &&
				operand.FPOffset-slot.Offset <= bytes-width && width > 0 {
				return true // Actual typed argument bits, not pointee/backing facts.
			}
		}
		return false
	}
	if operand.Kind == OpMem || operand.Kind == OpSym {
		// A native instruction reads actual memory bits; this does not prove
		// its address or authorize the read. The final memory guards do that.
		return operand.Kind == OpSym && !strings.HasPrefix(operand.Sym, "$") ||
			operand.Kind == OpMem && operand.Mem.Sym == "" && operand.Mem.Base != SP && operand.Mem.Base != BP
	}
	return x86ResultRead(operand, width, &x86ResultState{gp: state.gp}, nil, c.goarch)
}

func (c *amd64Ctx) lockCarryWrite(operand Operand, width int64, known bool, state *x86LockCarryState) {
	if operand.Kind == OpMem || operand.Kind == OpSym || operand.Kind == OpFP {
		// No numerical/address fact here establishes nonaliasing with an
		// outstanding source PUSH. Even an independently allowed native store
		// cannot preserve a stack cell without a separate exact alias proof.
		state.stack = nil
		return
	}
	if operand.Kind != OpReg {
		return
	}
	if base, valid := x86CallerGP(operand.Reg); valid && base == SP {
		// Explicit SP replacement/adjustment is not an ordinary balanced
		// PUSH/POP. This domain cannot recover its original physical identity,
		// even if a later instruction defines the pushed GP value again.
		state.stack = nil
		state.stackUnbound = true
	}
	index, mask, valid := x86ResultGP(operand.Reg, width, c.goarch)
	if !valid {
		state.gp = [16]uint8{}
		return
	}
	state.gp[index] &^= mask
	if known {
		state.gp[index] |= mask
	}
	if width == 4 || width == 8 {
		state.gp[index] = 0
		if known {
			state.gp[index] = 0xff
		}
	}
}

func (c *amd64Ctx) lockCarryTransfer(ins Instr, state x86LockCarryState) x86LockCarryState {
	ins = x86SourceMoveInstruction(ins, c.goarch) // Local numerical dispatch, never source/certificate identity.
	op := Op(strings.ToUpper(string(ins.Op)))
	if op == OpTEXT || op == OpRET || op == "LOCK" && len(ins.Args) == 0 ||
		op == OpJMP || isAMD64ConditionalBranch(op) || op == "LOOP" {
		return state
	}
	if (op == "CLC" || op == "STC" || op == "CMC") && len(ins.Args) == 0 {
		state.carry = op != "CMC" || state.carry
		return state
	}
	if width := x86RawReturnScalarMoveBytes(op); width != 0 &&
		op == ins.Op && len(ins.Args) == 2 && !(width == 8 && c.goarch == "386") {
		known := c.lockCarryRead(ins.Args[0], width, state)
		c.lockCarryWrite(ins.Args[1], width, known, &state)
		return state
	}
	if spec, found := amd64StackWidthSpecs[op]; found {
		validMode := spec.bits == 16 || spec.bits == 32 && c.goarch == "386" || spec.bits == 64 && c.goarch == "amd64"
		validCount := len(ins.Args) == 0
		if spec.mode == amd64StackPushValue || spec.mode == amd64StackPopValue {
			validCount = len(ins.Args) == 1
		}
		if !validMode || !validCount {
			return x86LockCarryState{stackUnbound: true}
		}
		if spec.mode == amd64StackPushValue || spec.mode == amd64StackPushFlags {
			if len(state.stack) >= 64 {
				return x86LockCarryState{stackUnbound: true}
			}
			cell := x86LockCarryCell{bits: spec.bits, carryKnown: state.carry}
			if spec.mode == amd64StackPushValue {
				cell.valueKnown = c.lockCarryRead(ins.Args[0], int64(spec.bits/8), state)
				cell.carryKnown = cell.valueKnown
			}
			if state.stackUnbound {
				cell.valueKnown, cell.carryKnown = false, false
			}
			// PUSHF captures a flags word, but this domain proves only its CF.
			// POP into GP must not promote unknown OF or other bits to numeric
			// byte facts. A direct POPF may independently consume known CF.
			state.stack = append(state.stack, cell)
			return state
		}
		cell := x86LockCarryCell{}
		if len(state.stack) != 0 {
			cell = state.stack[len(state.stack)-1]
			state.stack = state.stack[:len(state.stack)-1]
			if cell.bits != spec.bits {
				cell = x86LockCarryCell{}
			}
		}
		if spec.mode == amd64StackPopFlags {
			state.carry = cell.carryKnown
		} else {
			c.lockCarryWrite(ins.Args[0], int64(spec.bits/8), cell.valueKnown, &state)
		}
		return state
	}
	if effect, recognized, err := x86TypedInstructionByteEffect(op, ins, c.goarch); recognized {
		if err != nil {
			return x86LockCarryState{stackUnbound: true}
		}
		known := effect.flagsRead&x86ByteFlagCF == 0 || state.carry
		for _, operand := range effect.operands {
			if operand.read {
				known = known && c.lockCarryRead(operand.operand, operand.width, state)
			}
		}
		for _, operand := range effect.operands {
			if operand.write {
				c.lockCarryWrite(operand.operand, operand.width, known, &state)
			}
		}
		if effect.flagsKilled&x86ByteFlagCF != 0 {
			state.carry = false
		}
		if effect.flagsDefined&x86ByteFlagCF != 0 {
			state.carry = known
		}
		return state
	}
	if (op == "CMPB" || op == "CMPW" || op == "CMPL" || op == "CMPQ" ||
		op == "TESTB" || op == "TESTW" || op == "TESTL" || op == "TESTQ") && len(ins.Args) == 2 {
		bits := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[string(op)[len(op)-1]]
		valid := validateAMD64ScalarAddSubOperands(c.goarch, string(op), bits, ins.Args[0], ins.Args[1], ins) == nil
		if strings.HasPrefix(string(op), "CMP") {
			valid = valid || validateAMD64ScalarAddSubOperands(c.goarch, string(op), bits, ins.Args[1], ins.Args[0], ins) == nil
		}
		if !(bits == 64 && c.goarch == "386") && valid {
			state.carry = c.lockCarryRead(ins.Args[0], int64(bits/8), state) && c.lockCarryRead(ins.Args[1], int64(bits/8), state)
			return state
		}
	}
	if op == "STMXCSR" && len(ins.Args) == 1 && isAMD64MemoryOperand(ins.Args[0]) {
		c.lockCarryWrite(ins.Args[0], 4, false, &state)
		return state
	}
	if op == "NOP" && len(ins.Args) == 0 {
		return state
	}
	// Calls, native/raw effects and unregistered forms have no incoming flags
	// preservation contract. A later explicit definition may start a new fact.
	return x86LockCarryState{stackUnbound: true}
}

func (c *amd64Ctx) verifyNamedLockCarry() error {
	var required [][2]int
	for block, body := range c.blocks {
		for index := 1; index < len(body.instrs); index++ {
			previous, ins := body.instrs[index-1], body.instrs[index]
			if previous.Op != "LOCK" || len(previous.Args) != 0 {
				continue
			}
			form, known, err := x86LockScalarRMWProperties(ins.Op, ins, c.goarch)
			if known && err == nil && (form.spec.stem == "ADC" || form.spec.stem == "SBB") {
				required = append(required, [2]int{block, index})
			}
		}
	}
	if len(required) == 0 {
		return nil // Unrelated translations retain their existing contracts.
	}
	fail := func(reason string) error {
		return fmt.Errorf("%w: named LOCK incoming carry is not source-defined: %s", ErrProbeNeedsContext, reason)
	}
	if len(c.blocks) > 4096 {
		return fail("source CFG exceeds the bounded proof domain")
	}
	steps := 0
	states := map[int]x86LockCarryState{0: {}}
	queue := []int{0}
	inputs := make(map[[2]int]bool)
	for visits := 0; len(queue) != 0; visits++ {
		if visits >= 32768 {
			return fail("source CFG fixed-point budget exhausted")
		}
		block := queue[0]
		queue = queue[1:]
		state := states[block].clone()
		for index, ins := range c.blocks[block].instrs {
			steps++
			if steps > 262144 {
				return fail("combined source instruction work budget exhausted")
			}
			inputs[[2]int{block, index}] = state.carry
			state = c.lockCarryTransfer(ins, state)
		}
		successors, valid := c.lockCarrySuccessors(block)
		if !valid {
			return fail("indirect, external or unresolved source control flow")
		}
		for _, target := range successors {
			if previous, found := states[target]; found {
				stateAtTarget := previous.intersect(state)
				if reflect.DeepEqual(previous, stateAtTarget) {
					continue
				}
				states[target] = stateAtTarget
			} else {
				states[target] = state.clone()
			}
			queue = append(queue, target)
		}
	}
	for _, location := range required {
		if !inputs[location] {
			return fail("a complete ADC/SBB has an unknown predecessor CF value")
		}
	}
	return nil
}

func (c *amd64Ctx) lockCarrySuccessors(block int) ([]int, bool) {
	return c.sourceBlockSuccessors(block, nil)
}

// This decodes only ordinary source control flow. It supplies no LOCK, carry,
// memory or entry authority. A complete label index avoids repeated scans for
// consumers whose analysis must remain linear in source nodes and edges.
func (c *amd64Ctx) sourceBlockSuccessors(block int, labels map[string]int) ([]int, bool) {
	body := c.blocks[block].instrs
	if len(body) == 0 {
		if block+1 < len(c.blocks) {
			return []int{block + 1}, true
		}
		return nil, true
	}
	ins := body[len(body)-1]
	op := Op(strings.ToUpper(string(ins.Op)))
	if op == OpRET {
		return nil, len(ins.Args) == 0
	}
	if op != OpJMP && op != "LOOP" && !isAMD64ConditionalBranch(op) {
		if block+1 < len(c.blocks) {
			return []int{block + 1}, true
		}
		return nil, false
	}
	args := ins.Args
	if op != OpJMP && op != "LOOP" && !isAMD64CounterZeroBranch(op) &&
		len(args) == 2 && args[0].Kind == OpImm && (args[0].Imm == 0 || args[0].Imm == 1) {
		args = args[1:]
	}
	if len(args) != 1 {
		return nil, false
	}
	target, found := -1, false
	if args[0].Kind == OpMem && args[0].Mem.Base == PC && args[0].Mem.OffRaw == "" {
		base := int64(c.blockBase[block] + len(body) - 1)
		if args[0].Mem.Off > 1<<63-1-base {
			return nil, false
		}
		pc := base + args[0].Mem.Off
		if pc >= 0 && pc <= int64(^uint(0)>>1) {
			target, found = c.blockByIdx[int(pc)]
		}
	} else {
		label := ""
		switch args[0].Kind {
		case OpLabel, OpSym:
			label = args[0].Sym
		case OpIdent:
			label = args[0].Ident
		case OpReg:
			label = string(args[0].Reg)
		}
		if labels != nil {
			target, found = labels[label]
		} else {
			for index, candidate := range c.blocks {
				if candidate.name == label {
					target, found = index, true
					break
				}
			}
		}
	}
	if !found || target < 0 || target >= len(c.blocks) {
		return nil, false
	}
	if op == OpJMP {
		return []int{target}, true
	}
	return []int{target, block + 1}, block+1 < len(c.blocks)
}
