package plan9asm

import (
	"fmt"
	"strings"
)

type armKernelState uint32

const (
	armKernelN armKernelState = 1 << (17 + iota)
	armKernelZ
	armKernelC
	armKernelV
	armKernelFlags = armKernelN | armKernelZ | armKernelC | armKernelV
	armKernelTop   = (1 << 21) - 1
)

func armKernelRegBit(reg Reg) armKernelState {
	if reg == SP {
		return 1 << 16
	}
	for i := 0; i < 15; i++ {
		if reg == Reg(fmt.Sprintf("R%d", i)) {
			return 1 << i
		}
	}
	return 0 // R15 is not an ordinary source-state value.
}

func (s armKernelState) has(mask armKernelState) bool { return mask != 0 && s&mask == mask }

func armKernelConditionBits(condition string) armKernelState {
	switch condition {
	case "", "AL":
		return 0
	case "EQ", "NE":
		return armKernelZ
	case "CS", "HS", "CC", "LO":
		return armKernelC
	case "MI", "PL":
		return armKernelN
	case "VS", "VC":
		return armKernelV
	case "HI", "LS":
		return armKernelC | armKernelZ
	case "GE", "LT":
		return armKernelN | armKernelV
	case "GT", "LE":
		return armKernelN | armKernelV | armKernelZ
	}
	return armKernelFlags
}

// Native inputs cannot come from zero-filled generic register slots. This is
// a must-definition analysis: entry comes only from explicit typed registers,
// and every reachable predecessor must prove an input at a join. Loops use a
// descending fixed point; unreachable blocks do not manufacture a proof.
func proveARMKernelInputs(fn Func, sig FuncSig) error {
	blocks := armSplitBlocks(fn)
	if len(blocks) == 0 {
		return nil
	}
	hasCall := false
	for _, ins := range fn.Instrs {
		hasCall = hasCall || ins.armKernelCall != nil
	}
	if !hasCall {
		return nil
	}
	entry := armKernelState(0)
	for i, reg := range sig.ArgRegs {
		if i < len(sig.Args) {
			entry |= armKernelRegBit(reg)
		}
	}
	preds, reachable := armSourcePredecessors(blocks)
	in, out := make([]armKernelState, len(blocks)), make([]armKernelState, len(blocks))
	for i := range blocks {
		if reachable[i] {
			in[i], out[i] = armKernelTop, armKernelTop
		}
	}
	for changed := true; changed; {
		changed = false
		for i, block := range blocks {
			if !reachable[i] {
				continue
			}
			state := armKernelState(armKernelTop)
			if i == 0 {
				state = entry
			}
			for _, pred := range preds[i] {
				state &= out[pred]
			}
			in[i] = state
			for _, ins := range block.instrs {
				state, _ = armKernelTransfer(fn.Sym, sig, state, ins, false)
			}
			if out[i] != state {
				out[i], changed = state, true
			}
		}
	}
	for i, block := range blocks {
		state := in[i]
		for _, ins := range block.instrs {
			var err error
			state, err = armKernelTransfer(fn.Sym, sig, state, ins, true)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func armKernelTransfer(name string, sig FuncSig, state armKernelState, ins Instr, check bool) (armKernelState, error) {
	op, condition, post, setFlags := armDecodeOp(string(ins.Op))
	status, statusMove, statusError := parseARMStatusMove(ins)
	if statusMove {
		if statusError != nil {
			return state, statusError
		}
		condition = status.condition
	}
	if len(op) > 1 && op[0] == 'B' && armCondCodes[op[1:]] {
		condition = op[1:]
	}
	bits := armKernelConditionBits(condition)
	predicate := bits == 0 || state.has(bits)
	if check && !predicate {
		return state, fmt.Errorf("%w: ARM native continuation in %q has unproved condition %s: %s", ErrProbeNeedsContext, name, condition, ins.Raw)
	}
	assign := func(mask armKernelState, known bool) {
		if bits != 0 {
			known = known && predicate && state.has(mask)
		}
		state &^= mask
		if known {
			state |= mask
		}
	}
	if statusMove {
		if status.write {
			assign(armKernelFlags, armKernelValueDefined(status.source, sig, state))
		} else {
			assign(armKernelRegBit(status.dest), state.has(armKernelFlags))
		}
		return state, nil
	}
	if call := ins.armKernelCall; call != nil {
		for _, reg := range call.spec.inputs {
			if check && !state.has(armKernelRegBit(reg)) {
				return state, fmt.Errorf("%w: ARM kernel call in %q requires a typed/source-defined %s input: %s", ErrProbeNeedsContext, name, reg, ins.Raw)
			}
		}
		if call.spec.entry == armKernelCompareExchange32 {
			assign(armKernelRegBit("R0"), true)
			// R3/IP and non-C flags are explicitly clobbered by this ABI.
			state &^= armKernelRegBit("R3") | armKernelRegBit("R12") | armKernelN | armKernelZ | armKernelV
			assign(armKernelC, true)
		}
		return state, nil
	}
	if _, move := armIntegerMemorySpecs[op]; move && len(ins.Args) == 2 {
		if ins.Args[1].Kind == OpIdent && strings.EqualFold(ins.Args[1].Ident, "CPSR") {
			assign(armKernelFlags, armKernelValueDefined(ins.Args[0], sig, state))
			return state, nil
		}
		if ins.Args[1].Kind == OpReg {
			known := armKernelValueDefined(ins.Args[0], sig, state)
			assign(armKernelRegBit(ins.Args[1].Reg), known)
			if setFlags {
				assign(armKernelN|armKernelZ, known)
				state &^= armKernelC
			}
		}
		if post {
			for _, arg := range ins.Args {
				if arg.Kind == OpMem {
					state &^= armKernelRegBit(arg.Mem.Base)
				}
			}
		}
		return state, nil
	}
	if op == "BL" || op == "CALL" {
		return state &^ (armKernelRegBit("R0") | armKernelRegBit("R1") | armKernelRegBit("R2") | armKernelRegBit("R3") | armKernelRegBit("R12") | armKernelFlags), nil
	}
	if op == "CMP" || op == "CMN" || op == "TST" || op == "TEQ" {
		known := len(ins.Args) == 2
		for _, arg := range ins.Args {
			known = known && armKernelValueDefined(arg, sig, state)
		}
		mask := armKernelFlags
		if op == "TST" || op == "TEQ" {
			mask = armKernelN | armKernelZ
			state &^= armKernelC
		}
		assign(mask, known)
		return state, nil
	}
	if _, _, branch := armKernelBranchForm(ins); branch {
		return state, nil
	}
	switch op {
	case "TEXT", "PCDATA", "FUNCDATA", "NO_LOCAL_POINTERS", "NOP", "DMB", "RET", "UNDEF":
		return state, nil
	case "ADD", "SUB", "AND", "ORR", "EOR", "BIC", "RSB", "MUL", "SRL", "SLL", "SRA", "ROR":
		if len(ins.Args) >= 2 && ins.Args[len(ins.Args)-1].Kind == OpReg {
			destination := armKernelRegBit(ins.Args[len(ins.Args)-1].Reg)
			known := len(ins.Args) != 2 || state.has(destination)
			for _, arg := range ins.Args[:len(ins.Args)-1] {
				known = known && armKernelValueDefined(arg, sig, state)
			}
			assign(destination, known)
			if setFlags {
				mask := armKernelFlags
				if op != "ADD" && op != "SUB" && op != "RSB" {
					mask = armKernelN | armKernelZ
					state &^= armKernelC
				}
				assign(mask, known)
			}
			return state, nil
		}
	}
	// Raw words and unproved machine effects invalidate, never preserve stale
	// ABI inputs or manufacture a value from generic initialized slots.
	return 0, nil
}
