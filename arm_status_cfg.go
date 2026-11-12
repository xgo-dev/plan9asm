package plan9asm

import (
	"fmt"
	"strings"
)

type armStatusState struct {
	initialized armKernelState
	values      armKernelState
	vfpWitness  bool
}

// The emitter's flagsWritten boolean only describes compile-time traversal.
// Reading CPSR instead requires a must-initialized proof for all four modeled
// NZCV slots on every source path. Entry has no invented physical flags, and
// an ordinary C call has no source-native flags-result contract.
func proveARMStatusReads(fn Func, sig FuncSig) error {
	if !armFunctionUsesModeledFlags(fn) {
		return nil
	}
	// A raw VFP compare changes FPSCR only. Keep the source proof limited to
	// a closed unconditional compare/VMRS pair before any condition observes
	// its APSR result; the emitter copies native FPSCR at the VMRS itself.
	// Other sequences remain ordinary hard gaps, never native-entry N/A.
	fn.Instrs = append([]Instr(nil), fn.Instrs...)
	for i, ins := range fn.Instrs {
		if ins.Op != "WORD" || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm {
			continue
		}
		compare, ok := decodeARMRawVFPCompare(uint32(ins.Args[0].Imm))
		if !ok {
			continue
		}
		closed := compare.condition == "AL" && i+1 < len(fn.Instrs)
		if closed {
			next := fn.Instrs[i+1]
			closed = next.Op == "WORD" && len(next.Args) == 1 && next.Args[0].Kind == OpImm && uint32(next.Args[0].Imm) == 0xeef1fa10
		}
		if !closed {
			return fmt.Errorf("ARM raw VFP flags effect needs a closed unconditional compare/VMRS sequence: %s", ins.Raw)
		}
		fn.Instrs[i].Op = "CMPD" // Proof-only full NZCV writer; emitted source stays unchanged.
	}
	blocks := armSplitBlocks(fn)
	preds, reachable := armSourcePredecessors(blocks)
	entry := armStatusState{}
	if sig.ARMEntry != nil {
		// Full translation validates the entry contract before reaching this
		// proof; its shim captures physical NZCV and every non-PC GP register.
		entry.initialized = armKernelFlags
		entry.values = armKernelTop &^ armKernelRegBit("R15")
	}
	for i, reg := range sig.ArgRegs {
		if i < len(sig.Args) {
			entry.values |= armKernelRegBit(reg)
		}
	}
	in, out := make([]armStatusState, len(blocks)), make([]armStatusState, len(blocks))
	for i := range blocks {
		if reachable[i] {
			in[i] = armStatusState{initialized: armKernelFlags, values: armKernelTop, vfpWitness: true}
			out[i] = in[i]
		}
	}
	for changed := true; changed; {
		changed = false
		for i, block := range blocks {
			if !reachable[i] {
				continue
			}
			state := armStatusState{initialized: armKernelFlags, values: armKernelTop, vfpWitness: true}
			if i == 0 {
				state = entry
			}
			for _, pred := range preds[i] {
				state.initialized &= out[pred].initialized
				state.values &= out[pred].values
				state.vfpWitness = state.vfpWitness && out[pred].vfpWitness
			}
			in[i] = state
			for _, ins := range block.instrs {
				state, _ = armStatusTransfer(fn.Sym, sig, state, ins, false)
			}
			if out[i] != state {
				out[i], changed = state, true
			}
		}
	}
	for i, block := range blocks {
		if !reachable[i] {
			continue
		}
		state := in[i]
		for _, ins := range block.instrs {
			var err error
			state, err = armStatusTransfer(fn.Sym, sig, state, ins, true)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func armFunctionUsesModeledFlags(fn Func) bool {
	for _, ins := range fn.Instrs {
		if _, matched, _ := parseARMStatusMove(ins); matched {
			return true
		}
		if armInstructionReadsStatus(ins) || armInstructionFlagInputs(ins) != 0 {
			return true
		}
	}
	return false
}

func armInstructionFlagInputs(ins Instr) armKernelState {
	if form, ok := decodeARMRawDataForm(ins); ok {
		return armKernelConditionBits(form.condition)
	}
	if ins.Op == OpWORD && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
		if form, ok := decodeARMRawVFPCompare(uint32(ins.Args[0].Imm)); ok {
			// A raw predicate consumes source APSR even when no subsequent
			// named instruction reads flags. Enter the all-path proof; the
			// existing closed-pair rule does not authorize conditional VCMP.
			return armKernelConditionBits(form.condition)
		}
	}
	if form, matched, err := parseARMStatusMove(ins); matched && err == nil {
		return armKernelConditionBits(form.condition)
	}
	op, condition, _, _ := armDecodeOp(string(ins.Op))
	if len(op) > 1 && op[0] == 'B' && armCondCodes[op[1:]] {
		condition = op[1:]
	}
	inputs := armKernelConditionBits(condition)
	if op == "ADC" || op == "SBC" || op == "RSC" {
		inputs |= armKernelC
	}
	return inputs
}

func armInstructionReadsStatus(ins Instr) bool {
	op, _, _, _ := armDecodeOp(string(ins.Op))
	for i, arg := range ins.Args {
		if arg.Kind != OpIdent || !strings.EqualFold(arg.Ident, "CPSR") {
			continue
		}
		if _, move := armIntegerMemorySpecs[op]; move && i == 1 && len(ins.Args) == 2 {
			continue // A destination is a source write, not a status read.
		}
		return true
	}
	return false
}

func armStatusTransfer(name string, sig FuncSig, state armStatusState, ins Instr, check bool) (armStatusState, error) {
	if form, ok := decodeARMRawDataForm(ins); ok {
		predicate := armKernelConditionBits(form.condition)
		if check && predicate != 0 && !state.initialized.has(predicate) {
			return state, fmt.Errorf("%w: ARM raw %s in %q has no initialized %s predicate: %s", ErrProbeNeedsContext, form.family, name, form.condition, ins.Raw)
		}
		// These exact typed data forms leave APSR unchanged. GP outputs cannot
		// acquire a source-value witness from zero-initialized vector slots or
		// an unproved memory read. FPSCR changes never revive a VMRS witness.
		state.values &^= form.gpWrites
		state.vfpWitness = false
		return state, nil
	}
	if form, matched, err := parseARMStatusMove(ins); matched {
		if err != nil {
			return state, err
		}
		predicate := armKernelConditionBits(form.condition)
		if check && predicate != 0 && !state.initialized.has(predicate) {
			return state, fmt.Errorf("%w: ARM CPSR continuation in %q has no initialized %s predicate: %s", ErrProbeNeedsContext, name, form.condition, ins.Raw)
		}
		if !form.write {
			if check && !state.initialized.has(armKernelFlags) {
				return state, fmt.Errorf("%w: ARM CPSR read in %q needs source-defined NZCV on every path or an explicit native-entry state bridge: %s", ErrProbeNeedsContext, name, ins.Raw)
			}
			mask := armKernelRegBit(form.dest)
			known := state.initialized.has(armKernelFlags) && (predicate == 0 || state.values.has(mask))
			state.values &^= mask
			if known {
				state.values |= mask
			}
			return state, nil
		}
		known := armKernelValueDefined(form.source, sig, state.values)
		if check && !known {
			return state, fmt.Errorf("%w: ARM CPSR write in %q requires a typed/source-defined status value: %s", ErrProbeNeedsContext, name, ins.Raw)
		}
		if !known {
			state.initialized = 0
		} else if predicate == 0 {
			state.initialized = armKernelFlags
		}
		state.vfpWitness = false
		return state, nil
	}
	op, condition, _, setFlags := armDecodeOp(string(ins.Op))
	if len(op) > 1 && op[0] == 'B' && armCondCodes[op[1:]] {
		condition = op[1:]
	}
	predicate := armKernelConditionBits(condition)
	if check && predicate != 0 && !state.initialized.has(predicate) {
		return state, fmt.Errorf("%w: ARM CPSR continuation in %q has no initialized %s predicate: %s", ErrProbeNeedsContext, name, condition, ins.Raw)
	}
	readsStatus := armInstructionReadsStatus(ins)
	if check && readsStatus && !state.initialized.has(armKernelFlags) {
		return state, fmt.Errorf("%w: ARM CPSR read in %q needs source-defined NZCV on every path or an explicit native-entry state bridge: %s", ErrProbeNeedsContext, name, ins.Raw)
	}
	consumesCarry := op == "ADC" || op == "SBC" || op == "RSC"
	if check && consumesCarry && !state.initialized.has(armKernelC) {
		return state, fmt.Errorf("%w: ARM source carry input in %q has no source definition or typed native-entry bridge: %s", ErrProbeNeedsContext, name, ins.Raw)
	}
	values, _ := armKernelTransfer(name, sig, state.values, ins, false)
	if readsStatus && state.initialized.has(armKernelFlags) && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		mask := armKernelRegBit(ins.Args[1].Reg)
		if predicate == 0 || state.values.has(mask) {
			values |= mask
		}
	}
	if call := ins.armKernelCall; call != nil {
		if call.spec.entry == armKernelCompareExchange32 && predicate == 0 {
			// Unlike a C call, this typed region captures APSR in the same
			// assembly region as the documented native helper return.
			state.initialized = armKernelFlags
		}
		if call.spec.entry == armKernelCompareExchange32 {
			state.vfpWitness = false
		}
		state.values = values
		return state, nil
	}
	write := armKernelState(0)
	logical := op == "TST" || op == "TEQ" || setFlags && (op == "AND" || op == "ORR" || op == "EOR" || op == "BIC" || op == "MVN" || op == "MOVW")
	switch op {
	case "CMP", "CMN", "CMPF", "CMPD":
		write = armKernelFlags
	case "TST", "TEQ":
		write = armKernelN | armKernelZ
	case "BL", "CALL", "BX", "DIV", "DIVU", "MOD", "MODU", "DUFFZERO", "DUFFCOPY":
		state.initialized = 0
		state.vfpWitness = false
	case "WORD", "BYTE", "LONG":
		keep := false
		if len(ins.Args) == 1 && ins.Args[0].Kind == OpImm {
			if decoded, carry, ok := decodeARMRawTST(uint32(ins.Args[0].Imm), ins.Raw); ok {
				state, err := armStatusTransfer(name, sig, state, decoded, check)
				if carry != "" {
					state.initialized |= armKernelC
				}
				return state, err
			}
			form, ok := decodeARMRawVFPStatusTransfer(uint32(ins.Args[0].Imm))
			keep = ok && form.toFlags && state.vfpWitness
		}
		if !keep {
			state.initialized = 0
			state.vfpWitness = false
		}
	default:
		if setFlags {
			switch op {
			case "ADD", "SUB", "RSB", "ADC", "SBC", "RSC":
				write = armKernelFlags
			case "AND", "ORR", "EOR", "BIC", "MVN", "SLL", "SRL", "SRA", "MUL", "MULU", "MULA", "MULL", "MULLU", "MULAL", "MULALU":
				write = armKernelN | armKernelZ
			default:
				// Do not retain older slot values across an unmodeled .S
				// source effect merely because some earlier CMP ran.
				if op == "MOVW" && len(ins.Args) == 2 && ins.Args[0].Kind == OpSym {
					address := strings.TrimSpace(ins.Args[0].Sym)
					if strings.HasPrefix(address, "$") {
						memory, ok := parseMem(strings.TrimPrefix(address, "$"))
						if _, err := parseARMRegisterAddressForm(op, ins, memory); ok && err == nil {
							write = armKernelFlags
						}
					}
				}
				if op == "MOVW" && len(ins.Args) == 2 && (ins.Args[0].Kind == OpReg || ins.Args[0].Kind == OpRegShift) && ins.Args[1].Kind == OpReg {
					write = armKernelN | armKernelZ
				}
				if write == 0 {
					return state, fmt.Errorf("ARM %s flag-setting source effect is not modeled: %s", op, ins.Raw)
				}
			}
		}
	}
	if _, move := armIntegerMemorySpecs[op]; move && len(ins.Args) == 2 && ins.Args[1].Kind == OpIdent && strings.EqualFold(ins.Args[1].Ident, "CPSR") {
		if armKernelValueDefined(ins.Args[0], sig, state.values) {
			write = armKernelFlags
		} else {
			state.initialized = 0
		}
	}
	if predicate == 0 {
		state.initialized |= write
		if logical && len(ins.Args) != 0 && (armLogicalImmediateCarry(op, ins.Args[0]) != "" || armShifterDefinesCarry(ins.Args[0])) {
			state.initialized |= armKernelC
		}
		if setFlags && (op == "SLL" || op == "SRL" || op == "SRA") && len(ins.Args) != 0 && ins.Args[0].Kind == OpImm && ins.Args[0].Imm != 0 && (op != "SLL" || uint32(ins.Args[0].Imm)&31 != 0) {
			state.initialized |= armKernelC
		}
	}
	if write != 0 {
		if op == "CMPF" || op == "CMPD" {
			state.vfpWitness = predicate == 0 || state.vfpWitness
		} else {
			state.vfpWitness = false
		}
	}
	if len(ins.Args) == 2 && ins.Args[1].Kind == OpIdent && (strings.EqualFold(ins.Args[1].Ident, "FPCR") || strings.EqualFold(ins.Args[1].Ident, "FPSR")) {
		state.vfpWitness = false
	}
	state.values = values
	return state, nil
}
