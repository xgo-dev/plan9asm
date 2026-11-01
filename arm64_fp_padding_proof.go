package plan9asm

import (
	"fmt"
	mathbits "math/bits"
	"reflect"
	"strings"
)

type arm64FPPaddingRead struct {
	instruction Instr
	offset      int64
	bytes       int64
	declared    int64
}

type arm64PaddingState map[string]arm64PaddingBits

func (s arm64PaddingState) clone() arm64PaddingState {
	copyState := make(arm64PaddingState, len(s))
	for reg, value := range s {
		copyState[reg] = value
	}
	return copyState
}

func (s arm64PaddingState) merge(other arm64PaddingState) bool {
	changed := false
	for reg, value := range other {
		old := s[reg]
		merged := arm64PaddingBits{old[0] | value[0], old[1] | value[1]}
		if merged != old {
			s[reg], changed = merged, true
		}
	}
	return changed
}

func (s arm64PaddingState) read(reg Reg) arm64PaddingBits {
	if reg == ZR {
		return arm64PaddingBits{}
	}
	return s[arm64MachineRegister(reg)]
}

func (s arm64PaddingState) write(reg Reg, value arm64PaddingBits) {
	if reg != ZR {
		s[arm64MachineRegister(reg)] = value
	}
}

func (s arm64PaddingState) operand(arg Operand, word bool) uint64 {
	bits := 64
	if word {
		bits = 32
	}
	value := s.read(arg.Reg)[0] & arm64PaddingMask(bits)
	switch arg.Kind {
	case OpReg:
		return value
	case OpRegShift:
		if arg.ShiftReg != "" {
			return value | s.read(arg.ShiftReg)[0]
		}
		if arg.ShiftOp == ShiftRotate {
			if word {
				return uint64(mathbits.RotateLeft32(uint32(value), -int(arg.ShiftAmount)))
			}
			return mathbits.RotateLeft64(value, -int(arg.ShiftAmount))
		}
		return arm64PaddingShift(value, bits, arg.ShiftAmount, arg.ShiftOp != ShiftLeft, arg.ShiftOp == ShiftArith)
	case OpRegExtend:
		extendBits, signed := 64, false
		switch arg.Ext {
		case ExtendUXTB, ExtendSXTB:
			extendBits = 8
		case ExtendUXTH, ExtendSXTH:
			extendBits = 16
		case ExtendUXTW, ExtendSXTW:
			extendBits = 32
		}
		signed = arg.Ext == ExtendSXTB || arg.Ext == ExtendSXTH || arg.Ext == ExtendSXTW || arg.Ext == ExtendSXTX
		return arm64PaddingExtend(value, extendBits, signed, bits) << uint(arg.ShiftAmount) & arm64PaddingMask(bits)
	}
	return 0
}

func (s arm64PaddingState) observes(arg Operand) bool {
	unknown := func(reg Reg) bool { return s.read(reg) != (arm64PaddingBits{}) }
	switch arg.Kind {
	case OpReg, OpRegShift, OpRegExtend:
		return unknown(arg.Reg) || arg.ShiftReg != "" && unknown(arg.ShiftReg)
	case OpMem:
		return unknown(arg.Mem.Base) || arg.Mem.Index != "" && unknown(arg.Mem.Index)
	case OpRegList:
		for _, reg := range arg.RegList {
			if unknown(reg) {
				return true
			}
		}
	}
	return false
}

func arm64FPPaddingCandidate(ins Instr, decl *arm64FPReadDeclaration) (arm64FPPaddingRead, bool) {
	form, handled, err := parseARM64ScalarMemoryForm(arm64ControlOp(ins), ins)
	if !handled || err != nil || form.store || form.memory.Kind != OpFP || decl == nil {
		return arm64FPPaddingRead{}, false
	}
	offset, bytes := form.memory.FPOffset, int64(form.bits/8)
	end := decl.parameter.Offset + frameTypeSize(decl.parameter.Type, 8)
	if offset < decl.parameter.Offset || offset >= end || bytes <= end-offset || bytes > decl.paddingEnd-offset {
		return arm64FPPaddingRead{}, false
	}
	snapshot := ins
	snapshot.Args = append([]Operand(nil), ins.Args...)
	for i := range snapshot.Args {
		snapshot.Args[i].RegList = append([]Reg(nil), ins.Args[i].RegList...)
	}
	if ins.arm64ScalarMemoryFrameOffset != nil {
		offset := *ins.arm64ScalarMemoryFrameOffset
		snapshot.arm64ScalarMemoryFrameOffset = &offset
	}
	return arm64FPPaddingRead{instruction: snapshot, offset: offset, bytes: bytes, declared: end - offset}, true
}

func arm64FPPaddingReadProof(original, normalized Func, sig FuncSig) (map[[2]int]arm64FPPaddingRead, error) {
	decl := sig.arm64FPReadDeclaration
	if decl == nil {
		return nil, nil
	}
	hasRead := false
	for _, ins := range normalized.Instrs {
		if _, candidate := arm64FPPaddingCandidate(ins, decl); candidate {
			hasRead = true
		}
	}
	if !hasRead {
		return nil, nil
	}
	if !decl.matches(sig) || strings.HasSuffix(original.Sym, "<ABIInternal>") || original.arm64PrivateRegisterEntry {
		return nil, arm64PaddingContext("missing or changed complete typed ABI0 declaration")
	}
	// Prepare an independent copy of the original raw CFG. No partial proof or
	// normalized-only acceptance can authorize a representative padding value.
	prepared, err := normalizeARM64ScalarMemoryFrame(original)
	if err == nil {
		prepared, err = normalizeARM64AtomicPairNamedMemory(prepared)
	}
	if err == nil {
		prepared, err = normalizeARM64NamedPCRelative(prepared)
	}
	if err == nil {
		prepared, _, err = prepareARM64RawPCRelativeWithReturnClobbers(prepared, arm64RawPoolReturnClobbers(prepared, sig))
	}
	if err != nil {
		return nil, err
	}
	first, err := proveARM64FPPaddingBits(prepared, decl)
	if err != nil {
		return nil, fmt.Errorf("original source: %w", err)
	}
	final, err := proveARM64FPPaddingBits(normalized, decl)
	if err != nil {
		return nil, fmt.Errorf("normalized source: %w", err)
	}
	if !reflect.DeepEqual(first, final) {
		return nil, arm64PaddingContext("original/normalized parameter reads disagree")
	}
	return final, nil
}

func arm64PaddingContext(format string, args ...any) error {
	return fmt.Errorf("%w: ARM64 FP padding bit-use %s", ErrProbeNeedsContext, fmt.Sprintf(format, args...))
}

func proveARM64FPPaddingBits(fn Func, decl *arm64FPReadDeclaration) (map[[2]int]arm64FPPaddingRead, error) {
	if len(fn.Instrs) > 32768 {
		return nil, arm64PaddingContext("source exceeds bounded instruction inventory")
	}
	blocks := arm64SplitBlocks(fn)
	indices := make(map[string]int, len(blocks))
	for i, block := range blocks {
		if _, duplicate := indices[block.name]; duplicate {
			return nil, arm64PaddingContext("duplicate source CFG label")
		}
		indices[block.name] = i
	}
	before := make([]arm64PaddingState, len(blocks))
	reads := make(map[[2]int]arm64FPPaddingRead)
	queue, queued := []int{}, make([]bool, len(blocks))
	propagate := func(index int, state arm64PaddingState) error {
		if index < 0 || index >= len(blocks) {
			return arm64PaddingContext("unknown CFG edge")
		}
		changed := false
		if before[index] == nil {
			before[index], changed = state.clone(), true
		} else {
			changed = before[index].merge(state)
		}
		if changed && !queued[index] {
			queue, queued[index] = append(queue, index), true
		}
		return nil
	}
	work := 0
	// Include dead components too; later normalizations cannot erase a bad use.
	for seed := range blocks {
		if before[seed] != nil {
			continue
		}
		if err := propagate(seed, arm64PaddingState{}); err != nil {
			return nil, err
		}
		for next := 0; next < len(queue); next++ {
			bi := queue[next]
			queued[bi] = false
			state := before[bi].clone()
			terminated := false
			for ii, source := range blocks[bi].instrs {
				work++
				if work > 131072 {
					return nil, arm64PaddingContext("CFG proof exhausted its bounded work")
				}
				if handled := state.transferPaddingRawConstant(source); handled {
					continue
				}
				ins := arm64ControlDecode(source)
				op := arm64ControlOp(ins)
				if op == OpTEXT {
					if bi != 0 || ii != 0 {
						return nil, arm64PaddingContext("unexpected nested TEXT")
					}
					continue
				}
				if op == "BL" || op == "BLR" || op == "CALL" || op == "DUFFCOPY" || op == "DUFFZERO" ||
					op == "SVC" || op == "HVC" || op == "SMC" || op == "ERET" || op == OpWORD {
					return nil, arm64PaddingContext("unknown/native call or instruction: %q", source.Raw)
				}
				if op == OpRET {
					if len(ins.Args) != 0 || state.read("R30") != (arm64PaddingBits{}) || state.read(SP) != (arm64PaddingBits{}) ||
						state.read("R29") != (arm64PaddingBits{}) || state.read("R28") != (arm64PaddingBits{}) || state.read("R18") != (arm64PaddingBits{}) {
						return nil, arm64PaddingContext("unbound caller return: %q", source.Raw)
					}
					terminated = true
					break
				}
				if op == "B" || op == "JMP" || arm64IsConditionalBranch(op) {
					if len(ins.Args) == 0 {
						return nil, arm64PaddingContext("missing CFG target")
					}
					for _, arg := range ins.Args[:len(ins.Args)-1] {
						if state.observes(arg) {
							return nil, arm64PaddingContext("branch observes padding: %q", source.Raw)
						}
					}
					name, valid := arm64BranchTarget(ins.Args[len(ins.Args)-1])
					target, present := indices[name]
					if !valid || !present {
						return nil, arm64PaddingContext("nonlocal/unknown CFG target: %q", source.Raw)
					}
					if err := propagate(target, state); err != nil {
						return nil, err
					}
					if arm64IsConditionalBranch(op) {
						if err := propagate(bi+1, state); err != nil {
							return nil, err
						}
					}
					terminated = true
					break
				}
				if read, candidate := arm64FPPaddingCandidate(ins, decl); candidate {
					reads[[2]int{bi, ii}] = read
				}
				if err := state.transferPadding(ins, decl); err != nil {
					return nil, fmt.Errorf("%w at %q", err, source.Raw)
				}
			}
			if !terminated {
				if bi+1 >= len(blocks) {
					return nil, arm64PaddingContext("missing explicit source terminator")
				}
				if err := propagate(bi+1, state); err != nil {
					return nil, err
				}
			}
		}
		queue = nil
	}
	return reads, nil
}
