package plan9asm

import (
	"reflect"
	"strconv"
	"strings"
)

// Independent result-address state. Zero is ordinary data; -1 retains a lost
// or mixed capability. Neither initialized LLVM allocas nor function-wide FP
// routing hints establish that a result was written on every returning path.
type arm64ABI0ResultState struct {
	addresses [32]int16
	written   [16]uint8
}

func arm64ABI0ResultRegister(reg Reg) (int, bool) {
	if !strings.HasPrefix(string(reg), "R") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(string(reg), "R"))
	return n, err == nil && n >= 0 && n < 31
}

func (s *arm64ABI0ResultState) address(reg Reg) int16 {
	if n, ok := arm64ABI0ResultRegister(reg); ok {
		return s.addresses[n]
	}
	return 0
}

func (s *arm64ABI0ResultState) assign(reg Reg, value int16) {
	if n, ok := arm64ABI0ResultRegister(reg); ok {
		s.addresses[n] = value
	}
}

func (s *arm64ABI0ResultState) operand(op Operand) bool {
	if op.Kind == OpSym && strings.HasPrefix(op.Sym, "$") {
		if memory, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(op.Sym, "$"))); ok &&
			(s.address(memory.Base) != 0 || s.address(memory.Index) != 0) {
			return false // Address spellings cannot wash a Slot into Plain.
		}
	}
	if s.address(op.Reg) != 0 || s.address(op.ShiftReg) != 0 ||
		s.address(op.Mem.Base) != 0 || s.address(op.Mem.Index) != 0 {
		return false
	}
	for _, reg := range op.RegList {
		if s.address(reg) != 0 {
			return false
		}
	}
	return true
}

func arm64ABI0ResultIndex(sig FuncSig, off int64) (int, bool) {
	for i, slot := range sig.Frame.Results {
		if slot.Offset == off {
			return i, true
		}
	}
	return 0, false
}

func arm64ABI0ResultMask(slot FrameSlot) uint8 {
	return uint8((uint16(1) << uint(frameTypeSize(slot.Type, 8))) - 1)
}

func (s *arm64ABI0ResultState) step(ins Instr, sig FuncSig) error {
	reject := func() error {
		return arm64GoABIContext("ABI0 result capability has an incomplete/escaping effect at %q", ins.Raw)
	}
	op := arm64ControlOp(ins)
	if op == OpTEXT || op == OpLABEL {
		return nil
	}
	if op == OpRET {
		if len(ins.Args) != 0 {
			return reject()
		}
		for i, slot := range sig.Frame.Results {
			if s.written[i] != arm64ABI0ResultMask(slot) {
				return arm64GoABIContext("ABI0 result %d is not completely written on every RET path", i)
			}
		}
		return nil
	}
	if len(ins.Args) == 2 && ins.Args[1].Kind == OpReg && op == "MOVD" && string(ins.Op) == string(op) {
		src, dst := ins.Args[0], ins.Args[1].Reg
		if src.Kind == OpFPAddr {
			if _, gp := arm64ABI0ResultRegister(dst); !gp {
				return reject()
			}
			index, found := arm64ABI0ResultIndex(sig, src.FPOffset)
			if !found {
				return reject()
			}
			s.assign(dst, int16(index+1))
			return nil
		}
		if src.Kind == OpReg {
			if _, gp := arm64ABI0ResultRegister(dst); !gp && s.address(src.Reg) != 0 {
				return reject()
			}
			s.assign(dst, s.address(src.Reg))
			return nil
		}
	}
	if form, known := arm64RawPrivateMemory(ins); known {
		if form.store {
			if !form.gp || len(form.registers) != 1 || form.pre || form.post || form.scratch != nil ||
				s.address(form.registers[0]) != 0 {
				return reject()
			}
			index, found := 0, false
			if form.memory.Kind == OpFP {
				index, found = arm64ABI0ResultIndex(sig, form.memory.FPOffset)
			} else if form.memory.Kind == OpMem {
				m := form.memory.Mem
				capability := s.address(m.Base)
				if capability > 0 && m.Index == "" && m.Off == 0 && m.OffRaw == "" && m.Sym == "" && m.Segment == "" {
					index, found = int(capability-1), true
				}
			}
			if !found || index >= len(sig.Frame.Results) || form.elementBytes != frameTypeSize(sig.Frame.Results[index].Type, 8) {
				return reject() // Never a parameter, heap, SB, partial or affine store.
			}
			s.written[index] = arm64ABI0ResultMask(sig.Frame.Results[index])
			return nil
		}
		if !s.operand(form.memory) {
			return reject() // A result address cannot be read as data or written back.
		}
		if form.memory.Kind == OpFP {
			if _, result := arm64ABI0ResultIndex(sig, form.memory.FPOffset); result {
				return reject() // Initial scope uses declared parameter loads only.
			}
		}
		for _, reg := range form.registers {
			s.assign(reg, 0)
		}
		if form.pre || form.post {
			s.assign(form.memory.Mem.Base, 0)
		}
		if form.scratch != nil {
			s.assign("R27", 0)
		}
		return nil
	}
	if form, handled, err := parseARM64GPDataForm(op, ins); handled {
		if err != nil {
			return reject()
		}
		for _, input := range form.inputs {
			if !s.operand(input) {
				return reject()
			}
		}
		for _, reg := range arm64GPDataOutputRegisters(form) {
			s.assign(reg, 0)
		}
		return nil
	}
	if len(ins.Args) == 2 && ins.Args[1].Kind == OpReg &&
		(op == "MOVD" || op == "MOVW" || op == "MOVWU" || op == "MOVH" || op == "MOVHU" || op == "MOVB" || op == "MOVBU") {
		if !s.operand(ins.Args[0]) || ins.Args[0].Kind == OpFPAddr {
			return reject()
		}
		s.assign(ins.Args[1].Reg, 0)
		return nil
	}
	if form, handled, err := parseARM64StructureMemory(ins); handled {
		if err != nil || !form.load || !s.operand(form.memory) {
			return reject()
		}
		if form.post {
			s.assign(form.memory.Mem.Base, 0)
		}
		return nil
	}
	for _, arg := range ins.Args {
		if !s.operand(arg) || arg.Kind == OpFPAddr || arg.Kind == OpFP {
			return reject()
		}
	}
	// Unknown effects still go through the complete normal typed lowerer and
	// empty-entry must-definition proof. No unknown use can transport a Slot.
	return nil
}

func arm64ABI0TailResultProof(fn Func, sig FuncSig) error {
	if len(fn.Instrs) == 0 || len(fn.Instrs) > arm64PrivateRegisterExpansionBudget || len(sig.Frame.Results) > 16 {
		return arm64GoABIContext("ABI0 result CFG exceeds its checked bound")
	}
	labels := map[string]int{}
	for i, ins := range fn.Instrs {
		if ins.Op == OpLABEL {
			if len(ins.Args) != 1 || labels[ins.Args[0].Sym] != 0 {
				return arm64GoABIContext("ABI0 result CFG has an ambiguous label")
			}
			labels[ins.Args[0].Sym] = i
		}
	}
	states := make([]*arm64ABI0ResultState, len(fn.Instrs))
	states[0] = &arm64ABI0ResultState{}
	queue := []int{0}
	steps, returns := 0, 0
	for len(queue) != 0 {
		at := queue[0]
		queue = queue[1:]
		steps++
		if steps > 1<<20 {
			return arm64GoABIContext("ABI0 result CFG did not converge within its work bound")
		}
		state := *states[at]
		ins := fn.Instrs[at]
		if err := state.step(ins, sig); err != nil {
			return err
		}
		if ins.Op == OpRET {
			returns++
			continue
		}
		next := []int{at + 1}
		if ins.Op == "B" || ins.Op == "JMP" || arm64IsConditionalBranch(ins.Op) {
			if len(ins.Args) == 0 || ins.Args[len(ins.Args)-1].Kind != OpIdent {
				return arm64GoABIContext("ABI0 result CFG has an external/dynamic branch")
			}
			destination, exists := labels[ins.Args[len(ins.Args)-1].Ident]
			if !exists {
				return arm64GoABIContext("ABI0 result CFG has an unresolved label")
			}
			if ins.Op == "B" || ins.Op == "JMP" {
				next = []int{destination}
			} else {
				next = append(next, destination)
			}
		}
		for _, target := range next {
			if target >= len(states) {
				return arm64GoABIContext("ABI0 result CFG falls outside its returning source")
			}
			joined := state
			if old := states[target]; old != nil {
				for i, cap := range joined.addresses {
					if cap != old.addresses[i] {
						joined.addresses[i] = -1
					}
				}
				for i := range joined.written {
					joined.written[i] &= old.written[i]
				}
				if reflect.DeepEqual(joined, *old) {
					continue
				}
			}
			states[target] = &joined
			queue = append(queue, target)
		}
	}
	if returns == 0 {
		return arm64GoABIContext("ABI0 result CFG has no complete returning path")
	}
	return nil
}
