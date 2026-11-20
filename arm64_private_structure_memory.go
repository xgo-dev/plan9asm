package plan9asm

import "fmt"

// Decoding/lowering a structure access alone cannot certify a physical frame.
// In a raw framed source, any missing complete source proof remains Context,
// rather than silently falling back to a larger guarded LLVM allocation.
func requireARM64RawStructureFrameProof(fn Func, unexposed bool) error {
	if unexposed || !arm64RawStructureFrameProofRequired(fn) {
		return nil
	}
	return fmt.Errorf("%w: ARM64 raw framed structure memory needs the complete physical-stack/source-escape proof", ErrProbeNeedsContext)
}

func arm64RawStructureFrameProofRequired(fn Func) bool {
	if !arm64HasRawFrameCode(fn) || !arm64SourceGoFrame(fn).present {
		return false
	}
	for _, ins := range fn.Instrs {
		if _, handled, _ := parseARM64StructureMemory(ins); handled {
			return true
		}
	}
	return false
}

// Structures cannot preserve a pointer's exact identity through the SIMD bank.
// The complete transfer width still supplies a bounds/overlap certificate; a
// register-indexed writeback remains unknown for a private affine base.
func (s *arm64RawPrivateFrameState) structureMemory(form arm64StructureMemoryForm, frameSize int64) bool {
	base := form.memory.Mem.Base
	address, private := s.address(base)
	if _, frame := s.address(form.index); frame || private && form.index != "" {
		return false
	}
	if !s.memory(arm64RawPrivateMemoryForm{
		memory: form.memory, registers: []Reg{form.registers[0]},
		elementBytes: form.width(), store: !form.load,
	}, frameSize) {
		return false
	}
	if private && form.post {
		updated, valid := arm64PrivateFrameOffset(address, form.increment)
		if !valid || !updated.exact || updated.offset < s.sp || updated.offset > frameSize+8 {
			return false
		}
		return s.assign(base, updated, true)
	}
	return true
}

func (state *arm64ControlState) transferStructureMemory(ins Instr) bool {
	form, handled, err := parseARM64StructureMemory(ins)
	if !handled || err != nil {
		return false
	}
	if form.load {
		value := state.readMemoryWidth(form.memory, form.width(), false)
		for _, reg := range form.registers {
			if form.lane >= 0 {
				// LDn lane preserves the remaining physical vector bits.
				value = arm64ControlUnion(value, arm64ControlRead(state.regs, reg))
			}
			state.write(Operand{Kind: OpReg, Reg: reg}, value, false)
		}
	} else {
		value := arm64ControlExternal()
		for _, reg := range form.registers {
			value = arm64ControlUnion(value, arm64ControlRead(state.regs, reg))
		}
		state.writeMemoryWidth(form.memory, value, form.width(), false)
	}
	if form.post {
		base := arm64ControlBase(form.memory.Mem.Base)
		value := arm64ControlRead(state.regs, base)
		if form.index == "" {
			value = arm64ControlOffset(value, form.increment)
		} else {
			value = arm64ControlUnion(arm64ControlExternal(), arm64ControlLabels(value))
			value = arm64ControlUnion(value, arm64ControlLabels(arm64ControlRead(state.regs, form.index)))
			if arm64ControlCount(arm64ControlLabels(value)) != 0 {
				value = arm64ControlWithToken(value, "code-derived:")
			}
		}
		state.regs[base] = value
	}
	return true
}
