package plan9asm

import (
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

// This admission check is used only for a factory-captured same-package ABI0
// callee on the new scratch-call path. It is not an ordinary ABI0 permission,
// memory extent, caller frame, initialized pointee or physical SP certificate.
// Architectural frame operations are kept separate from numerical GP facts.
func arm64ScratchSamePackageInputs(function Func, signature FuncSig, body arm64ScratchNativeBody) bool {
	return arm64ScratchSamePackageInputsWithCalls(function, signature, body, nil)
}

func arm64ScratchSamePackageInputsWithCalls(function Func, signature FuncSig, body arm64ScratchNativeBody, calls map[string]FuncSig) bool {
	if !arm64ScratchSourceInputs(function, signature, calls, false) {
		return false
	}
	instructions, edges, valid := arm64ScratchNativeGraph(body)
	if !valid {
		return false
	}
	neutral := make(map[int]bool)
	frame := arm64SourceGoFrame(function)
	if frame.present {
		autosize := arm64SourceFrameAutosize(function.FrameSize)
		if autosize < 16 || autosize > 240 || autosize%16 != 0 || len(instructions) < 6 ||
			body.code[0] != 0xf8000ffe|uint32((-autosize)&511)<<12 ||
			body.code[1] != 0xf81f83fd || body.code[2] != 0xd10023fd {
			return false
		}
		for index := 0; index < 3; index++ {
			neutral[index] = true
		}
		for index, instruction := range instructions {
			if instruction.Op != arm64asm.RET {
				continue
			}
			if index < 5 {
				return false
			}
			restore := body.code[index-2 : index]
			if frame.restoresLink {
				if !arm64ScratchGeneratedRestore(restore, autosize) {
					return false
				}
			} else if !arm64ScratchGeneratedLeafRestore(restore, autosize) {
				return false
			}
			neutral[index-2], neutral[index-1] = true, true
		}
		// No branch may enter the middle of a generated frame operation.
		for from, successors := range edges {
			for _, to := range successors {
				if neutral[to] && (to < 3 || neutral[to-1]) && from != to-1 {
					return false
				}
			}
		}
	}
	effects := make([]arm64ScratchInputEffect, len(instructions))
	for index, instruction := range instructions {
		if neutral[index] {
			continue
		}
		if instruction.Op == arm64asm.BL {
			// Every original target is separately closed by the factory. No
			// data register, flag or address escapes that call into the caller.
			effects[index].call = true
			continue
		}
		effect, valid := arm64ScratchNativeInputEffect(instruction, true)
		if !valid {
			return false
		}
		effects[index] = effect
	}
	return arm64ScratchNativeAvailable(effects, edges, 0)
}

// These are the two actual obj7 leaf epilogues. One restores BP before SP;
// the older producer restores SP then computes BP from that restored SP.
// Neither architectural frame operation creates a numerical register fact.
func arm64ScratchGeneratedLeafRestore(code []uint32, autosize int64) bool {
	if len(code) != 2 || autosize < 16 || autosize > 240 || autosize%16 != 0 {
		return false
	}
	return code[0] == 0x910003fd|uint32(autosize-8)<<10 &&
		code[1] == 0x910003ff|uint32(autosize)<<10 ||
		code[0] == 0x910003ff|uint32(autosize)<<10 && code[1] == 0xd10023fd
}

type arm64ScratchLocalBytes [4]uint64

type arm64ScratchSourceBytes struct {
	local, results arm64ScratchLocalBytes
}

func (bytes *arm64ScratchLocalBytes) transfer(offset, width int64, write bool) bool {
	if offset < 0 || width <= 0 || width > 16 || offset > 256-width {
		return false
	}
	for cursor := offset; cursor < offset+width; cursor++ {
		word, bit := cursor/64, uint(cursor%64)
		if write {
			bytes[word] |= 1 << bit
		} else if bytes[word]&(1<<bit) == 0 {
			return false
		}
	}
	return true
}

func arm64ScratchReservedInput(reg Reg) bool {
	return arm64StackReg(reg) || reg == "R29" || reg == "R30"
}

// Exact source-local bytes start undefined. This is an observation, not an
// allocation: no slot is invented and no logical address becomes native. The
// lowerer's existing frame/ABI/native-pointer guards must still accept it.
func arm64ScratchSourceLocalInputs(function Func, signature FuncSig) bool {
	return arm64ScratchSourceInputs(function, signature, nil, false)
}

// Call contracts come only from the factory's recursively closed original
// source and matching assembler/archive bodies. They supply exact initialized
// result bytes, never GP/NZCV outputs or permission to retain other locals.
func arm64ScratchSourceInputs(function Func, signature FuncSig, calls map[string]FuncSig, requireResults bool) bool {
	if function.FrameSize < 0 || function.FrameSize > 224 || function.ArgSize < 0 || function.ArgSize > 256 ||
		len(function.Instrs) == 0 || len(function.Instrs) > 65536 {
		return false
	}
	blocks := arm64SplitBlocks(function)
	indices := make(map[string]int, len(blocks))
	for index, block := range blocks {
		if _, duplicate := indices[block.name]; duplicate {
			return false
		}
		indices[block.name] = index
	}
	before, seen := make([]arm64ScratchSourceBytes, len(blocks)), make([]bool, len(blocks))
	steps := 0
	for entry := range blocks {
		if seen[entry] {
			continue
		}
		seen[entry] = true
		queue := []int{entry}
		for len(queue) != 0 {
			at := queue[0]
			queue = queue[1:]
			state := before[at]
			steps++
			if steps > len(function.Instrs)*512 {
				return false
			}
			for _, original := range blocks[at].instrs {
				instruction := arm64ControlDecode(original)
				op := arm64ControlOp(instruction)
				if op == OpWORD || op == "DWORD" || op == arm64RawDataOp || original.arm64Encoded {
					return false
				}
				for _, operand := range instruction.Args {
					registers := []Reg{operand.Reg, operand.ShiftReg, operand.Mem.Index}
					registers = append(registers, operand.RegList...)
					for _, register := range registers {
						if arm64ScratchReservedInput(register) {
							return false
						}
					}
					if operand.Kind == OpFPAddr || operand.Mem.Base == "R29" || operand.Mem.Base == "R30" {
						return false
					}
					if operand.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(operand.Sym), "$") {
						if memory, parsed := parseMem(strings.TrimSpace(strings.TrimPrefix(operand.Sym, "$"))); parsed &&
							(arm64ScratchReservedInput(memory.Base) || arm64ScratchReservedInput(memory.Index)) {
							return false
						}
					}
				}
				if op == "CALL" || op == "BL" {
					if len(instruction.Args) != 1 || instruction.Args[0].Kind != OpSym ||
						!strings.HasSuffix(instruction.Args[0].Sym, "(SB)") {
						return false
					}
					target := strings.ReplaceAll(strings.TrimSuffix(instruction.Args[0].Sym, "(SB)"), "·", ".")
					callee, closed := calls[target]
					if !closed || !arm64ScratchCallLayout(callee) ||
						!arm64ScratchCallSlots(&state.local, callee.Frame.Params, function.FrameSize, false) {
						return false
					}
					state = arm64ScratchSourceBytes{}
					if !arm64ScratchCallSlots(&state.local, callee.Frame.Results, function.FrameSize, true) {
						return false
					}
					continue
				}
				if op == OpRET && requireResults {
					for _, slot := range signature.Frame.Results {
						width := int64((arm64MachineScalarWidth(slot.Type) + 7) / 8)
						if !state.results.transfer(slot.Offset, width, false) {
							return false
						}
					}
				}
				memory, width, store, registered := arm64ScratchSourceMemory(instruction)
				for _, operand := range instruction.Args {
					if operand.Kind == OpMem && arm64StackReg(operand.Mem.Base) {
						exact := operand.Mem
						exact.Base = SP // The registered grammar canonicalizes RSP's address-bank alias.
						if !registered || memory.Kind != OpMem || memory.Mem != exact || function.FrameSize == 0 ||
							operand.Mem.Index != "" || operand.Mem.Sym != "" || operand.Mem.OffRaw != "" ||
							operand.Mem.Off < 8 || operand.Mem.Off > function.FrameSize+8-width ||
							!state.local.transfer(operand.Mem.Off, width, store) {
							return false
						}
					}
				}
				if registered && memory.Kind == OpFP && !store && !arm64ScratchParameterRange(signature, memory.FPOffset, width) {
					return false
				}
				if registered && memory.Kind == OpFP && store && requireResults {
					if !arm64ScratchSlotRange(signature.Frame.Results, memory.FPOffset, width) ||
						!state.results.transfer(memory.FPOffset, width, true) {
						return false
					}
				}
				if registered && store && memory.Kind != OpFP && !(memory.Kind == OpMem && arm64StackReg(memory.Mem.Base)) {
					// A potentially aliased write cannot preserve local byte facts.
					state = arm64ScratchSourceBytes{}
				}
			}
			successors, valid := arm64ScratchSourceSuccessors(blocks, indices, at)
			if !valid {
				return false
			}
			for _, next := range successors {
				value := state
				if seen[next] {
					for word := range value.local {
						value.local[word] &= before[next].local[word]
						value.results[word] &= before[next].results[word]
					}
				}
				if !seen[next] || value != before[next] {
					seen[next], before[next] = true, value
					queue = append(queue, next)
				}
			}
		}
	}
	return true
}

func arm64ScratchParameterRange(signature FuncSig, offset, width int64) bool {
	return arm64ScratchSlotRange(signature.Frame.Params, offset, width)
}

func arm64ScratchSlotRange(slots []FrameSlot, offset, width int64) bool {
	if offset < 0 || width <= 0 || width > 16 || offset > 256-width {
		return false
	}
	for at := offset; at < offset+width; at++ {
		matches := 0
		for _, slot := range slots {
			bits := arm64MachineScalarWidth(slot.Type)
			if bits != 0 && slot.Offset >= 0 && slot.Offset <= 256-int64((bits+7)/8) &&
				at >= slot.Offset && at < slot.Offset+int64((bits+7)/8) {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

func arm64ScratchNumericCallLayout(signature FuncSig) bool {
	if !arm64ScratchCallLayout(signature) {
		return false
	}
	for _, argument := range signature.Args {
		if argument == Ptr {
			return false
		}
	}
	return true
}

func arm64ScratchCallLayout(signature FuncSig) bool {
	integer := func(typ LLVMType) bool {
		return typ == I1 || typ == I8 || typ == I16 || typ == I32 || typ == I64
	}
	if len(signature.Args) != len(signature.Frame.Params) || len(signature.ArgRegs) != 0 ||
		signature.ARM64GoRegisterABI != nil || signature.ARM64ClosureABI != nil {
		return false
	}
	for _, argument := range signature.Args {
		if !integer(argument) && argument != Ptr {
			return false
		}
	}
	return signature.Ret == Void && len(signature.Frame.Results) == 0 ||
		integer(signature.Ret) && len(signature.Frame.Results) == 1 && signature.Frame.Results[0].Type == signature.Ret
}

func arm64ScratchCallSlots(bytes *arm64ScratchLocalBytes, slots []FrameSlot, frame int64, write bool) bool {
	for _, slot := range slots {
		width := int64((arm64MachineScalarWidth(slot.Type) + 7) / 8)
		if slot.Offset < 0 || width == 0 || slot.Offset > frame-width ||
			!bytes.transfer(8+slot.Offset, width, write) {
			return false
		}
	}
	return true
}

func arm64ScratchSourceMemory(instruction Instr) (Operand, int64, bool, bool) {
	op := arm64ControlOp(instruction)
	if form, handled, err := parseARM64ScalarMemoryForm(op, instruction); handled {
		return form.memory, int64(form.bits / 8), form.store, err == nil && !form.pre && !form.post
	}
	if pair, handled := arm64IntegerPairSpecs[op]; handled && len(instruction.Args) == 2 && instruction.Op == op {
		memory, registers := instruction.Args[0], instruction.Args[1]
		if !pair.load {
			memory, registers = registers, memory
		}
		if registers.Kind == OpRegList && len(registers.RegList) == 2 &&
			isARM64GeneralOrZeroReg(registers.RegList[0]) && isARM64GeneralOrZeroReg(registers.RegList[1]) &&
			(!pair.load || registers.RegList[0] != registers.RegList[1]) {
			if memory.Kind == OpMem && arm64StackReg(memory.Mem.Base) {
				// Match the scalar grammar's address-bank canonicalization.
				// This changes no offset, width, indexing or byte-definedness.
				memory.Mem.Base = SP
			}
			return memory, int64(pair.elementBytes * 2), !pair.load, true
		}
	}
	return Operand{}, 0, false, false
}

func arm64ScratchSourceSuccessors(blocks []arm64Block, labels map[string]int, at int) ([]int, bool) {
	block := blocks[at]
	if len(block.instrs) == 0 {
		// Consecutive source labels retain separate CFG identities, but
		// execute no effects. Preserve the incoming byte facts along their
		// real fallthrough edge; a final empty block still has no exit proof.
		if at+1 < len(blocks) {
			return []int{at + 1}, true
		}
		return nil, false
	}
	last := arm64ControlDecode(block.instrs[len(block.instrs)-1])
	op := arm64ControlOp(last)
	if op == OpRET {
		return nil, len(last.Args) == 0
	}
	var successors []int
	if op == "B" || op == "JMP" || arm64IsConditionalBranch(op) {
		if len(last.Args) == 0 {
			return nil, false
		}
		name, valid := arm64BranchTarget(last.Args[len(last.Args)-1])
		next, present := labels[name]
		if !valid || !present {
			return nil, false
		}
		successors = append(successors, next)
		if op == "B" || op == "JMP" {
			return successors, true
		}
	}
	if at+1 == len(blocks) {
		return nil, false
	}
	return append(successors, at+1), true
}
