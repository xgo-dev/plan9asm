package plan9asm

import (
	"reflect"
	"strings"
)

// This additive proof is only for framed source-leaf functions containing raw
// encodings or checked R20 uses. Unlike the older affine proof it tracks physical SP
// movement and privately spilled frame-address values. Neither decoding a WORD
// nor a generic GP-write mask supplies permission to expose or erase an address.
type arm64RawPrivateFrameState struct {
	sp     int64
	regs   arm64PrivateFrameAddresses
	spills map[int64]arm64PrivateFrameAddress // eight-byte address-bearing cells
	fixed  *arm64ControlState                 // independent R18/g entry identities and saved cells
}

func (s *arm64RawPrivateFrameState) clone() *arm64RawPrivateFrameState {
	next := &arm64RawPrivateFrameState{sp: s.sp, regs: s.regs.clone(), spills: make(map[int64]arm64PrivateFrameAddress)}
	for offset, value := range s.spills {
		next.spills[offset] = value
	}
	if s.fixed != nil {
		next.fixed = s.fixed.clone()
	}
	return next
}

func (s *arm64RawPrivateFrameState) address(reg Reg) (arm64PrivateFrameAddress, bool) {
	if arm64StackReg(reg) {
		return arm64PrivateFrameAddress{offset: s.sp, exact: true}, true
	}
	value, present := s.regs[reg]
	return value, present
}

func (s *arm64RawPrivateFrameState) assign(reg Reg, value arm64PrivateFrameAddress, present bool) bool {
	if arm64StackReg(reg) {
		if !present || !value.exact || value.offset > 0 || value.offset < -arm64MaxLocalStackSpan {
			return false
		}
		s.sp = value.offset
		return true
	}
	return s.regs.assign(reg, value, present)
}

func arm64HasRawFrameCode(fn Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op == OpWORD {
			return true
		}
	}
	return false
}

func arm64RawPrivateFrameUnexposed(fn Func) bool {
	return arm64RawPrivateFrameUnexposedForTransport(fn, nil)
}

func arm64RawPrivateFrameUnexposedForTransport(fn Func, transport *arm64PrivateFrameTransport) bool {
	frame := arm64SourceGoFrame(fn)
	if !frame.present || frame.restoresLink || !arm64SourceFrameFlagsKnown(fn) || fn.FrameSize < 0 || fn.FrameSize > arm64MaxLocalStackSpan || fn.FrameSize&7 != 0 {
		return false
	}
	text := false
	for _, ins := range fn.Instrs {
		if ins.Op != OpTEXT {
			continue
		}
		_, rest := splitOpcode(ins.Raw)
		parts := strings.Split(rest, ",")
		if len(parts) < 2 || len(parts) > 3 || !strings.HasPrefix(strings.TrimSpace(parts[len(parts)-1]), "$") {
			return false
		}
		size, _, err := parseTEXTFrame(parts)
		if err != nil || size != fn.FrameSize || text {
			return false
		}
		text = true
	}
	if !text {
		return false
	}
	// Register raw PC edges through the exact source-boundary checker. Once
	// these edges are named, use that CFG directly: reclassifying skipped WORDs
	// as anonymous data would change the original executable source role.
	// Unknown words and every dead component still pass the guards below.
	prepared := fn
	rawBranch := false
	for _, ins := range fn.Instrs {
		_, _, relative, err := arm64RawPCRelativeDisplacement(ins)
		if err != nil {
			return false
		}
		if relative {
			// Decode only the control role here. The placeholder is never
			// emitted or trusted as a target; prepare below proves that target.
			decoded, err := decodeARM64RawWordInstructionTarget(ins, "checked_branch_role")
			op := arm64ControlOp(decoded)
			if err != nil || op != "B" && op != OpJMP && !arm64IsConditionalBranch(op) {
				// In particular BAL/BNV, BL and native address producers cannot
				// be mistaken for ordinary fallthrough or known frame branches.
				return false
			}
			rawBranch = true
		}
	}
	if rawBranch {
		var blobs []arm64RawDataBlob
		var err error
		prepared, blobs, err = prepareARM64RawPCRelative(fn)
		if err != nil || len(blobs) != 0 {
			return false
		}
	}
	blocks := arm64SplitBlocks(prepared)
	indices := make(map[string]int, len(blocks))
	for index, block := range blocks {
		indices[block.name] = index
	}
	before := make([]*arm64RawPrivateFrameState, len(blocks))
	queue := []int{}
	queued := make([]bool, len(blocks))
	propagate := func(index int, state *arm64RawPrivateFrameState) bool {
		if index < 0 || index >= len(blocks) {
			return false
		}
		changed := false
		if before[index] == nil {
			before[index], changed = state.clone(), true
		} else {
			old := before[index]
			// Do not merge distinct physical SP values into a guessed frame.
			if old.sp != state.sp {
				return false
			}
			changed = old.regs.merge(state.regs)
			spillUnion := make(map[int64]arm64PrivateFrameAddress)
			for offset, value := range old.spills {
				if other, ok := state.spills[offset]; !ok || value != other {
					value = arm64PrivateFrameAddress{}
				}
				spillUnion[offset] = value
			}
			for offset := range state.spills {
				if _, ok := old.spills[offset]; !ok {
					spillUnion[offset] = arm64PrivateFrameAddress{}
				}
			}
			if !reflect.DeepEqual(old.spills, spillUnion) {
				old.spills, changed = spillUnion, true
			}
			changed = old.fixed.merge(state.fixed) || changed
		}
		if changed && !queued[index] {
			queue, queued[index] = append(queue, index), true
		}
		return true
	}
	// Include dead source components: later normalization cannot erase an escape.
	for seed := range blocks {
		if before[seed] != nil {
			continue
		}
		entry := &arm64RawPrivateFrameState{
			regs: arm64PrivateFrameAddresses{"R18": {}, "R28": {}, "R29": {}},
			// The Go prologue itself saves the incoming frame pointer here.
			// Reading it must not silently turn its unknown may-frame value
			// into an ordinary external scalar.
			spills: map[int64]arm64PrivateFrameAddress{-8: {}},
			fixed: &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true})},
				memory: make(map[string]arm64ControlValue), unexposedSP: true,
			},
		}
		for _, fixed := range arm64RawZeroFixedEntry[:2] {
			entry.fixed.regs[fixed.reg] = arm64ControlFromMap(map[string]bool{fixed.token: true})
		}
		if arm64SourceUsesR20(fn) {
			entry.regs["R20"] = arm64PrivateFrameAddress{}
		}
		r20Transport := arm64SourceFrameR20(fn) && arm64SourceFrameR20Transport(fn, transport)
		if arm64SourceFrameAutosize(fn.FrameSize) > 0xf0 {
			entry.regs["R20"] = arm64PrivateFrameAddress{
				exact: r20Transport,
			}
			if entry.regs["R20"].exact {
				entry.fixed.regs["R20"] = arm64ControlFromMap(map[string]bool{"sp:0": true})
				entry.fixed.regs["R30"] = arm64ControlFromMap(map[string]bool{"label:entry-lr": true})
				entry.fixed.memory["sp:0"] = entry.fixed.regs["R30"]
			}
		}
		if !propagate(seed, entry) {
			return false
		}
		for next := 0; next < len(queue); next++ {
			index := queue[next]
			queued[index] = false
			state := before[index].clone()
			terminated := false
			for _, original := range blocks[index].instrs {
				ins := arm64ControlDecode(original)
				op := arm64ControlOp(ins)
				if op == OpRET {
					// Only a source Go RET consumes its implicit frame pointer.
					// The separate continuation proof still checks SP and LR.
					if !arm64RawPrivateSourceRET(original) || state.sp != 0 {
						return false
					}
					delete(state.regs, "R29")
					if r20Transport {
						// A source leaf RET uses R30, but Go's traceback still
						// owns the automatic saved-link cell. Its exact identity
						// cannot be discarded merely because LLVM returns natively.
						link := state.fixed.source(Operand{Kind: OpMem, Mem: MemRef{Base: SP}}, false)
						if arm64ControlCount(link) != 1 || !arm64ControlHas(link, "label:entry-lr") {
							return false
						}
					}
					for _, fixed := range arm64RawZeroFixedEntry[:2] {
						value := arm64ControlRead(state.fixed.regs, fixed.reg)
						if arm64ControlCount(value) != 1 || !arm64ControlHas(value, fixed.token) {
							return false
						}
						delete(state.regs, fixed.reg)
					}
					if len(state.regs) != 0 && (!r20Transport || !state.regs.bounded(fn.FrameSize) ||
						!transport.consume(original, state.regs, false)) {
						return false
					}
					terminated = true
					break
				}
				switch op {
				case "CALL", "BL", "BLR", "ADR", "ADRP", "BAL", "BNV", arm64RawDataOp:
					return false
				}
				if !state.transfer(original, ins, fn.FrameSize) {
					return false
				}
				if !state.fixed.transferStructureMemory(original) {
					state.fixed.transfer(ins, op, strings.HasSuffix(string(ins.Op), ".P"), nil)
				}
				if op == "B" || op == "JMP" || arm64IsConditionalBranch(op) {
					if len(ins.Args) == 0 {
						return false
					}
					name, ok := arm64BranchTarget(ins.Args[len(ins.Args)-1])
					target, local := indices[name]
					if !ok || !local || !propagate(target, state) {
						return false
					}
					if arm64IsConditionalBranch(op) && !propagate(index+1, state) {
						return false
					}
					terminated = true
					break
				}
			}
			if !terminated && !propagate(index+1, state) {
				return false
			}
		}
		queue = queue[:0]
	}
	return true
}

func arm64RawPrivateSourceRET(ins Instr) bool {
	if ins.Op != OpRET {
		return false
	}
	if len(ins.Args) == 0 {
		return true
	}
	if len(ins.Args) != 1 {
		return false
	}
	arg := ins.Args[0]
	return arg.Kind == OpReg && arg.Reg == "R30" ||
		arg.Kind == OpMem && arg.Mem.Base == "R30" && arg.Mem.Index == "" && arg.Mem.Off == 0 && arg.Mem.OffRaw == ""
}

func (s *arm64RawPrivateFrameState) transfer(original, ins Instr, frameSize int64) bool {
	op := arm64ControlOp(ins)
	if immediate, handled, err := parseARM64GPImmediateForm(op, ins); handled {
		if err != nil {
			return false
		}
		if immediate.scratch && !s.assign("R27", arm64PrivateFrameAddress{}, false) {
			return false
		}
	}
	for _, arg := range ins.Args {
		if arg.Kind == OpFPAddr {
			return false
		}
	}
	if form, handled, err := parseARM64StructureMemory(original); handled {
		return err == nil && s.structureMemory(form, frameSize)
	}
	if op == OpWORD {
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
			return false
		}
		effects, known := arm64RawContinuationEffectsForWord(uint32(ins.Args[0].Imm))
		if !known || effects.stores || effects.readsSP {
			return false
		}
		for reg := range s.regs {
			index, gp := arm64StackIndex(reg)
			if !gp || effects.gpReads&(1<<uint(index)) != 0 || effects.gpWrites&(1<<uint(index)) != 0 {
				return false
			}
		}
		return true
	}
	if form, handled, err := parseARM64RegisterAddressForm(op, ins); handled {
		if err != nil || form.usesScratch {
			return false
		}
		value, present := s.address(form.base)
		if present {
			var ok bool
			value, ok = arm64PrivateFrameOffset(value, form.offset)
			if !ok {
				return false
			}
		}
		return s.assign(form.destination, value, present)
	}
	if form, ok := arm64RawPrivateMemory(ins); ok {
		return s.memory(form, frameSize)
	}
	if op == "MOVD" && string(ins.Op) == "MOVD" && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		src := ins.Args[0]
		if src.Kind == OpReg {
			value, present := s.address(src.Reg)
			return s.assign(ins.Args[1].Reg, value, present)
		}
		if src.Kind == OpImm && src.ImmRaw == "" || src.Kind == OpFP || src.Kind == OpSym && strings.HasSuffix(src.Sym, "(SB)") {
			return s.assign(ins.Args[1].Reg, arm64PrivateFrameAddress{}, false)
		}
	}
	if (op == "ADD" || op == "SUB") && string(ins.Op) == string(op) && len(ins.Args) >= 2 && len(ins.Args) <= 3 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" && ins.Args[1].Kind == OpReg && ins.Args[len(ins.Args)-1].Kind == OpReg {
		value, present := s.address(ins.Args[1].Reg)
		if present {
			offset := ins.Args[0].Imm
			if op == "SUB" {
				if offset == int64(-1<<63) {
					return false
				}
				offset = -offset
			}
			var ok bool
			value, ok = arm64PrivateFrameOffset(value, offset)
			if !ok {
				return false
			}
		}
		return s.assign(ins.Args[len(ins.Args)-1].Reg, value, present)
	}
	if form, handled, err := parseARM64GPDataForm(op, ins); handled {
		if err != nil {
			return false
		}
		for _, reg := range arm64GPDataInputRegisters(form) {
			if _, frame := s.address(reg); frame {
				return false
			}
		}
		for _, reg := range arm64GPDataOutputRegisters(form) {
			if !s.assign(reg, arm64PrivateFrameAddress{}, false) {
				return false
			}
		}
		return true
	}
	// No unrecognized transform can kill a may-frame register. Its explicit
	// operands must not consume an address; native/implicit-effect forms are
	// excluded even when no temporary happens to be live.
	switch op {
	case "DWORD", "BYTE", "QUAD", "SVC", "HVC", "SMC", "BRK", "HLT", "DCPS1", "DCPS2", "DCPS3", "DRPS", "ERET", "UNDEF", "MRS", "MSR", "SYS", "SYSL", "DC", "IC", "TLBI":
		return false
	}
	for _, arg := range ins.Args {
		if arg.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(arg.Sym), "$") {
			if strings.Contains(arg.Sym, "(FP)") {
				return false
			}
			if memory, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$"))); ok {
				if _, frame := s.address(memory.Base); frame {
					return false
				}
				if _, frame := s.address(memory.Index); frame {
					return false
				}
			}
		}
		regs := []Reg{arg.Reg, arg.ShiftReg, arg.Mem.Base, arg.Mem.Index}
		regs = append(regs, arg.RegList...)
		for _, reg := range regs {
			if _, frame := s.address(reg); frame {
				return false
			}
		}
		if arg.Kind == OpMem || arg.Kind == OpFP || arg.Kind == OpFPAddr {
			return false // Unknown memory direction/width is not an external store.
		}
	}
	if original.Op == OpWORD {
		word := uint32(original.Args[0].Imm)
		// Validated ordinary data-processing encodings have explicit GP/FP
		// operands. Other classes need a separately typed effect contract.
		return word&0x1c000000 == 0x10000000 || word&0x0e000000 == 0x0a000000 || word&0x0e000000 == 0x0e000000
	}
	return true
}

type arm64RawPrivateMemoryForm struct {
	memory       Operand
	registers    []Reg
	elementBytes int64
	store, gp    bool
	pre, post    bool
	scratch      *arm64ScalarMemoryForm
}

func arm64RawPrivateScalarBytes(op Op) int64 {
	switch op {
	case "MOVB", "MOVBU", "MOVBW":
		return 1
	case "MOVH", "MOVHU", "MOVHW":
		return 2
	case "MOVW", "MOVWU", "FMOVS":
		return 4
	case "MOVD", "FMOVD":
		return 8
	case "FMOVQ":
		return 16
	}
	return 0
}

func arm64RawPrivatePairBytes(op Op) int64 {
	switch op {
	case "LDPW", "LDPSW", "STPW", "FLDPS", "FSTPS":
		return 4
	case "LDP", "STP", "FLDPD", "FSTPD":
		return 8
	case "FLDPQ", "FSTPQ":
		return 16
	}
	return 0
}

func arm64RawPrivateMemory(ins Instr) (arm64RawPrivateMemoryForm, bool) {
	op := arm64ControlOp(ins)
	form := arm64RawPrivateMemoryForm{}
	if scalar, handled, err := parseARM64ScalarMemoryForm(op, ins); handled {
		if err != nil {
			return form, false
		}
		form.memory, form.registers = scalar.memory, []Reg{scalar.data}
		form.elementBytes, form.store, form.gp = int64(scalar.bits/8), scalar.store, true
		form.pre, form.post = scalar.pre, scalar.post
		if scalar.scratch {
			form.scratch = &scalar
		}
		return form, true
	}
	suffix := strings.TrimPrefix(string(ins.Op), string(op))
	if suffix != "" && suffix != ".W" && suffix != ".P" || len(ins.Args) != 2 {
		return form, false
	}
	form.pre, form.post = suffix == ".W", suffix == ".P"
	width := arm64RawPrivateScalarBytes(op)
	if width != 0 {
		value := ins.Args[1]
		form.memory = ins.Args[0]
		if ins.Args[1].Kind == OpMem || ins.Args[1].Kind == OpFP || ins.Args[1].Kind == OpSym {
			value, form.memory, form.store = ins.Args[0], ins.Args[1], true
		}
		form.gp = !strings.HasPrefix(string(op), "F")
		// Go obj7.progedit's complete zrReplace MOVB/H/W/D family maps
		// a resolved literal $0 source to ZR, including its unsigned aliases.
		if form.store && form.gp && value.Kind == OpImm && value.Imm == 0 && value.ImmRaw == "" {
			value = Operand{Kind: OpReg, Reg: ZR}
		}
		if value.Kind != OpReg {
			return form, false
		}
		if form.gp && !isARM64GeneralOrZeroReg(value.Reg) {
			return form, false
		}
		if !form.gp {
			if _, ok := arm64ParseFReg(value.Reg); !ok {
				return form, false
			}
		}
		form.elementBytes, form.registers = width, []Reg{value.Reg}
	} else {
		width = arm64RawPrivatePairBytes(op)
		if width == 0 {
			return form, false
		}
		form.store = op == "STP" || op == "STPW" || strings.HasPrefix(string(op), "FSTP")
		pair := ins.Args[1]
		form.memory = ins.Args[0]
		if form.store {
			pair, form.memory = ins.Args[0], ins.Args[1]
		}
		if pair.Kind != OpRegList || len(pair.RegList) != 2 {
			return form, false
		}
		form.gp = !strings.HasPrefix(string(op), "F")
		for _, reg := range pair.RegList {
			if form.gp && !isARM64GeneralOrZeroReg(reg) {
				return form, false
			}
			if !form.gp {
				if _, ok := arm64ParseFReg(reg); !ok {
					return form, false
				}
			}
		}
		form.elementBytes, form.registers = width, pair.RegList
	}
	if !form.store && len(form.registers) == 2 && form.registers[0] == form.registers[1] {
		return form, false
	}
	// $offset(base) and $symbol(SB) materialize an address, not memory
	// contents. Their own typed grammar must retain source provenance and
	// Go's implicit R27 literal scratch effect before any memory transfer.
	if form.memory.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(form.memory.Sym), "$") {
		return form, false
	}
	if form.pre || form.post {
		if form.memory.Kind != OpMem || form.memory.Mem.Index != "" || form.memory.Mem.OffRaw != "" {
			return form, false
		}
		// ARM writeback with a transferred GP base register is constrained
		// unpredictable. Never derive a proof from a guessed update order.
		if form.gp {
			for _, reg := range form.registers {
				if reg == form.memory.Mem.Base {
					return form, false
				}
			}
		}
	}
	return form, form.memory.Kind == OpMem || form.memory.Kind == OpFP || form.memory.Kind == OpSym
}

func (s *arm64RawPrivateFrameState) memory(form arm64RawPrivateMemoryForm, frameSize int64) bool {
	address, local := arm64PrivateFrameAddress{}, false
	if form.memory.Kind == OpMem {
		mem := form.memory.Mem
		if _, frame := s.address(mem.Index); frame {
			return false
		}
		address, local = s.address(mem.Base)
		if local && (!address.exact || mem.Index != "" || mem.OffRaw != "") {
			return false
		}
		if local {
			offset := mem.Off
			if form.post {
				offset = 0
			}
			var ok bool
			address, ok = arm64PrivateFrameOffset(address, offset)
			low := s.sp
			if form.pre && mem.Base != "" && arm64StackReg(mem.Base) {
				low = address.offset
			}
			if low > -8 {
				low = -8 // Go's implicit saved-FP cell, not a general red zone.
			}
			width := form.elementBytes * int64(len(form.registers))
			if !ok || low < -arm64MaxLocalStackSpan || address.offset < low || address.offset > frameSize+8-width {
				return false
			}
		}
	}
	if form.scratch != nil {
		value, frame := s.regs.scalarMemoryScratch(*form.scratch)
		if !s.assign("R27", value, frame) {
			return false
		}
	}
	for index, reg := range form.registers {
		offset := address.offset + int64(index)*form.elementBytes
		if form.store {
			value, frame := s.address(reg)
			if frame && (!local || !form.gp || form.elementBytes != 8) {
				return false
			}
			if local {
				for cell := range s.spills {
					if offset < cell+8 && cell < offset+form.elementBytes {
						if offset > cell || offset+form.elementBytes < cell+8 {
							return false // A partial overwrite cannot wash a spill clean.
						}
						delete(s.spills, cell)
					}
				}
				if frame {
					s.spills[offset] = value
				}
			}
		} else {
			value, frame := arm64PrivateFrameAddress{}, false
			if local {
				matches := 0
				for cell, stored := range s.spills {
					if offset < cell+8 && cell < offset+form.elementBytes {
						if !form.gp {
							return false // Do not lose a frame address in the SIMD bank.
						}
						matches++
						value, frame = arm64PrivateFrameAddress{}, true
						if matches == 1 && cell == offset && form.elementBytes == 8 {
							value = stored
						}
					}
				}
			}
			if form.gp && !s.assign(reg, value, frame) {
				return false
			}
		}
	}
	if form.pre || form.post {
		if form.memory.Kind != OpMem || form.memory.Mem.Index != "" || form.memory.Mem.OffRaw != "" {
			return false
		}
		base := form.memory.Mem.Base
		value, frame := s.address(base)
		if frame {
			var ok bool
			value, ok = arm64PrivateFrameOffset(value, form.memory.Mem.Off)
			if !ok || !s.assign(base, value, true) {
				return false
			}
		}
	}
	return true
}
