package plan9asm

import "strings"

// A local affine address is not an escape. Keep a separate may-frame lattice:
// unlike continuation values, a mixed/different-offset join must never collapse
// to an ordinary external pointer. Only a full known overwrite kills it.
type arm64PrivateFrameAddress struct {
	offset int64
	exact  bool
}

type arm64PrivateFrameAddresses map[Reg]arm64PrivateFrameAddress

func (state arm64PrivateFrameAddresses) clone() arm64PrivateFrameAddresses {
	next := make(arm64PrivateFrameAddresses, len(state))
	for reg, value := range state {
		next[reg] = value
	}
	return next
}

func (state arm64PrivateFrameAddresses) merge(other arm64PrivateFrameAddresses) bool {
	changed := false
	for reg, incoming := range other {
		old, present := state[reg]
		if !present || old != incoming {
			if !present || old.exact {
				state[reg], changed = arm64PrivateFrameAddress{}, true
			}
		}
	}
	for reg, old := range state {
		if _, present := other[reg]; !present && old.exact {
			state[reg], changed = arm64PrivateFrameAddress{}, true
		}
	}
	return changed
}

func (state arm64PrivateFrameAddresses) address(reg Reg) (arm64PrivateFrameAddress, bool) {
	if arm64StackReg(reg) {
		return arm64PrivateFrameAddress{exact: true}, true
	}
	value, present := state[reg]
	return value, present
}

func (state arm64PrivateFrameAddresses) assign(reg Reg, value arm64PrivateFrameAddress, present bool) bool {
	if arm64StackReg(reg) || !isARM64GeneralOrZeroReg(reg) {
		return false
	}
	if reg != ZR {
		if present {
			state[reg] = value
		} else {
			delete(state, reg)
		}
	}
	return true
}

func arm64PrivateFrameOffset(value arm64PrivateFrameAddress, off int64) (arm64PrivateFrameAddress, bool) {
	if !value.exact || off > 0 && value.offset > int64(1<<63-1)-off || off < 0 && value.offset < int64(-1<<63)-off {
		return arm64PrivateFrameAddress{}, false
	}
	return arm64PrivateFrameAddress{offset: value.offset + off, exact: true}, true
}

// Reuse source basic blocks and branch grammar. Calls with any live temporary
// frame address are conservatively rejected: this source-only proof cannot
// guess a callee's transport. Audited register-only helper rewrites are checked
// before and after coalescing; they cannot form an address from an absent one.
func arm64PrivateFrameReadProof(fn Func) bool {
	return arm64PrivateFrameReadProofForTransport(fn, nil)
}

func arm64PrivateFrameReadProofForTransport(fn Func, transport *arm64PrivateFrameTransport) bool {
	if arm64PrivateFrameReadExactProof(fn, transport) {
		return true
	}
	_, bounded := arm64PrivateDataProof(fn, transport)
	return bounded
}

func arm64PrivateFrameReadExactProof(fn Func, transport *arm64PrivateFrameTransport) bool {
	blocks := arm64SplitBlocks(fn)
	indices := make(map[string]int, len(blocks))
	for index, block := range blocks {
		indices[block.name] = index
	}
	before := make([]arm64PrivateFrameAddresses, len(blocks))
	queue := []int{}
	queued := make([]bool, len(blocks))
	propagate := func(index int, state arm64PrivateFrameAddresses) {
		if index < 0 || index >= len(blocks) {
			return
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
	}
	// Check even dead source components; a dead escape cannot erase the original
	// whole-source contract during later normalization/helper rewriting.
	for seed := range blocks {
		if before[seed] != nil {
			continue
		}
		propagate(seed, arm64PrivateFrameAddresses{})
		for next := 0; next < len(queue); next++ {
			index := queue[next]
			queued[index] = false
			state := before[index].clone()
			if transport != nil && !state.bounded(fn.FrameSize) {
				return false
			}
			terminated := false
			for ii, original := range blocks[index].instrs {
				ins := arm64StackInstruction(original)
				op := arm64ControlOp(ins)
				if op == "SVC" && transport != nil && transport.nanosleep != nil &&
					transport.nanosleep.matchesSource(fn, transport.entry, transport.nanosleep.target) {
					input, present := transport.nanosleep.inputs[[2]int{index, ii}]
					address, frame := state.address("R0")
					if !present || !frame || !address.exact || address.offset != input.span.low {
						return false
					}
					state.assign("R0", arm64PrivateFrameAddress{}, false)
					continue
				}
				if op == "CALL" || op == "BL" || op == OpRET {
					if len(state) != 0 {
						if transport == nil || !transport.consume(ins, state, strings.HasSuffix(fn.Sym, "<ABIInternal>")) {
							return false
						}
					}
					if op != OpRET {
						propagate(index+1, state)
					}
					terminated = true
					break
				}
				if !state.transfer(ins, fn.FrameSize) {
					return false
				}
				if transport != nil && !state.bounded(fn.FrameSize) {
					return false
				}
				if op == "B" || op == "JMP" || arm64IsConditionalBranch(op) {
					if len(ins.Args) != 0 {
						if name, ok := arm64BranchTarget(ins.Args[len(ins.Args)-1]); ok {
							if target, present := indices[name]; present {
								propagate(target, state)
							}
						}
					}
					if arm64IsConditionalBranch(op) {
						propagate(index+1, state)
					}
					terminated = true
					break
				}
			}
			if !terminated {
				propagate(index+1, state)
			}
		}
		queue = queue[:0]
	}
	return true
}

// The extended transport proof rejects forming a known out-of-allocation
// temporary. Mixed joins retain may-frame taint: they cannot authorize a
// memory access or result/argument transport, but an unused temporary need
// not be zeroed solely for a terminator.
func (state arm64PrivateFrameAddresses) bounded(frameSize int64) bool {
	if frameSize < 0 || frameSize > int64(1<<63-1)-8 {
		return len(state) == 0
	}
	for _, value := range state {
		if value.exact && (value.offset < 0 || value.offset > frameSize+8) {
			return false
		}
	}
	return true
}

func (state arm64PrivateFrameAddresses) transfer(ins Instr, frameSize int64) bool {
	op := arm64ControlOp(ins)
	if immediate, handled, err := parseARM64GPImmediateForm(op, ins); handled {
		if err != nil {
			return false
		}
		if immediate.scratch && !state.assign("R27", arm64PrivateFrameAddress{}, false) {
			return false
		}
	}
	if form, handled, err := parseARM64ScalarMemoryForm(op, ins); handled {
		return err == nil && state.scalarMemory(form, frameSize)
	}
	switch op {
	case "SVC", "HVC", "SMC", "BRK", "HLT", "DCPS1", "DCPS2", "DCPS3", "DRPS", "ERET", "UNDEF":
		// Exception/syscall transport is not an ordinary typed Go call. It
		// must not observe a temporary through an implicit native GP input.
		return false
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpMem {
			continue
		}
		_, baseFrame := state.address(arg.Mem.Base)
		_, indexFrame := state.address(arg.Mem.Index)
		writeback := strings.HasSuffix(string(ins.Op), ".P") || strings.HasSuffix(string(ins.Op), ".W")
		if indexFrame || baseFrame && (arg.Mem.Index != "" || writeback) {
			return false
		}
	}
	if form, handled, err := parseARM64RegisterAddressForm(op, ins); handled {
		if err != nil || form.usesScratch {
			return false
		}
		value, present := state.address(form.base)
		if present {
			var ok bool
			value, ok = arm64PrivateFrameOffset(value, form.offset)
			if !ok {
				return false
			}
		}
		return state.assign(form.destination, value, present)
	}
	if op == "MOVD" && string(ins.Op) == "MOVD" && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		src := ins.Args[0]
		if src.Kind == OpReg {
			value, present := state.address(src.Reg)
			return state.assign(ins.Args[1].Reg, value, present)
		}
		literal := src.Kind == OpImm && src.ImmRaw == ""
		symbol := false
		if src.Kind == OpSym && strings.HasSuffix(src.Sym, "(SB)") {
			_, _, symbol = parseSBRef(strings.TrimPrefix(src.Sym, "$"))
		}
		if literal || symbol || src.Kind == OpFP {
			return state.assign(ins.Args[1].Reg, arm64PrivateFrameAddress{}, false)
		}
	}
	if (op == "ADD" || op == "SUB") && string(ins.Op) == string(op) && len(ins.Args) >= 2 && len(ins.Args) <= 3 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" && ins.Args[1].Kind == OpReg && ins.Args[len(ins.Args)-1].Kind == OpReg {
		value, present := state.address(ins.Args[1].Reg)
		if present {
			off := ins.Args[0].Imm
			if op == "SUB" {
				if off == int64(-1<<63) {
					return false
				}
				off = -off
			}
			var ok bool
			value, ok = arm64PrivateFrameOffset(value, off)
			if !ok {
				return false
			}
			return state.assign(ins.Args[len(ins.Args)-1].Reg, value, true)
		}
	}
	if len(ins.Args) == 2 && ins.Args[0].Kind == OpMem {
		if width, outputs, ok := arm64PrivateFrameLoad(ins); ok {
			memory := ins.Args[0].Mem
			if _, indexedFrame := state.address(memory.Index); indexedFrame {
				return false
			}
			value, frame := state.address(memory.Base)
			if frame {
				value, ok = arm64PrivateFrameOffset(value, memory.Off)
				if !ok || memory.Index != "" || memory.OffRaw != "" || value.offset < 0 || frameSize < 0 || frameSize > int64(1<<63-1)-8 || value.offset > frameSize+8-width {
					return false
				}
			}
			for _, reg := range outputs {
				if !state.assign(reg, arm64PrivateFrameAddress{}, false) {
					return false
				}
			}
			return true
		}
	}
	if form, handled, err := parseARM64GPDataForm(op, ins); handled {
		if err != nil {
			return false
		}
		for _, reg := range arm64GPDataInputRegisters(form) {
			if _, frame := state.address(reg); frame {
				return false
			}
		}
		for _, reg := range arm64GPDataOutputRegisters(form) {
			if !state.assign(reg, arm64PrivateFrameAddress{}, false) {
				return false
			}
		}
		return true
	}
	// Unknown effects cannot wash a tainted register clean. Source-relative SP
	// memory itself is not address transport and remains subject to the separate
	// continuation-cell overlap proof; aliases/indexes do not get that exemption.
	for _, arg := range ins.Args {
		registers := []Reg{arg.Reg, arg.ShiftReg, arg.Mem.Index}
		registers = append(registers, arg.RegList...)
		if arg.Kind == OpMem && !arm64StackReg(arg.Mem.Base) {
			registers = append(registers, arg.Mem.Base)
		}
		for _, reg := range registers {
			if _, frame := state.address(reg); frame {
				return false
			}
		}
	}
	return true
}

func (state arm64PrivateFrameAddresses) scalarMemory(form arm64ScalarMemoryForm, frameSize int64) bool {
	// Validate the old address before changing R27; the store's transfer
	// operand is read after that change, including a base/data R27 overlap.
	if form.memory.Kind == OpMem {
		mem := form.memory.Mem
		if _, indexed := state.address(mem.Index); indexed {
			return false
		}
		value, frame := state.address(mem.Base)
		if frame {
			if mem.Index != "" || form.pre || form.post {
				return false
			}
			if form.store {
				// Preserve the source-relative SP exemption from the coarse
				// proof: its stores still undergo continuation-cell checks.
				// A derived GP address needs the separate per-instruction
				// DATA extent and complete typed transport proof.
				if !arm64StackReg(mem.Base) {
					return false
				}
			} else {
				var ok bool
				value, ok = arm64PrivateFrameOffset(value, mem.Off)
				if !ok || !value.exact || value.offset < 0 || frameSize < 0 ||
					frameSize > int64(1<<63-1)-8 || value.offset > frameSize+8-int64(form.bits/8) {
					return false
				}
			}
		}
	}
	if form.scratch {
		scratch, private := state.scalarMemoryScratch(form)
		if !state.assign("R27", scratch, private) {
			return false
		}
	}
	if form.store {
		_, private := state.address(form.data)
		return !private
	}
	return state.assign(form.data, arm64PrivateFrameAddress{}, false)
}

func (state arm64PrivateFrameAddresses) scalarMemoryScratch(form arm64ScalarMemoryForm) (arm64PrivateFrameAddress, bool) {
	if !form.scratchAddress || form.scratchBase == "" {
		return arm64PrivateFrameAddress{}, false
	}
	value, frame := state.address(form.scratchBase)
	if frame {
		if form.scratchKnown {
			if next, ok := arm64PrivateFrameOffset(value, form.scratchOffset); ok {
				return next, true
			}
		}
		return arm64PrivateFrameAddress{}, true // Preserve may-frame; lose bounds.
	}
	return value, false
}

// The accepted subset is read-only, non-writeback, with a literal displacement
// and exact destination bank/width. Ordinary lowering still validates the full
// Go operand grammar; no unrecognized operation is treated as a load or kill.
func arm64PrivateFrameLoad(ins Instr) (int64, []Reg, bool) {
	if strings.Contains(string(ins.Op), ".") || len(ins.Args) != 2 || ins.Args[0].Kind != OpMem {
		return 0, nil, false
	}
	op, dst := ins.Op, ins.Args[1]
	width := map[Op]int64{"MOVB": 1, "MOVBU": 1, "MOVH": 2, "MOVHU": 2, "MOVW": 4, "MOVWU": 4, "MOVD": 8}[op]
	if width != 0 && dst.Kind == OpReg && isARM64GeneralOrZeroReg(dst.Reg) {
		return width, []Reg{dst.Reg}, true
	}
	width = map[Op]int64{"FMOVS": 4, "FMOVD": 8, "FMOVQ": 16}[op]
	if width != 0 && dst.Kind == OpReg {
		if _, ok := arm64ParseFReg(dst.Reg); ok {
			return width, nil, true
		}
	}
	if op == "LDP" || op == "LDPW" || op == "LDPSW" {
		if dst.Kind != OpRegList || len(dst.RegList) != 2 || dst.RegList[0] == dst.RegList[1] ||
			!isARM64GeneralOrZeroReg(dst.RegList[0]) || !isARM64GeneralOrZeroReg(dst.RegList[1]) {
			return 0, nil, false
		}
		width = 16
		if op != "LDP" {
			width = 8
		}
		return width, dst.RegList, true
	}
	width = map[Op]int64{"FLDPS": 8, "FLDPD": 16, "FLDPQ": 32}[op]
	if width != 0 && dst.Kind == OpRegList && len(dst.RegList) == 2 {
		_, first := arm64ParseFReg(dst.RegList[0])
		_, second := arm64ParseFReg(dst.RegList[1])
		if first && second && dst.RegList[0] != dst.RegList[1] {
			return width, nil, true
		}
	}
	if op == "VLD1" && dst.Kind == OpReg {
		kind, _, ok := arm64ParseVRegLane(dst.Reg)
		if ok {
			return map[byte]int64{'B': 1, 'H': 2, 'S': 4, 'D': 8}[kind], nil, true
		}
	}
	if op == "VLD1" && dst.Kind == OpRegList && len(dst.RegList) >= 1 && len(dst.RegList) <= 4 {
		arrangement, ok := parseARM64VectorArrangement(dst.RegList[0])
		first, firstOK := arm64ParseVReg(dst.RegList[0])
		if !ok || !firstOK {
			return 0, nil, false
		}
		for index, reg := range dst.RegList {
			parsed, valid := parseARM64VectorArrangement(reg)
			vector, vectorOK := arm64ParseVReg(reg)
			if !valid || !vectorOK || parsed != arrangement || vector != (first+index)%32 {
				return 0, nil, false
			}
		}
		return int64(len(dst.RegList) * arrangement.lanes * arrangement.elementBits / 8), nil, true
	}
	return 0, nil, false
}
