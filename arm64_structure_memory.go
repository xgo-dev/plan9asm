package plan9asm

import (
	"fmt"
	"strings"
)

// One operand grammar supplies lowering and both frame/control proofs. The
// extent is the encoded transfer, not the width of LLVM's vector backing or
// (for VLD2-4) necessarily the number of registers written in Go's C_LIST.
type arm64StructureMemoryForm struct {
	op              Op
	memory          Operand
	registers       []Reg
	arrangement     arm64VectorArrangement
	load, replicate bool
	lane            int // -1 means a whole-register or replicate transfer
	post            bool
	increment       int64
	index           Reg
}

func (f arm64StructureMemoryForm) width() int64 {
	width := int64(f.arrangement.elementBits / 8 * len(f.registers))
	if f.lane < 0 && !f.replicate {
		width *= int64(f.arrangement.lanes)
	}
	return width
}

func parseARM64StructureMemory(ins Instr) (form arm64StructureMemoryForm, handled bool, err error) {
	if ins.Op == OpWORD && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
		word := uint32(ins.Args[0].Imm)
		if raw, valid := decodeARM64RawStructureLane(word); valid {
			return raw.memoryForm(), true, nil
		}
		if word&0xbf000000 == 0x0c000000 || word&0xbf000000 == 0x0d000000 {
			decoded, err := decodeARM64RawWordInstruction(ins)
			if err != nil {
				return form, true, err
			}
			return parseARM64StructureMemory(decoded)
		}
	}
	op := arm64ControlOp(ins)
	count, handled := arm64StructureLoadStoreCounts[op]
	if !handled {
		return form, false, nil
	}
	form.op, form.load, form.replicate, form.lane = op, strings.HasPrefix(string(op), "VLD"), strings.HasSuffix(string(op), "R"), -1
	suffix := strings.TrimPrefix(string(ins.Op), string(op))
	if (suffix != "" && suffix != ".P") || len(ins.Args) != 2 {
		return form, true, fmt.Errorf("arm64 %s requires memory/vector operands and only optional .P: %q", op, ins.Raw)
	}
	form.post = suffix == ".P"
	vector := ins.Args[0]
	form.memory = ins.Args[1]
	if form.load {
		form.memory, vector = ins.Args[0], ins.Args[1]
	}
	if form.memory.Kind != OpMem {
		return form, true, fmt.Errorf("arm64 %s requires a register-based memory operand: %q", op, ins.Raw)
	}

	written := 1
	if (op == "VLD1" || op == "VST1") && vector.Kind == OpReg {
		kind, lane, valid := arm64ParseVRegLane(vector.Reg)
		first, vectorOK := arm64ParseVReg(vector.Reg)
		if !valid || !vectorOK {
			return form, true, fmt.Errorf("arm64 %s requires a valid vector lane: %q", op, ins.Raw)
		}
		bits := map[byte]int{'B': 8, 'H': 16, 'S': 32, 'D': 64}[kind]
		form.arrangement = arm64VectorArrangement{elementBits: bits, lanes: 128 / bits}
		form.registers, form.lane = []Reg{Reg(fmt.Sprintf("V%d", first))}, lane
	} else {
		if vector.Kind != OpRegList || len(vector.RegList) < 1 || len(vector.RegList) > 4 {
			return form, true, fmt.Errorf("arm64 %s requires one through four arranged vector registers: %q", op, ins.Raw)
		}
		listed := vector.RegList
		arrangement, valid := parseARM64VectorArrangement(listed[0])
		first, vectorOK := arm64ParseVReg(listed[0])
		if !valid || !vectorOK {
			return form, true, fmt.Errorf("arm64 %s requires an arranged vector list: %q", op, ins.Raw)
		}
		for i, reg := range listed {
			other, valid := parseARM64VectorArrangement(reg)
			index, vectorOK := arm64ParseVReg(reg)
			if !valid || !vectorOK || other != arrangement || index != (first+i)%32 {
				return form, true, fmt.Errorf("arm64 %s requires consecutive same-arrangement registers: %q", op, ins.Raw)
			}
		}
		written, form.arrangement = len(listed), arrangement
		if op == "VLD1" || op == "VST1" {
			count = written
		} else if !form.replicate && arrangement.elementBits == 64 && arrangement.lanes == 1 {
			// Go's C_LIST encoder accepts Q=0/size=3 for LD/ST2-4,
			// but the raw architectural decoder correctly rejects it.
			return form, true, fmt.Errorf("%w: ARM64 %s D1 has a reserved original Go structure encoding: %q", ErrProbeNeedsContext, op, ins.Raw)
		}
		for i := 0; i < count; i++ {
			form.registers = append(form.registers, Reg(fmt.Sprintf("V%d.%s", (first+i)%32, arm64VectorArrangementName(arrangement))))
		}
	}

	mem := form.memory.Mem
	if mem.Sym != "" || mem.OffRaw != "" || mem.IndexExt != "" || (mem.Scale != 0 && mem.Scale != 1) ||
		(!isARM64GeneralOrZeroReg(mem.Base) && !arm64StackReg(mem.Base)) {
		return form, true, fmt.Errorf("arm64 %s requires a plain GP/SP base: %q", op, ins.Raw)
	}
	if mem.Base == ZR || arm64StackReg(mem.Base) {
		mem.Base = SP // encoding Rn=31 selects SP, not the zero register.
	}
	if !form.post {
		if mem.Index != "" || form.lane < 0 && mem.Off != 0 {
			return form, true, fmt.Errorf("arm64 %s non-post form requires (Rbase): %q", op, ins.Raw)
		}
		// Go cases 96/97 accept nonzero C_LOREG for a no-post lane,
		// but set Rm=31, which is reserved in that encoding. Do not turn
		// the original source into a valid zero-offset access silently.
		if form.lane >= 0 && mem.Off != 0 {
			return form, true, fmt.Errorf("%w: ARM64 %s no-post lane displacement has a reserved original Go Rm encoding: %q", ErrProbeNeedsContext, op, ins.Raw)
		}
	} else if mem.Index != "" {
		if mem.Off != 0 || !isARM64GeneralOrZeroReg(mem.Index) {
			return form, true, fmt.Errorf("arm64 %s register post-increment requires (Rbase)(Rindex): %q", op, ins.Raw)
		}
		if mem.Index != ZR {
			form.index = mem.Index
		}
	} else {
		expected := form.width()
		if form.lane < 0 {
			expected = int64(written * form.arrangement.elementBits / 8)
			if !form.replicate {
				expected *= int64(form.arrangement.lanes)
			}
		}
		if form.lane >= 0 && mem.Off == 0 || mem.Off != 0 && mem.Off != expected ||
			mem.Off != 0 && form.lane < 0 && op != "VLD1" && op != "VST1" && written != count {
			return form, true, fmt.Errorf("arm64 %s invalid immediate post-increment: %q", op, ins.Raw)
		}
	}
	if form.post && form.index == "" {
		form.increment = form.width()
	}
	// The access itself always uses the original base. A post displacement
	// describes writeback, not an address offset.
	mem.Off, mem.Index = 0, ""
	form.memory.Mem = mem
	return form, true, nil
}

func (raw arm64RawStructureLane) memoryForm() arm64StructureMemoryForm {
	base := Reg(fmt.Sprintf("R%d", raw.base))
	if raw.base == 31 {
		base = SP
	}
	form := arm64StructureMemoryForm{
		memory: Operand{Kind: OpMem, Mem: MemRef{Base: base}},
		load:   raw.load, lane: raw.lane, post: raw.post,
		arrangement: arm64VectorArrangement{elementBits: raw.elementBits, lanes: 128 / raw.elementBits},
	}
	for i := 0; i < raw.count; i++ {
		form.registers = append(form.registers, Reg(fmt.Sprintf("V%d", (raw.firstRegister+i)%32)))
	}
	if raw.post {
		if raw.postRegister == 31 {
			form.increment = form.width()
		} else {
			form.index = Reg(fmt.Sprintf("R%d", raw.postRegister))
		}
	}
	return form
}

func (c *arm64Ctx) structureAddress(form arm64StructureMemoryForm) (address, increment string, err error) {
	address, err = c.loadReg(form.memory.Mem.Base)
	if err != nil || !form.post {
		return address, "", err
	}
	if form.index != "" {
		increment, err = c.loadReg(form.index)
	} else {
		increment = c.imm64(form.increment)
	}
	return address, increment, err
}
