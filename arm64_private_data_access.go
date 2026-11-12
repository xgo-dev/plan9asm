package plan9asm

import (
	"math"
	"strings"
)

// Half-open envelope of every effective byte written by this instruction on
// every reaching path. This is not an exemption for other stores in the function.
type arm64PrivateDataSpan struct {
	low, end int64
}

func arm64PrivateDataMemory(ins Instr) (arm64RawPrivateMemoryForm, bool) {
	// Share Go's literal-zero alias with the scalar memory grammar. Nonzero,
	// unresolved and floating immediates cannot be interpreted as ZR stores.
	if len(ins.Args) == 2 && ins.Args[0].Kind == OpImm && ins.Args[0].Imm == 0 &&
		ins.Args[0].ImmRaw == "" && !ins.Args[0].ImmIsFloat {
		switch arm64ControlOp(ins) {
		case "MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD":
			ins.Args = append([]Operand(nil), ins.Args...)
			ins.Args[0] = Operand{Kind: OpReg, Reg: ZR}
		}
	}
	return arm64RawPrivateMemory(ins)
}

func (state *arm64PrivateDataState) memory(op Op, form arm64RawPrivateMemoryForm, frameSize int64) (*arm64PrivateDataSpan, bool) {
	var address arm64PrivateDataValue
	local := false
	if form.memory.Kind == OpMem {
		mem := form.memory.Mem
		address = state.value(mem.Base)
		index := state.value(mem.Index)
		if mem.Index != "" && index.frame {
			return nil, false
		}
		local = address.frame
		if local {
			if address.mixed || mem.OffRaw != "" || mem.Sym != "" || mem.IndexExt != "" || mem.Segment != "" {
				return nil, false
			}
			offset := mem.Off
			if form.post {
				offset = 0
			}
			if offset == math.MinInt64 ||
				offset < 0 && address.interval.low < uint64(-offset) ||
				offset > 0 && address.interval.high > math.MaxUint64-uint64(offset) {
				return nil, false
			}
			address.interval.low += uint64(offset)
			address.interval.high += uint64(offset)
			if mem.Index != "" {
				scale := mem.Scale
				if scale == 0 {
					scale = 1
				}
				if scale < 1 || scale > 16 || index.interval.high > math.MaxUint64/uint64(scale) {
					return nil, false
				}
				low, high := index.interval.low*uint64(scale), index.interval.high*uint64(scale)
				if high > math.MaxUint64-address.interval.high {
					return nil, false
				}
				address.interval.low += low
				address.interval.high += high
			}
		}
	}
	width := form.elementBytes * int64(len(form.registers))
	var span *arm64PrivateDataSpan
	if local {
		if width <= 0 || frameSize < 0 || frameSize > arm64MaxLocalStackSpan ||
			address.interval.high > uint64(frameSize+8) || uint64(width) > uint64(frameSize+8)-address.interval.high {
			return nil, false
		}
		if form.store {
			if address.interval.low < 8 {
				return nil, false // The saved caller link is not private data.
			}
			span = &arm64PrivateDataSpan{int64(address.interval.low), int64(address.interval.high) + width}
		}
	}
	if form.scratch != nil {
		f := *form.scratch
		value := arm64PrivateDataUnknown
		if f.scratchAddress && f.scratchBase != "" {
			value = state.value(f.scratchBase)
			if f.scratchKnown && !value.mixed && f.scratchOffset >= 0 &&
				value.interval.high <= math.MaxUint64-uint64(f.scratchOffset) {
				value.interval.low += uint64(f.scratchOffset)
				value.interval.high += uint64(f.scratchOffset)
			} else {
				value.interval = arm64PoolUnknownInterval
				value.mixed = value.frame
			}
		} else if f.scratchKnown {
			value = arm64PrivateDataNumber(arm64PoolInterval{uint64(f.scratchOffset), uint64(f.scratchOffset)})
		}
		if !state.assign("R27", value) {
			return nil, false
		}
	}
	for index, reg := range form.registers {
		if form.store {
			if state.value(reg).frame {
				return nil, false // Even a private spill would expose an address.
			}
			if local {
				low := address.interval.low + uint64(index)*uint64(form.elementBytes)
				high := address.interval.high + uint64(index+1)*uint64(form.elementBytes)
				for cell := range state.cells {
					if uint64(cell) < high && low < uint64(cell)+8 {
						delete(state.cells, cell)
					}
				}
				if form.gp && form.elementBytes == 8 && address.interval.low == address.interval.high {
					state.cells[int64(low)] = state.value(reg).interval
				}
				if state.initialized != nil && address.interval.low == address.interval.high {
					for offset := int64(low); offset < int64(high); offset++ {
						state.initialized[offset] = true
					}
				}
			}
		} else if form.gp {
			value := arm64PoolUnknownInterval
			if local && form.elementBytes == 8 && address.interval.low == address.interval.high {
				if stored, present := state.cells[int64(address.interval.low)+int64(index)*8]; present {
					value = stored
				}
			}
			signed := op == "MOVB" || op == "MOVH" || op == "MOVW" || op == "MOVBW" || op == "MOVHW" || op == "LDPSW"
			value = arm64PrivateDataNarrow(value, form.elementBytes, signed)
			if op == "MOVBW" || op == "MOVHW" {
				value = arm64PoolMaskInterval(value, math.MaxUint32)
			}
			if !state.assign(reg, arm64PrivateDataNumber(value)) {
				return nil, false
			}
		}
	}
	if (form.pre || form.post) && form.memory.Kind == OpMem {
		mem := form.memory.Mem
		value := state.value(mem.Base)
		if value.frame {
			if arm64StackReg(mem.Base) || value.mixed || mem.Off == math.MinInt64 ||
				mem.Off < 0 && value.interval.low < uint64(-mem.Off) ||
				mem.Off > 0 && uint64(mem.Off) > uint64(frameSize+8)-value.interval.high {
				return nil, false
			}
			value.interval.low += uint64(mem.Off)
			value.interval.high += uint64(mem.Off)
			if !state.assign(mem.Base, value) {
				return nil, false
			}
		} else {
			state.assign(mem.Base, arm64PrivateDataUnknown)
		}
	}
	return span, true
}

func (state *arm64PrivateDataState) transfer(ins Instr, at int, frameSize int64) (*arm64PrivateDataSpan, bool) {
	op := arm64ControlOp(ins)
	if state.initialized != nil && op != OpTEXT {
		if !arm64NanosleepNumericalInstruction(ins) {
			return nil, false
		}
		for _, operand := range ins.Args {
			for _, reg := range []Reg{operand.Reg, operand.ShiftReg, operand.Mem.Base, operand.Mem.Index} {
				if reg == "R29" || reg == "R30" {
					return nil, false // native FP/LR is not a numerical initializer
				}
			}
			for _, reg := range operand.RegList {
				if reg == "R29" || reg == "R30" {
					return nil, false
				}
			}
			if operand.Kind == OpFPAddr || operand.Kind == OpSym ||
				operand.Kind == OpMem && !state.value(operand.Mem.Base).frame {
				return nil, false // no external/native backing or pointer escape
			}
		}
	}
	if immediate, handled, err := parseARM64GPImmediateForm(op, ins); handled {
		if err != nil {
			return nil, false
		}
		if immediate.scratch && !state.assign("R27", arm64PrivateDataNumber(arm64PoolInterval{immediate.value, immediate.value})) {
			return nil, false
		}
	}
	if op == OpTEXT || op == "NOP" {
		return nil, true
	}
	if form, handled, err := parseARM64RegisterAddressForm(op, ins); handled {
		if err != nil || form.usesScratch {
			return nil, false
		}
		value := state.value(form.base)
		if value.frame {
			if value.mixed || form.offset == math.MinInt64 ||
				form.offset < 0 && value.interval.low < uint64(-form.offset) ||
				form.offset > 0 && uint64(form.offset) > uint64(frameSize+8)-value.interval.high {
				return nil, false
			}
			value.interval.low += uint64(form.offset)
			value.interval.high += uint64(form.offset)
			value.origin = at
		}
		return nil, state.assign(form.destination, value)
	}
	if form, known := arm64PrivateDataMemory(ins); known {
		return state.memory(op, form, frameSize)
	}
	if op == "CMP" || op == "CMPW" {
		return nil, state.compare(ins)
	}
	if handled, valid := state.arithmetic(ins, at, frameSize); handled {
		return nil, valid
	}
	if len(ins.Args) == 2 && ins.Args[1].Kind == OpReg && string(ins.Op) == string(op) {
		dst, src := ins.Args[1].Reg, ins.Args[0]
		if op == "MOVD" || op == "MOVB" || op == "MOVBU" || op == "MOVH" || op == "MOVHU" || op == "MOVW" || op == "MOVWU" {
			if src.Kind == OpReg || src.Kind == OpImm {
				value, valid := state.operand(src, 64)
				if !valid || value.frame && op != "MOVD" {
					return nil, false
				}
				if op != "MOVD" {
					signed := src.Kind != OpImm && (op == "MOVB" || op == "MOVH" || op == "MOVW")
					value.interval = arm64PrivateDataNarrow(value.interval, arm64RawPrivateScalarBytes(op), signed)
				}
				return nil, state.assign(dst, value)
			}
			if src.Kind == OpFP || src.Kind == OpSym && strings.HasSuffix(src.Sym, "(SB)") {
				return nil, state.assign(dst, arm64PrivateDataUnknown)
			}
		}
		if op == "MOVK" || op == "MOVKW" {
			value := state.value(dst)
			if value.frame {
				return nil, false
			}
			return nil, state.assign(dst, arm64PrivateDataUnknown)
		}
	}
	// The original may-frame transfer rejects unrecognized uses, address stores,
	// SIMD transports and exception observers. Unknown numeric results lose all
	// bounds, rather than retaining a previous mask/shift fact.
	addresses := state.addresses()
	if !addresses.transfer(ins, frameSize) {
		return nil, false
	}
	state.comparison = arm64PrivateDataCompare{}
	if form, handled, err := parseARM64GPDataForm(op, ins); handled {
		if err != nil {
			return nil, false
		}
		for _, reg := range arm64GPDataOutputRegisters(form) {
			if form.scratch != nil && reg == "R27" && form.destination.Reg != "R27" {
				continue
			}
			if !state.assign(reg, arm64PrivateDataUnknown) {
				return nil, false
			}
		}
		return nil, true
	}
	if len(ins.Args) != 0 {
		dst := ins.Args[len(ins.Args)-1]
		if dst.Kind == OpReg && isARM64GeneralOrZeroReg(dst.Reg) {
			return nil, state.assign(dst.Reg, arm64PrivateDataUnknown)
		}
	}
	return nil, true
}
