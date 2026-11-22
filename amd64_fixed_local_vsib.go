package plan9asm

import (
	"encoding/binary"
	"fmt"
	"math"
)

func fixedLocalVSIBOperand(ins Instr) int {
	for index, operand := range ins.Args {
		if operand.Kind == OpMem && operand.Mem.Index != "" && amd64VectorByteWidth(operand.Mem.Index) != 0 {
			return index
		}
	}
	return -1
}

func fixedLocalVSIBAddress(ins Instr) bool {
	return fixedLocalVSIBOperand(ins) >= 0
}

func (state *x86FixedLocalState) setVectorBytes(root Reg, bits uint64) {
	delete(state.vectorLiterals, root)
	state.vectors[root] = bits
}

func (state *x86FixedLocalState) clearVectorLiterals() {
	for root := range state.vectorLiterals {
		delete(state.vectorLiterals, root)
	}
}

func (state *x86FixedLocalState) zeroVectorLiterals(form x86VectorZeroForm) {
	if state.vectorLiterals == nil {
		return
	}
	first := form.spec.firstByte
	for index := 0; index < form.registers; index++ {
		root := Reg(fmt.Sprintf("Z%d", index))
		old := state.vectorLiterals[root]
		if int(old.width) < first {
			continue
		}
		value := x86ShiftLiteral{width: 64}
		copy(value.bytes[:first], old.bytes[:first])
		state.vectorLiterals[root] = value
	}
}

func (state *x86FixedLocalState) observeVectorZero(ins Instr, root Reg, upper x86TypedVectorUpperWrite) {
	form, known, err := x86PackedLogicalProperties(ins, "amd64")
	if !known || err != nil || form.spec.mode != amd64PackedLogicalXor ||
		form.mask >= 0 || form.memory >= 0 || form.source.Kind != OpReg ||
		form.source.Reg != ins.Args[form.second].Reg ||
		root != x86CallerVectorRoot(ins.Args[form.destination].Reg) {
		return
	}
	width := uint8(form.byteWidth)
	if upper == x86TypedVectorUpperZero {
		width = 64
	}
	state.vectorLiterals[root] = x86ShiftLiteral{width: width}
}

func fixedLocalVSIBLiteralRequests(file *File, requests map[string]map[int64]int) {
	for _, fn := range file.Funcs {
		indexed := false
		for _, ins := range fn.Instrs {
			if fixedLocalVSIBAddress(ins) {
				indexed = true
				break
			}
		}
		if !indexed {
			continue
		}
		for _, ins := range fn.Instrs {
			if len(ins.Args) == 0 || ins.Args[0].Kind != OpSym {
				continue
			}
			width := 0
			if form, known, err := amd64PackedVectorMoveProperties(ins, "amd64"); known {
				if err == nil && form.memory == 0 && form.mask < 0 && !form.undefinedOpcode() {
					width = form.byteWidth
				}
			} else if form, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, "amd64"); known && err == nil && form.memory == 0 {
				width = 16
			}
			address, valid := x86StaticSBReadAddress(ins.Args[0], "amd64")
			if width == 0 || !valid || address.offset > maxDataGlobalSize-int64(width) {
				continue
			}
			if requests[address.symbol] == nil {
				requests[address.symbol] = make(map[int64]int)
			}
			if requests[address.symbol][address.offset] < width {
				requests[address.symbol][address.offset] = width
			}
		}
	}
}

func (state *x86FixedLocalState) packedMoveLiteral(ins Instr, form amd64PackedVectorMoveForm,
	binding *x86FixedLocalBinding, legacy bool) x86ShiftLiteral {
	if state.vectorLiterals == nil || form.mask >= 0 {
		return x86ShiftLiteral{}
	}
	var value x86ShiftLiteral
	switch source := ins.Args[0]; source.Kind {
	case OpReg:
		value = state.vectorLiterals[x86CallerVectorRoot(source.Reg)]
	case OpSym:
		if binding != nil {
			address, valid := x86StaticSBReadAddress(source, "amd64")
			if valid {
				value = binding.literalData[address.symbol].literals[address.offset]
			}
		}
	}
	width := uint8(form.byteWidth)
	if value.width < width {
		return x86ShiftLiteral{}
	}
	result := x86ShiftLiteral{width: width}
	copy(result.bytes[:width], value.bytes[:width])
	if !legacy {
		result.width = 64
	}
	return result
}

// Keep a private envelope for relocation alias checks. Prove initialization
// and revoke spill roles at the exact lane intervals, including sparse or
// repeated addresses. The emitter still uses the actual index and mask.
func fixedLocalVSIBStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) error {
	form, known, err := x86VSIBProperties(*ins, "amd64")
	if !known || err != nil || form.prefetch {
		return goAMD64FrameContext("fixed local VSIB shape is not closed")
	}
	operand := fixedLocalVSIBOperand(*ins)
	memory, err := fixedLocalMemoryAddress(*ins, operand, proof.frame)
	if err != nil {
		return err
	}
	dataWidth, indexWidth := int64(form.spec.elemBits/8), int64(form.spec.indexBits/8)
	lanes := form.activeLanes()
	index := state.vectorLiterals[x86CallerVectorRoot(memory.Index)]
	need := x86CallerVectorByteMask(int64(lanes) * dataWidth)
	data := x86CallerVectorRoot(form.data.Reg)
	mask := form.mask.Reg
	if int64(index.width) < int64(lanes)*indexWidth || state.vectors[data]&need != need ||
		form.evex && !state.masks[mask] ||
		!form.evex && state.vectors[x86CallerVectorRoot(mask)]&need != need {
		return goAMD64FrameContext("fixed local VSIB needs exact indices and initialized data and mask bytes")
	}
	scale := memory.Scale
	if scale == 0 {
		scale = 1
	}
	memory.Index, memory.Scale = "", 0
	base, valid := fixedLocalPrivateOffset(memory, state)
	if !valid {
		return goAMD64FrameContext("fixed local VSIB base lacks a private stack origin")
	}

	var offsets [16]int64
	low, high := proof.frame, int64(0)
	for lane := 0; lane < lanes; lane++ {
		literal := index.bytes[int64(lane)*indexWidth:]
		var relative int64
		if indexWidth == 4 {
			relative = int64(int32(binary.LittleEndian.Uint32(literal)))
		} else {
			relative = int64(binary.LittleEndian.Uint64(literal))
		}
		if relative < math.MinInt64/scale || relative > math.MaxInt64/scale {
			return goAMD64FrameContext("fixed local VSIB lane index overflows")
		}
		delta := relative * scale
		if delta > 0 && base > math.MaxInt64-delta || delta < 0 && base < math.MinInt64-delta {
			return goAMD64FrameContext("fixed local VSIB lane address overflows")
		}
		start := base + delta
		if start < 0 || start > proof.frame-dataWidth {
			return goAMD64FrameContext("fixed local VSIB lane crosses private storage")
		}
		if !form.scatter && !state.bytes.all(start, dataWidth) {
			return goAMD64FrameContext("fixed local VSIB lane reads uninitialized or address bytes")
		}
		offsets[lane] = start
		if start < low {
			low = start
		}
		if end := start + dataWidth; end > high {
			high = end
		}
	}
	if err := fixedLocalRecordAccess(ins, operand, proof, residue, high-low, form.scatter, false, low); err != nil {
		return err
	}
	if form.scatter {
		for _, offset := range offsets[:lanes] {
			fixedLocalNumericalStore(state, offset, dataWidth, false)
		}
	} else {
		state.setVectorBytes(data, ^uint64(0))
	}
	if form.evex {
		state.masks[mask] = true
	} else {
		root := x86CallerVectorRoot(mask)
		state.setVectorBytes(root, ^uint64(0))
		state.vectorLiterals[root] = x86ShiftLiteral{width: 64}
	}
	return nil
}
