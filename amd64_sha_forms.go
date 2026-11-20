package plan9asm

import (
	"fmt"
	"strings"
)

// Complete Go legacy SHA rows. The same encoding identity selects the
// grammar, numerical dependencies, native decoder and LLVM operation.
var x86SHAEncodings = map[Op]uint16{
	"SHA1NEXTE": 0x38c8, "SHA1MSG1": 0x38c9, "SHA1MSG2": 0x38ca,
	"SHA1RNDS4": 0x3acc, "SHA256RNDS2": 0x38cb,
	"SHA256MSG1": 0x38cc, "SHA256MSG2": 0x38cd,
}

type x86SHAForm struct {
	op                          Op
	encoding                    uint16
	source, destination, memory int
	immediate                   uint8
	sourceOperand               Operand
}

func x86SHAProperties(op Op, ins Instr, arch string) (x86SHAForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	encoding, known := x86SHAEncodings[Op(name)]
	if !known {
		return x86SHAForm{}, false, nil
	}
	f := x86SHAForm{op: Op(name), encoding: encoding, destination: 1, memory: -1}
	fail := func() (x86SHAForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside complete Go SHA grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted || ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		return fail()
	}
	count := 2
	if encoding == 0x3acc || encoding == 0x38cb {
		count, f.source, f.destination = 3, 1, 2
	}
	if len(ins.Args) != count {
		return fail()
	}
	if encoding == 0x3acc {
		selector := ins.Args[0]
		if arch == "386" && !ins.x86Encoded {
			selector.Imm = int64(int32(selector.Imm))
		}
		if !amd64UnsignedImmediate(selector, 2) || selector.ImmIsFloat || selector.ImmRaw != "" {
			return fail()
		}
		f.immediate = uint8(selector.Imm)
	} else if encoding == 0x38cb && (ins.Args[0].Kind != OpReg || ins.Args[0].Reg != "X0") {
		return fail()
	}
	register := func(a Operand) bool {
		index, valid := amd64ParseXReg(a.Reg)
		return a.Kind == OpReg && valid && index < 16 && (arch != "386" || index < 8)
	}
	if !register(ins.Args[f.destination]) {
		return fail()
	}
	f.sourceOperand = ins.Args[f.source]
	if isAMD64MemoryOperand(f.sourceOperand) {
		if !x86PackedShiftMemoryValid(f.sourceOperand, arch) || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return fail()
		}
		if f.sourceOperand.Kind == OpMem {
			if !x86ConditionalMoveOffsetKnown(f.sourceOperand.Mem) {
				return fail()
			}
			if err := x86SymbolIndexedMemoryError(f.sourceOperand.Mem, arch); err != nil {
				return f, true, err
			}
			if f.source == 1 && !ins.x86Encoded && ins.x86SourceRaw == nil {
				// Go encodes segment prefixes from From/To, not From3.
				f.sourceOperand.Mem.Segment = ""
				if f.sourceOperand.Mem.Base == FS || f.sourceOperand.Mem.Base == GS {
					f.sourceOperand.Mem.Base = ""
				}
			}
		}
		f.memory = f.source
	} else if !register(f.sourceOperand) {
		return fail()
	}
	return f, true, nil
}

// Required bytes for one output byte: source, old destination, implicit X0.
// Copy/XOR dependencies retain byte precision. Rotates, carries and rounds
// conservatively require complete input dwords; unrelated dwords stay unused.
func x86SHAByteInputs(encoding uint16, out int) (source, old, implicit uint64) {
	lane, within := out/4, uint(out%4)
	word := func(lane int) uint64 { return uint64(15) << uint(lane*4) }
	switch encoding {
	case 0x38c8:
		if lane < 3 {
			return uint64(1) << uint(out), 0, 0
		}
		return word(3), word(3), 0
	case 0x38c9:
		if lane < 2 {
			return uint64(1) << uint((lane+2)*4+int(within)), uint64(1) << uint(out), 0
		}
		return 0, uint64(1)<<uint(out) | uint64(1)<<uint(out-8), 0
	case 0x38ca:
		if lane == 0 {
			return word(2), word(0) | word(3), 0
		}
		return word(lane - 1), word(lane), 0
	case 0x3acc:
		return uint64(0xffff) << uint((3-lane)*4) & 0xffff, 0xffff, 0
	case 0x38cc:
		if lane == 3 {
			return word(0), word(3), 0
		}
		return 0, word(lane) | word(lane+1), 0
	case 0x38cd:
		old = word(lane)
		if lane >= 2 {
			old |= word(lane - 2)
		}
		return word(lane%2 + 2), old, 0
	case 0x38cb:
		return [4]uint64{0x00ff, 0x00ff, 0xffff, 0xffff}[lane],
			[4]uint64{0x0fff, 0xffff, 0xf0ff, 0xffff}[lane],
			[4]uint64{0x000f, 0x00ff, 0x000f, 0x00ff}[lane]
	}
	return 0, 0, 0
}

func x86SHADefinedBytes(f x86SHAForm, source, old, implicit uint64) uint64 {
	var result uint64
	for out := 0; out < 16; out++ {
		s, d, x := x86SHAByteInputs(f.encoding, out)
		if source&s == s && old&d == d && implicit&x == x {
			result |= uint64(1) << uint(out)
		}
	}
	return result
}

func x86TypedSHAByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86SHAProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	var source, old, implicit uint64
	for out := 0; out < 16; out++ {
		s, d, x := x86SHAByteInputs(f.encoding, out)
		source, old, implicit = source|s, old|d, implicit|x
	}
	if f.memory >= 0 {
		source = 0 // A register dependency mask never narrows the m128 access.
	}
	e := x86TypedByteEffect{requiresResultProof: true,
		vector: x86TypedVectorEffect{x86TypedVectorUpperPreserve, 16},
		operands: []x86TypedByteOperand{
			{index: f.source, operand: f.sourceOperand, width: 16, read: true, requiredBytes: source},
			{index: f.destination, operand: ins.Args[f.destination], width: 16, read: true, write: true, requiredBytes: old},
		}}
	if implicit != 0 {
		e.operands = append(e.operands, x86TypedByteOperand{index: 0, operand: ins.Args[0], width: 16, read: true, requiredBytes: implicit})
	}
	return e, true, nil
}

func x86ResultSHAStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	f, known, err := x86SHAProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawOrdinaryVectorSourceAt(ins, arch, f.source) {
			return false, true
		}
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	input := uint64(0xffff)
	if f.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, f.sourceOperand, 16, state, owned, arch, native) {
			return false, true
		}
	} else {
		index, _ := amd64ParseXReg(f.sourceOperand.Reg)
		input = state.vectorBytes(index)
	}
	destination, _ := amd64ParseXReg(ins.Args[f.destination].Reg)
	defined := x86SHADefinedBytes(f, input, state.vectorBytes(destination), state.vectorBytes(0))
	state.writeVector(destination, 16, defined, true)
	return true, true
}

func x86RawSHASource(ins Instr, arch string) bool {
	f, known, err := x86SHAProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSourceAt(ins, arch, f.source)
}

func fixedLocalSHAStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) (bool, error) {
	f, known, err := x86SHAProperties(ins.Op, *ins, "amd64")
	if !known {
		return false, nil
	}
	if err != nil {
		return true, goAMD64FrameContext("fixed local SHA shape is not closed")
	}
	source := state.vectors[x86CallerVectorRoot(f.sourceOperand.Reg)]
	if f.memory >= 0 {
		if _, _, err := fixedLocalReadMemory(ins, f.memory, state, proof, residue, 16, 16); err != nil {
			return true, err
		}
		source = 0xffff
	}
	destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
	old := state.vectors[destination]
	state.vectors[destination] = old&^uint64(0xffff) | x86SHADefinedBytes(f, source, old, state.vectors["Z0"])
	return true, nil
}
