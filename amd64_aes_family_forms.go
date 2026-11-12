package plan9asm

import (
	"fmt"
	"strings"
)

type x86AESOperation uint8

const (
	x86AESEncrypt x86AESOperation = iota
	x86AESEncryptLast
	x86AESDecrypt
	x86AESDecryptLast
	x86AESInverseMix
	x86AESKeyAssist
)

type x86AESSpec struct {
	operation x86AESOperation
	vector    bool
}

// All AES optab attributes are explicit. In particular _yvaesdec has EVEX
// full tuples but no mask, broadcast, zeroing, rounding or SAE capability.
var x86AESSpecs = map[Op]x86AESSpec{
	"AESENC": {x86AESEncrypt, false}, "AESENCLAST": {x86AESEncryptLast, false},
	"AESDEC": {x86AESDecrypt, false}, "AESDECLAST": {x86AESDecryptLast, false},
	"AESIMC": {x86AESInverseMix, false}, "AESKEYGENASSIST": {x86AESKeyAssist, false},
	"VAESENC": {x86AESEncrypt, true}, "VAESENCLAST": {x86AESEncryptLast, true},
	"VAESDEC": {x86AESDecrypt, true}, "VAESDECLAST": {x86AESDecryptLast, true},
	"VAESIMC": {x86AESInverseMix, true}, "VAESKEYGENASSIST": {x86AESKeyAssist, true},
}

type x86AESForm struct {
	spec                                          x86AESSpec
	byteWidth, source, state, destination, memory int
	sourceOperand                                 Operand // effective Go source role; original instruction is immutable
}

// This shared grammar supplies operand roles only. No bank initialization,
// native memory, source authentication, frame or pointer authority is created.
func x86AESProperties(op Op, ins Instr, arch string) (x86AESForm, bool, error) {
	name, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86AESSpecs[Op(name)]
	if !known {
		return x86AESForm{}, false, nil
	}
	f := x86AESForm{spec: spec, byteWidth: 16, source: 0, state: -1, destination: len(ins.Args) - 1, memory: -1}
	fail := func() (x86AESForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside complete Go AES grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted || suffix != "" || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	count := 2
	if spec.operation == x86AESKeyAssist {
		count, f.source = 3, 1
		if len(ins.Args) != count || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat || !amd64UnsignedImmediate(ins.Args[0], 8) && !(spec.vector && amd64VectorByteShiftImmediate(ins.Args[0])) {
			return fail()
		}
	} else if spec.operation < x86AESInverseMix {
		f.state = 1
		if spec.vector {
			count = 3
		}
	}
	if len(ins.Args) != count {
		return fail()
	}
	if spec.vector && spec.operation < x86AESInverseMix {
		f.byteWidth = amd64VectorByteWidth(ins.Args[f.destination].Reg)
	}
	register := func(a Operand) bool {
		if a.Kind != OpReg {
			return false
		}
		if spec.vector && spec.operation < x86AESInverseMix {
			return amd64GoPackedVectorMoveRegister(a, f.byteWidth, arch)
		}
		index, valid := amd64ParseXReg(a.Reg)
		return valid && index < 16 && (spec.vector || arch != "386" || index < 8)
	}
	if !register(ins.Args[f.destination]) || f.state >= 0 && !register(ins.Args[f.state]) {
		return fail()
	}
	source := ins.Args[f.source]
	if isAMD64MemoryOperand(source) {
		validation := source
		if source.Kind == OpMem && arch == "386" && strings.HasSuffix(source.Mem.Sym, "(SB)") {
			validation.Mem.Base = "" // actual Go ignores Reg, not Index, for named SB memory
		}
		if !x86PackedShiftMemoryValid(validation, arch) {
			return fail()
		}
		if source.Kind == OpSym {
			if address, err := parseInt(strings.TrimSpace(source.Sym)); err == nil &&
				address != int64(int32(address)) && !(arch == "386" && address == int64(uint32(address))) {
				return fail()
			}
		}
		if source.Kind == OpMem {
			if !x86ConditionalMoveOffsetKnown(source.Mem) {
				return fail()
			}
			if err := x86SymbolIndexedMemoryError(source.Mem, arch); err != nil {
				return f, true, err
			}
		}
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return f, true, fmt.Errorf("%w: AES source has no bound native address-size override", ErrProbeNeedsContext)
		}
		f.memory = f.source
	} else if !register(source) {
		return fail()
	}
	if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
		return f, true, err
	}
	f.sourceOperand = source
	if spec.operation == x86AESKeyAssist && source.Kind == OpMem && !ins.x86Encoded && ins.x86SourceRaw == nil {
		// cmd/asm puts this memory in From3; obj/x86 emits segment prefixes
		// only from From and To. Its real memory bytes therefore omit this
		// annotation. Raw physical instructions retain their actual prefix.
		f.sourceOperand.Mem.Segment = ""
		if source.Mem.Base == FS || source.Mem.Base == GS {
			f.sourceOperand.Mem.Base = ""
		}
	}
	return f, true, nil
}

func x86TypedAESByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86AESProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	e := x86TypedByteEffect{requiresResultProof: true,
		operands: []x86TypedByteOperand{{index: f.source, operand: f.sourceOperand, width: int64(f.byteWidth), read: true}}}
	if f.state >= 0 && f.state != f.destination {
		e.operands = append(e.operands, x86TypedByteOperand{index: f.state, operand: ins.Args[f.state], width: int64(f.byteWidth), read: true})
	}
	e.operands = append(e.operands, x86TypedByteOperand{index: f.destination, operand: ins.Args[f.destination], width: int64(f.byteWidth), read: f.state == f.destination, write: true})
	return e, true, nil
}

// Numerical dependencies are independent of the complete physical memory
// envelope. A SubWord/RotWord observes only source dwords 1 and 3; an AES round
// never has a zero idiom when the two sources alias. Wider lanes are 128-bit.
func x86AESDefinedBytes(f x86AESForm, source, state uint64) uint64 {
	known := uint64(0)
	for lane := 0; lane < f.byteWidth; lane += 16 {
		for out := 0; out < 16; out++ {
			var sourceMask, stateMask uint64
			switch f.spec.operation {
			case x86AESKeyAssist:
				at := out/8*8 + 4 + out%4
				if out%8 >= 4 {
					at = out/8*8 + 4 + (out+1)%4
				}
				sourceMask = uint64(1) << uint(lane+at)
			case x86AESInverseMix:
				sourceMask = uint64(15) << uint(lane+out/4*4)
			default:
				sourceMask = uint64(1) << uint(lane+out)
				column, row := out/4, out%4
				first, last := 0, 4
				if f.spec.operation == x86AESEncryptLast || f.spec.operation == x86AESDecryptLast {
					first, last = row, row+1
				}
				for r := first; r < last; r++ {
					shift := r
					if f.spec.operation == x86AESDecrypt || f.spec.operation == x86AESDecryptLast {
						shift = 4 - r
					}
					stateMask |= uint64(1) << uint(lane+((column+shift)%4)*4+r)
				}
			}
			if source&sourceMask == sourceMask && state&stateMask == stateMask {
				known |= uint64(1) << uint(lane+out)
			}
		}
	}
	return known
}

func x86ResultAESStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultAESStepWithRead(ins, state, owned, arch, false)
}

func x86ResultAESStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	f, known, err := x86AESProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil {
		return false, true
	}
	read := func(index int) (uint64, bool) {
		a := ins.Args[index]
		if index == f.source {
			a = f.sourceOperand
		}
		if a.Kind == OpReg {
			i, valid := amd64VectorRegisterIndex(a.Reg, f.byteWidth)
			if !valid || i >= len(state.xmm) {
				return 0, false
			}
			return state.vectorBytes(i), true
		}
		return x86CallerVectorByteMask(int64(f.byteWidth)),
			x86ResultReadWithNativeContinuation(ins, a, int64(f.byteWidth), state, owned, arch, native && index == f.source)
	}
	source, valid := read(f.source)
	if !valid {
		return false, true
	}
	input := uint64(0)
	if f.state >= 0 {
		input, valid = read(f.state)
		if !valid {
			return false, true
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
	if destination >= len(state.xmm) {
		return false, true
	}
	defined := x86AESDefinedBytes(f, source, input)
	// Preserve the existing nontrapping register NUM domain: an accepted
	// transfer may leave result bytes unknown, never initialized to alloca
	// zeroes. Every later result, store, address or control use still consumes
	// its actual known bytes. Native memory retains its full read above.
	state.writeVector(destination, f.byteWidth, defined, !f.spec.vector)
	return true, true
}
