package plan9asm

import (
	"fmt"
	"strings"
)

type x86TernaryLogicForm struct {
	laneBits, byteWidth, destination int
	mask, memory, memoryBytes        int
	broadcast, zeroing               bool
	inputs                           [3]int // Intel A=old destination, B=vvvv, C=r/m.
	terms                            uint8  // Boolean algebraic normal form coefficients.
}

// Go's complete _yvalignd grammar is shared by D/Q. Encoding validation
// establishes neither initialized bytes nor permission to access native memory.
func x86TernaryLogicProperties(op Op, ins Instr, arch string) (x86TernaryLogicForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, known := amd64TernaryLogicSpecs[Op(base)]
	if !known {
		return x86TernaryLogicForm{}, false, nil
	}
	f := x86TernaryLogicForm{laneBits: bits, destination: len(ins.Args) - 1, mask: -1, memory: -1}
	fail := func() (x86TernaryLogicForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside Go ternary-logic grammar: %q", arch, op, ins.Raw)
	}
	// The named 386 frontend rejects four/five operands, independently of
	// the legal low-bank EVEX physical forms observed by the raw decoder.
	physical32 := arch == "386" && (ins.x86Encoded || ins.x86SourceRaw != nil)
	if arch != "amd64" && !physical32 || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	switch suffix {
	case "":
		if dotted {
			return fail()
		}
	case "Z":
		f.zeroing = true
	case "BCST":
		f.broadcast = true
	case "BCST.Z":
		f.broadcast, f.zeroing = true, true
	default:
		return fail()
	}
	if len(ins.Args) != 4 && len(ins.Args) != 5 {
		return fail()
	}
	if len(ins.Args) == 5 {
		if !amd64NonzeroKOperand(ins.Args[3]) {
			return fail()
		}
		f.mask = 3
	} else if f.zeroing {
		return fail()
	}
	immediate, integer := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
	if !integer || immediate.Imm < 0 || immediate.Imm > 255 {
		return fail()
	}
	f.byteWidth = amd64VectorByteWidth(ins.Args[f.destination].Reg)
	register := func(operand Operand) bool {
		index, valid := amd64VectorRegisterIndex(operand.Reg, f.byteWidth)
		return amd64EVEXVectorRegister(operand, f.byteWidth) && valid && (arch != "386" || index < 8)
	}
	if !register(ins.Args[f.destination]) || !register(ins.Args[2]) {
		return fail()
	}
	source := ins.Args[1]
	if isAMD64MemoryOperand(source) {
		if !x86PackedShiftMemoryValid(source, arch) {
			return fail()
		}
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return f, true, fmt.Errorf("%w: ternary logic has no bound native address-size override", ErrProbeNeedsContext)
		}
		if source.Kind == OpMem {
			if err := x86SymbolIndexedMemoryError(source.Mem, arch); err != nil {
				return f, true, err
			}
			if source.Mem.OffRaw != "" || source.Mem.IndexExt != "" {
				return fail()
			}
		}
		f.memory, f.memoryBytes = 1, f.byteWidth
		if f.broadcast {
			f.memoryBytes = bits / 8
		}
	} else if f.broadcast || !register(source) {
		return fail()
	}
	f.inputs = [3]int{f.destination, 2, 1}
	representatives := [3]int{0, 1, 2}
	for role, index := range f.inputs {
		for earlier := 0; earlier < role; earlier++ {
			other := f.inputs[earlier]
			if ins.Args[index].Kind == OpReg && ins.Args[other].Kind == OpReg && ins.Args[index].Reg == ins.Args[other].Reg {
				representatives[role] = representatives[earlier]
				break
			}
		}
	}
	f.terms = x86TernaryLogicTerms(uint8(immediate.Imm), representatives)
	return f, true, nil
}

// Convert the truth table to its unique XOR-of-ANDs representation. First
// identify equal physical inputs, so x XOR x and independent input variables
// disappear before emission. This avoids relying on LLVM undef cancellation.
func x86TernaryLogicTerms(immediate uint8, representatives [3]int) uint8 {
	var coefficients [8]uint8
	for assignment := range coefficients {
		truth := 0
		for _, representative := range representatives {
			truth = truth*2 + (assignment>>uint(representative))&1
		}
		coefficients[assignment] = immediate >> uint(truth) & 1
	}
	for bit := 1; bit < 8; bit <<= 1 {
		for subset := range coefficients {
			if subset&bit != 0 {
				coefficients[subset] ^= coefficients[subset^bit]
			}
		}
	}
	var terms uint8
	for subset, coefficient := range coefficients {
		terms |= coefficient << uint(subset)
	}
	return terms
}

func (f x86TernaryLogicForm) dependencies() uint8 {
	var inputs uint8
	for subset := 1; subset < 8; subset++ {
		if f.terms>>uint(subset)&1 != 0 {
			inputs |= uint8(subset)
		}
	}
	return inputs
}

func x86TypedTernaryLogicByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86TernaryLogicProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	dependencies := form.dependencies()
	if form.mask >= 0 && !form.zeroing {
		dependencies |= 1 // An inactive merging lane retains the old A value.
	}
	effect := x86TypedByteEffect{requiresResultProof: true}
	for role, index := range form.inputs {
		width := form.byteWidth
		read := dependencies>>uint(role)&1 != 0
		if index == form.memory {
			// Physical E4 access remains observable even when the selected
			// Boolean function does not depend on its loaded numerical value.
			width, read = form.memoryBytes, true
		}
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: index, operand: ins.Args[index], width: int64(width),
			read: read, write: index == form.destination,
		})
	}
	if form.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: form.mask, operand: ins.Args[form.mask], width: 8, read: true,
		})
	}
	return effect, true, nil
}
