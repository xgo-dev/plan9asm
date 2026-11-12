package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedShiftCount uint8

const (
	x86PackedShiftUniform x86PackedShiftCount = iota
	x86PackedShiftPerLane
	x86PackedShiftBytes
)

type x86PackedShiftForm struct {
	countMode                              x86PackedShiftCount
	laneBits, byteWidth                    int
	count, data, destination, mask, memory int
	memoryBytes                            int
	left, legacy, mmx, broadcast, zeroing  bool
	faultSuppressed                        bool
	arithmetic                             bool
	countOperand                           Operand
}

func x86TypedLegacyPackedShiftByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedShiftProperties(op, ins, arch)
	if !known || err != nil || !form.legacy || form.mmx {
		return x86TypedByteEffect{}, known && (err != nil || form.legacy && !form.mmx), err
	}
	return x86PackedShiftDependencyEffect(ins, form), true, nil
}

// Properties establish encoding and access shape only, never initialized
// data, pointer bounds, alignment or permission to return through raw bytes.
func x86PackedShiftProperties(op Op, ins Instr, goarch string) (x86PackedShiftForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	uniform, recognized := amd64PackedLogicalShiftSpecs[Op(base)]
	arithmetic, arithmeticUniform := amd64PackedArithmeticShiftSpecs[Op(base)]
	if arithmeticUniform {
		uniform, recognized = arithmetic, true
	}
	perLane, variable := amd64PerLaneVariableShiftSpecs[base]
	byteShift := base == "PSLLO" || base == "PSLLDQ" || base == "PSRLO" || base == "PSRLDQ" || base == "VPSLLDQ" || base == "VPSRLDQ"
	if !recognized && !variable && !byteShift {
		return x86PackedShiftForm{}, false, nil
	}
	f := x86PackedShiftForm{count: 0, data: 1, destination: len(ins.Args) - 1, mask: -1, memory: -1,
		arithmetic: arithmeticUniform || variable && perLane.arithmetic}
	fail := func() (x86PackedShiftForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside Go packed shift grammar: %q", goarch, op, ins.Raw)
	}
	if goarch != "amd64" && goarch != "386" || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	local := ins
	local.Op = op
	if recognized && !uniform.vector {
		var err error
		local, err = x86LegacyMMXReadInstruction(local, goarch)
		if err != nil {
			return f, true, err
		}
	}
	f.countMode, f.laneBits, f.left, f.legacy = x86PackedShiftUniform, uniform.laneBits, uniform.left, !uniform.vector
	if variable {
		f.countMode, f.laneBits, f.left, f.legacy = x86PackedShiftPerLane, perLane.laneBits, perLane.operation == "shl", false
	}
	if byteShift {
		f.countMode, f.laneBits, f.left, f.legacy = x86PackedShiftBytes, 8, strings.Contains(base, "SLL"), !strings.HasPrefix(base, "V")
	}
	if f.legacy {
		if dotted || len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return fail()
		}
		f.data = f.destination
		f.byteWidth = 16
		_, f.mmx = amd64ParseMReg(ins.Args[f.destination].Reg)
		if f.mmx {
			if byteShift || goarch == "386" {
				return fail()
			}
			f.byteWidth = 8
		}
	} else {
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
		if len(ins.Args) != 3 && len(ins.Args) != 4 || byteShift && dotted || f.broadcast && f.laneBits == 16 {
			return fail()
		}
		if len(ins.Args) == 4 {
			if byteShift || goarch == "386" && !ins.x86Encoded || !amd64NonzeroKOperand(ins.Args[2]) {
				return fail()
			}
			f.mask = 2
		} else if f.zeroing {
			return fail()
		}
		f.byteWidth = amd64VectorByteWidth(ins.Args[f.destination].Reg)
	}
	register := func(operand Operand, width int) bool {
		if f.mmx {
			_, valid := amd64ParseMReg(operand.Reg)
			return operand.Kind == OpReg && valid
		}
		if f.legacy {
			index, valid := amd64ParseXReg(operand.Reg)
			return operand.Kind == OpReg && valid && (goarch == "amd64" && index < 16 || goarch == "386" && index < 8)
		}
		return amd64GoPackedVectorMoveRegister(operand, width, goarch)
	}
	if !register(ins.Args[f.destination], f.byteWidth) {
		return fail()
	}
	count, data := local.Args[f.count], local.Args[f.data]
	if count.Kind == OpImm {
		var valid bool
		count, valid = x86ImmediateShuffleConstant(count, goarch, ins.x86Encoded)
		if !valid {
			return fail()
		}
		if variable || count.Imm < -128 || count.Imm > 255 || f.legacy && count.Imm > 127 {
			return fail()
		}
		if count.Imm < 0 && (base == "VPSRAQ" || f.mask >= 0 ||
			!f.legacy && amd64PackedByteShiftRequiresEVEX(data, ins.Args[f.destination], f.byteWidth)) {
			return fail()
		}
		if isAMD64MemoryOperand(data) {
			f.memory, f.memoryBytes = f.data, f.byteWidth
			if f.broadcast {
				f.memoryBytes = f.laneBits / 8
			}
		} else if f.broadcast || !register(data, f.byteWidth) {
			return fail()
		}
		// All W/D/Q immediate Full tuples use E4/E4.nb. Byte shifts
		// retain E4NF.nb; uniform Mem128 count rows are handled below.
		f.faultSuppressed = !f.legacy && !byteShift
	} else {
		if byteShift || f.broadcast && !variable || !register(data, f.byteWidth) {
			return fail()
		}
		countWidth := f.byteWidth
		if !variable && !f.mmx {
			countWidth = 16
		}
		if isAMD64MemoryOperand(count) {
			f.memory, f.memoryBytes = f.count, countWidth
			if f.broadcast {
				f.memoryBytes = f.laneBits / 8
			}
		} else if f.broadcast || !register(count, countWidth) {
			return fail()
		}
		f.faultSuppressed = variable
	}
	f.countOperand = count
	if f.memory >= 0 && !x86PackedShiftMemoryValid(ins.Args[f.memory], goarch) {
		return fail()
	}
	if f.memory >= 0 && ins.Args[f.memory].Kind == OpMem {
		memory := ins.Args[f.memory].Mem
		if err := x86SymbolIndexedMemoryError(memory, goarch); err != nil {
			return f, true, err
		}
		if memory.OffRaw != "" || memory.IndexExt != "" {
			return fail()
		}
	}
	if goarch == "386" {
		for _, operand := range ins.Args {
			width := amd64VectorByteWidth(operand.Reg)
			if index, valid := amd64VectorRegisterIndex(operand.Reg, width); operand.Kind == OpReg && valid && index >= 8 {
				return f, true, fmt.Errorf("mode32 packed shift has no physical SIMD register %s: %w", operand.Reg, ErrProbeNeedsContext)
			}
		}
	}
	return f, true, nil
}

func x86PackedShiftMemoryValid(operand Operand, goarch string) bool {
	if operand.Kind == OpSym {
		symbol := strings.TrimSpace(operand.Sym)
		_, integer := parseInt(symbol)
		return !strings.HasPrefix(symbol, "$") && (strings.HasSuffix(symbol, "(SB)") || integer == nil)
	}
	if operand.Kind != OpMem {
		return operand.Kind == OpFP
	}
	memory := operand.Mem
	return (memory.Off == int64(int32(memory.Off)) || goarch == "386" && memory.Off == int64(uint32(memory.Off))) &&
		x86MemoryRegistersValidForArch(memory, goarch) && (memory.Index == "" || memory.Index != SP &&
		(memory.Scale == 1 || memory.Scale == 2 || memory.Scale == 4 || memory.Scale == 8))
}
