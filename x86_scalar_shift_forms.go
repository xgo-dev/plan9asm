package plan9asm

import (
	"fmt"
	"strings"
)

type x86ScalarShiftForm struct {
	stem, name                    string
	bits                          int
	count, source, destination    Operand
	sourceIndex, destinationIndex int
	double, bmi2                  bool
}

// Match complete Go yshb/yshl, movDoubleShift, _ybextrl and _yrorxl
// grammars. A shape is not numerical input, memory backing or entry authority.
func x86ScalarShiftProperties(op Op, ins Instr, arch string) (x86ScalarShiftForm, bool, error) {
	name := strings.ToUpper(string(op))
	base, _, dotted := strings.Cut(name, ".")
	stem, bits, known := amd64ScalarShiftRotateProperties(base)
	bmi2 := false
	if !known {
		if spec, present := amd64BMI2ShiftSpecs[Op(base)]; present {
			stem, bits, known, bmi2 = base[:len(base)-1], spec.bits, true, true
		}
	}
	if !known {
		return x86ScalarShiftForm{}, false, nil
	}
	f := x86ScalarShiftForm{stem: stem, name: base, bits: bits, bmi2: bmi2, sourceIndex: -1, destinationIndex: 1}
	fail := func(reason string) (x86ScalarShiftForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside Go scalar shift/rotate grammar (%s): %q", arch, op, reason, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return fail("mode or opcode identity")
	}
	if arch == "386" && bits == 64 {
		if !bmi2 {
			return fail("legacy Q requires 64-bit mode")
		}
		f.bits = 32 // Go accepts VEX.W1 spellings; hardware ignores W in mode32.
	}
	if bmi2 || len(ins.Args) == 3 {
		if len(ins.Args) != 3 || !bmi2 && (bits == 8 || stem != "SHL" && stem != "SHR") {
			return fail("operand count or double-shift width")
		}
		f.double, f.sourceIndex, f.destinationIndex = !bmi2, 1, 2
		f.source = ins.Args[1]
		if f.source.Kind == OpReg {
			if !isX86YrlRegisterForArch(f.source.Reg, arch) {
				return fail("Yrl source")
			}
		} else if f.double || !isAMD64MemoryOperand(f.source) || !x86PackedShiftMemoryValid(f.source, arch) {
			return fail("Yml source")
		}
	} else if len(ins.Args) != 2 {
		return fail("operand count")
	}
	f.count, f.destination = ins.Args[0], ins.Args[f.destinationIndex]
	if f.destination.Kind == OpReg {
		valid := isX86YrlRegisterForArch(f.destination.Reg, arch)
		if f.bits == 8 {
			valid = isGoYmbRegisterForArch(f.destination.Reg, arch)
		}
		if !valid {
			return fail("destination register class")
		}
	} else if bmi2 || !isAMD64MemoryOperand(f.destination) || !x86PackedShiftMemoryValid(f.destination, arch) {
		return fail("destination memory class")
	}
	if bmi2 && stem != "RORX" {
		if f.count.Kind != OpReg || !isX86YrlRegisterForArch(f.count.Reg, arch) {
			return fail("Yrl register count")
		}
	} else if f.count.Kind == OpImm {
		low, high := int64(0), int64(255)
		if f.double {
			low, high = -128, 127
		} else if bmi2 { // _yrorxl has both Yu8 and Yi8 encoder rows.
			low = -128
		}
		if f.count.ImmRaw != "" || f.count.ImmIsFloat || f.count.Imm < low || f.count.Imm > high {
			return fail("resolved encoder imm8 count")
		}
	} else if bmi2 || f.count.Kind != OpReg || f.count.Reg != CL && f.count.Reg != CX {
		return fail("CL/CX count")
	}
	return f, true, nil
}

func (f x86ScalarShiftForm) maskedCount() int64 {
	mask := int64(31)
	if f.bits == 64 {
		mask = 63
	}
	return f.count.Imm & mask
}

func x86TypedScalarShiftByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86ScalarShiftProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	count, variable := f.maskedCount(), f.count.Kind == OpReg
	if f.double && f.bits == 16 && (variable || count > 16) {
		return x86TypedByteEffect{}, true, fmt.Errorf("%w: W double-shift has an unproved or undefined numerical count", ErrProbeNeedsContext)
	}
	effect := f.inputEffect()
	if f.bmi2 || !variable && count == 0 {
		return effect, true, nil // BMI2 never writes flags; Group2 count0 preserves.
	}
	rotate := f.stem == "RCL" || f.stem == "RCR" || f.stem == "ROL" || f.stem == "ROR"
	carry := f.stem == "RCL" || f.stem == "RCR"
	if rotate {
		effect.flagsKilled = x86ByteFlagOF
		if !variable {
			if !carry || count%int64(f.bits+1) != 0 {
				effect.flagsDefined = x86ByteFlagCF
			}
			if count == 1 {
				effect.flagsDefined |= x86ByteFlagOF
			}
		}
		return effect, true, nil
	}
	effect.flagsKilled = x86ByteFlagAF | x86ByteFlagOF
	if variable {
		// Count0 preserves unknown flags: no fresh definition is unconditional.
		// B/W logical shifts also have a legal count where CF is undefined.
		if f.bits < 32 && f.stem != "SAR" {
			effect.flagsKilled |= x86ByteFlagCF
		}
	} else {
		effect.flagsKilled = x86ByteFlagsAll
		effect.flagsDefined = x86ByteFlagPF | x86ByteFlagZF | x86ByteFlagSF
		if f.double || f.stem == "SAR" || count < int64(f.bits) {
			effect.flagsDefined |= x86ByteFlagCF
		}
		if count == 1 {
			effect.flagsDefined |= x86ByteFlagOF
		}
	}
	return effect, true, nil
}

func (f x86ScalarShiftForm) inputEffect() x86TypedByteEffect {
	count, variable := f.maskedCount(), f.count.Kind == OpReg
	// A numerical byte effect is not memory authority. Logical FP/AUTO
	// consumers still need initialized storage; native operands require the
	// lowering-only continuation paired with their exact volatile access.
	effect := x86TypedByteEffect{requiresResultProof: f.bmi2 || f.hasMemory()}
	if variable {
		// Both CX spelling and every BMI2 Yrl count consume only low CL bits.
		effect.operands = append(effect.operands, x86TypedByteOperand{index: 0, operand: f.count, width: 1, read: true})
	}
	width := int64(f.bits / 8)
	if f.sourceIndex >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{index: f.sourceIndex, operand: f.source, width: width, read: f.bmi2 || variable || count != 0})
	}
	effect.operands = append(effect.operands, x86TypedByteOperand{index: f.destinationIndex, operand: f.destination, width: width, read: !f.bmi2, write: true})
	if (f.stem == "RCL" || f.stem == "RCR") && (variable || count%int64(f.bits+1) != 0) {
		effect.flagsRead = x86ByteFlagCF
	}
	return effect
}

func (f x86ScalarShiftForm) hasMemory() bool {
	return f.destination.Kind != OpReg || f.sourceIndex >= 0 && f.source.Kind != OpReg
}
