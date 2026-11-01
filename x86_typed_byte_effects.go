package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

// A descriptor records operand roles and machine effects only. Neither a
// numerical input nor a native memory/frame/source capability can be obtained
// from this record. Consumers must independently prove every required byte.
type x86TypedByteOperand struct {
	index         int
	operand       Operand
	width         int64
	read          bool
	write         bool
	requiredBytes uint64 // Optional vector-register read mask; zero requires the full width.
}

type x86TypedByteEffect struct {
	operands            []x86TypedByteOperand
	vector              x86TypedVectorEffect
	flagsRead           uint8
	flagsDefined        uint8
	flagsKilled         uint8
	dynamicMemory       bool // A register-indexed bit string has no fixed base span.
	requiresResultProof bool // Mandatory NUM/result obligation, independent of cost-only storage routing.
}

// Zero is deliberately unknown: an existing operand dependency alone does
// not establish memory alignment or what happens to the upper vector alias.
type x86TypedVectorEffect struct {
	upperWrite      x86TypedVectorUpperWrite
	memoryAlignment int64
}

type x86TypedVectorUpperWrite uint8

const (
	x86TypedVectorUpperUnknown x86TypedVectorUpperWrite = iota
	x86TypedVectorUpperPreserve
	x86TypedVectorUpperZero
)

const (
	x86ByteFlagCF uint8 = 1 << iota
	x86ByteFlagPF
	x86ByteFlagAF
	x86ByteFlagZF
	x86ByteFlagSF
	x86ByteFlagOF
	x86ByteFlagsAll = x86ByteFlagCF | x86ByteFlagPF | x86ByteFlagAF | x86ByteFlagZF | x86ByteFlagSF | x86ByteFlagOF
)

type x86ExplicitIMULForm struct {
	bits        int
	immediate   Operand
	source      Operand
	destination Operand
	three       bool
}

// Go's complete yimul/yimul3 explicit axis is W/L/Q: register or memory
// source, the two immediate classes, and a Yrl result. One-operand IMUL is
// a separate implicit-accumulator effect and is not silently admitted here.
func x86ExplicitIMULProperties(op Op, ins Instr, arch string) (x86ExplicitIMULForm, bool, error) {
	name := strings.ToUpper(string(op))
	stem, bits, three, recognized := x86ScalarMultiplyDivideProperties(name)
	if !recognized || stem != "IMUL" || bits == 8 {
		return x86ExplicitIMULForm{}, false, nil
	}
	if !three && len(ins.Args) == 1 {
		return x86ExplicitIMULForm{}, false, nil
	}
	fail := func(reason string) (x86ExplicitIMULForm, bool, error) {
		return x86ExplicitIMULForm{}, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || arch == "386" && bits == 64 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) ||
		three && len(ins.Args) != 3 || !three && len(ins.Args) != 2 {
		return fail("has an unbound mode, dispatch identity or operand count")
	}
	sourceIndex := 0
	if three {
		sourceIndex = 1
	}
	if projected, segment, err := x86NamedSegmentMemorySource(ins, ins.Args[sourceIndex], arch); segment {
		if err != nil {
			return x86ExplicitIMULForm{}, true, err
		}
		ins.Args = append([]Operand(nil), ins.Args...)
		ins.Args[sourceIndex] = projected
	}
	if err := validateX86ExplicitIMUL(arch, name, bits, ins, three); err != nil {
		return x86ExplicitIMULForm{}, true, err
	}
	form := x86ExplicitIMULForm{bits: bits, source: ins.Args[0], destination: ins.Args[1], three: three}
	if three {
		form.immediate, form.source, form.destination = ins.Args[0], ins.Args[1], ins.Args[2]
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpImm && (operand.ImmRaw != "" || operand.ImmIsFloat) {
			return fail("requires a resolved integer immediate")
		}
		if err := x86NamedMultiplyMemoryError(operand, arch); err != nil {
			return fail(err.Error())
		}
	}
	// These copies retain Go's actual encoded immediate, including W truncation
	// and Q sign extension. Effects and lowering must not use different literal
	// values; the original source/operands remain unchanged.
	if form.source.Kind == OpImm {
		form.source.Imm = x86IMULEncodedImmediate(form.source.Imm, bits)
	}
	if form.immediate.Kind == OpImm {
		form.immediate.Imm = x86IMULEncodedImmediate(form.immediate.Imm, bits)
	}
	return form, true, nil
}

func x86TypedGPByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if arch != "amd64" && arch != "386" {
		return x86TypedByteEffect{}, false, nil
	}
	if effect, known, err := x86TypedScalarMoveAliasEffect(op, ins, arch); known {
		return effect, known, err
	}
	if op == ins.Op && x86PreservesNumericalSourceState(ins) {
		return x86TypedByteEffect{}, true, nil
	}
	if known, err := x86SizedNOPProperties(ins, arch); known {
		if op != ins.Op {
			return x86TypedByteEffect{}, true, fmt.Errorf("sized NOP dispatch/source identity mismatch")
		}
		return x86TypedByteEffect{}, true, err
	}
	if effect, known, err := x86TypedAHFlagsEffect(op, ins, arch); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedSelfCompareByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedCarryControlByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedCounterControlByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedByteSwapEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedScalarBitFieldByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedBLSByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedADXByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedTernaryGPByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedMULXByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedMOVBEByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedLEAByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedBitTestByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedScalarShiftByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedScalarBitCountByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedConditionalMoveByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if form, recognized, err := x86LockScalarRMWProperties(op, ins, arch); recognized {
		if err != nil {
			return x86TypedByteEffect{}, true, err
		}
		width := int64(form.spec.bits / 8)
		zero := x86ScalarXORZeroRegister(form, width)
		destinationIndex := 1
		effect := x86TypedByteEffect{flagsDefined: form.spec.flagsDefined, flagsKilled: form.spec.flagsKilled}
		if form.spec.unary {
			destinationIndex = 0
		} else {
			effect.operands = append(effect.operands, x86TypedByteOperand{index: 0, operand: form.source, width: width, read: !zero})
		}
		if form.spec.stem == "ADC" || form.spec.stem == "SBB" {
			effect.flagsRead = x86ByteFlagCF
		}
		effect.dynamicMemory = form.spec.bitString && form.source.Kind == OpReg && isAMD64MemoryOperand(form.destination)
		effect.operands = append(effect.operands, x86TypedByteOperand{index: destinationIndex, operand: form.destination, width: width, read: !zero, write: true})
		return effect, true, nil
	}
	if form, recognized, err := x86ScalarExtensionProperties(op, ins, arch); recognized {
		if err != nil {
			return x86TypedByteEffect{}, true, err
		}
		return x86TypedByteEffect{operands: []x86TypedByteOperand{
			{index: 0, operand: form.source, width: int64(form.spec.sourceBits / 8), read: true},
			{index: 1, operand: Operand{Kind: OpReg, Reg: form.result}, width: int64(form.spec.destinationBits / 8), write: true},
		}}, true, nil
	}
	form, recognized, err := x86ExplicitIMULProperties(op, ins, arch)
	if !recognized || err != nil {
		return x86TypedByteEffect{}, recognized, err
	}
	return x86ExplicitIMULByteEffect(form), true, nil
}

func x86ExplicitIMULByteEffect(form x86ExplicitIMULForm) x86TypedByteEffect {
	width := int64(form.bits / 8)
	sourceIndex, destinationIndex := 0, 1
	if form.three {
		sourceIndex, destinationIndex = 1, 2
	}
	effect := x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: sourceIndex, operand: form.source, width: width, read: true},
		{index: destinationIndex, operand: form.destination, width: width, read: !form.three, write: true},
	}, flagsDefined: x86ByteFlagCF | x86ByteFlagOF, flagsKilled: x86ByteFlagsAll}
	if form.three {
		effect.operands = append([]x86TypedByteOperand{{index: 0, operand: form.immediate, width: width, read: true}}, effect.operands...)
	}
	return effect
}

// Only a validated XOR row selecting the same physical GP bytes is independent
// of its incoming value. AL/AX byte aliases are equivalent; AH/AL are not.
// The grammar has already applied Go's actual REX byte view. This supplies no
// memory, stack, caller or backing authority and defines no unwritten bytes.
func x86ScalarXORZeroRegister(form x86LockScalarRMWForm, width int64) bool {
	if form.spec.stem != "XOR" ||
		!reflect.DeepEqual(form.source, Operand{Kind: OpReg, Reg: form.source.Reg}) ||
		!reflect.DeepEqual(form.destination, Operand{Kind: OpReg, Reg: form.destination.Reg}) {
		return false
	}
	source, sourceValid := x86CallerGP(form.source.Reg)
	destination, destinationValid := x86CallerGP(form.destination.Reg)
	mask := x86CallerByteMask(form.source.Reg, width)
	return sourceValid && destinationValid && source == destination && mask != 0 &&
		mask == x86CallerByteMask(form.destination.Reg, width)
}

func x86ByteConditionFlags(condition string) uint8 {
	switch condition {
	case "CC", "CS":
		return x86ByteFlagCF
	case "EQ", "NE":
		return x86ByteFlagZF
	case "GE", "LT":
		return x86ByteFlagSF | x86ByteFlagOF
	case "GT", "LE":
		return x86ByteFlagSF | x86ByteFlagOF | x86ByteFlagZF
	case "HI", "LS":
		return x86ByteFlagCF | x86ByteFlagZF
	case "MI", "PL":
		return x86ByteFlagSF
	case "OC", "OS":
		return x86ByteFlagOF
	case "PC", "PS":
		return x86ByteFlagPF
	}
	return 0
}

func x86ByteBranchFlags(op Op) uint8 {
	if spec, counter := x86CounterControlPropertiesForOpcode(op); counter {
		return x86ByteConditionFlags(spec.condition)
	}
	return x86ByteConditionFlags(x86BranchCondition(op))
}
