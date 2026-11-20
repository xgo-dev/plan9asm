package plan9asm

import "fmt"

type arm64RawSVEMemory uint8

const (
	arm64RawSVENoMemory arm64RawSVEMemory = iota
	arm64RawSVEReadMemory
	arm64RawSVEMemoryOperand
)

// The accepted decoder, lowerer and architectural effects belong to one
// family. A vector address operand is not a memory access, and predicate
// flags are not GP writes. Never infer either property from an opcode prefix.
type arm64RawSVEFamily struct {
	decode      func(uint32) (Instr, bool)
	lower       func(*arm64Ctx, Instr) error
	gpResult    bool
	readsResult bool
	memory      arm64RawSVEMemory
}

type arm64RawSVEControlEffects struct {
	gpWrites uint32
	gpReads  uint32
	stores   bool
	accesses bool
}

type arm64RawSVEVectorFamily struct {
	matches func(uint32) bool
	lower   func(*arm64Ctx, uint32) error
}

// T retains each family's concrete decoded form; no reflection or untyped
// payload is involved. This constructor is only for the explicitly registered
// vector-only families below: no GP input/output, control flow or memory.
func arm64RawSVEVectorForm[T any](decode func(uint32) (T, bool), lower func(*arm64Ctx, T) error) arm64RawSVEVectorFamily {
	return arm64RawSVEVectorFamily{
		matches: func(word uint32) bool {
			_, ok := decode(word)
			return ok
		},
		lower: func(c *arm64Ctx, word uint32) error {
			form, ok := decode(word)
			if !ok {
				return fmt.Errorf("ARM64 raw SVE vector family rejected its selected encoding %#08x", word)
			}
			return lower(c, form)
		},
	}
}

var arm64RawSVEVectorFamilies = [...]arm64RawSVEVectorFamily{
	arm64RawSVEVectorForm(decodeARM64RawSVEMultiply, (*arm64Ctx).lowerRawSVEMultiply),
	arm64RawSVEVectorForm(decodeARM64RawSVETable, (*arm64Ctx).lowerRawSVETable),
	arm64RawSVEVectorForm(decodeARM64RawSVEUMULLB, (*arm64Ctx).lowerRawSVEUMULLB),
	arm64RawSVEVectorForm(decodeARM64RawSVEMultiplyAccumulateLong, (*arm64Ctx).lowerRawSVEMultiplyAccumulateLong),
	arm64RawSVEVectorForm(decodeARM64RawSVEFloatMinMaxReduction,
		func(c *arm64Ctx, form arm64RawSVEFloatMinMaxReduction) error {
			return c.lowerARM64SVEFloatMinMaxReductionForm(form.spec, form.form, form.destination)
		}),
}

func arm64RawSVEEffects(word uint32) (arm64RawSVEControlEffects, bool) {
	if family, decoded, ok := decodeARM64RawSVEFamily(word); ok {
		return family.effects(decoded), true
	}
	for _, family := range arm64RawSVEVectorFamilies {
		if family.matches(word) {
			return arm64RawSVEControlEffects{}, true
		}
	}
	return arm64RawSVEControlEffects{}, false
}

func arm64RawSVENamed(lower func(*arm64Ctx, Op, Instr) (bool, bool, error)) func(*arm64Ctx, Instr) error {
	return func(c *arm64Ctx, ins Instr) error {
		handled, terminated, err := lower(c, ins.Op, ins)
		if err == nil && (!handled || terminated) {
			return fmt.Errorf("ARM64 raw SVE family did not lower its decoded instruction: %s", ins.Op)
		}
		return err
	}
}

// Keep the former raw-lowering precedence. The same table drives lowering,
// GP/control effects and relocated-pool address independence.
var arm64RawSVEFamilies = [...]arm64RawSVEFamily{
	{decode: decodeARM64RawSVEIndex,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEIndex)},
	{decode: decodeARM64RawSVEFloatMinMax,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEFloatMinMax)},
	{decode: decodeARM64RawSVEFloatUnary,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEFloatUnary)},
	{decode: decodeARM64RawSVEFloatImmediate,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEFloatImmediate)},
	{decode: decodeARM64RawSVEDupM,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEDupM)},
	{decode: decodeARM64RawSVEFloatMultiplyAccumulate,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEFloatMultiplyAccumulate)},
	{decode: decodeARM64RawSVEFloatReciprocalStep,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEFloatReciprocalStep)},
	{decode: decodeARM64RawSVEConvert,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEConvert)},
	{decode: decodeARM64RawSVEWhile,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEPredicateWhile)},
	{decode: decodeARM64RawSVECharacterMatch,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVECharacterMatch)},
	{decode: decodeARM64RawSVEPredicateBreak,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEPredicateBreak)},
	{decode: decodeARM64RawSVEPredicateCount, gpResult: true,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEPredicateCounter)},
	{decode: decodeARM64RawSVEPredicateIncDec, gpResult: true, readsResult: true,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEPredicateIncDec)},
	{decode: decodeARM64RawSVEFloatCompare,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVECompare)},
	{decode: decodeARM64RawSVEIntegerCompare,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVECompare)},
	{decode: decodeARM64RawSVEPredicateLogical,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEPredicateLogical)},
	{decode: decodeARM64RawSVEPredicatePermute,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEPredicatePermute)},
	{decode: decodeARM64RawSVECompact,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVECompact)},
	{decode: decodeARM64RawSVECopy,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVECopy)},
	{decode: decodeARM64RawSVEIntegerUnary,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEIntegerUnary)},
	{decode: decodeARM64RawSVERevd,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVERevd)},
	{decode: decodeARM64RawSVEStructuredMemory, memory: arm64RawSVEMemoryOperand,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEStructuredMemory)},
	{decode: decodeARM64RawSVEMultiplyAccumulate,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEMultiplyAccumulate)},
	{decode: decodeARM64RawSVETernaryBitwise,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVETernaryBitwise)},
	{decode: decodeARM64RawSVEIntegerReduction,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEIntegerReduction)},
	{decode: decodeARM64RawSVEIntegerDot,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEIntegerDot)},
	{decode: decodeARM64RawSVEXAR,
		lower: (*arm64Ctx).lowerARM64RawSVEXAR},
	{decode: decodeARM64RawSVEExtraShift,
		lower: (*arm64Ctx).lowerARM64RawSVEExtraShift},
	{decode: decodeARM64RawSVESplice,
		lower: (*arm64Ctx).lowerARM64RawSVESplice},
	{decode: decodeARM64RawSVEReplicateScalar, memory: arm64RawSVEReadMemory,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEReplicateMemory)},
	{decode: decodeARM64RawSVEReplicateBlock, memory: arm64RawSVEReadMemory,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEReplicateMemory)},
	{decode: decodeARM64RawSVEUnsignedLoad, memory: arm64RawSVEReadMemory,
		lower: (*arm64Ctx).lowerRawSVEUnsignedLoad},
	{decode: decodeARM64RawSVEContiguousMemory, memory: arm64RawSVEMemoryOperand,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEOrdinaryMemory)},
	{decode: decodeARM64RawSVESignedLoad, memory: arm64RawSVEReadMemory,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEOrdinaryMemory)},
	{decode: decodeARM64RawSVEAddSubWide,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEWideningAddSub)},
	{decode: decodeARM64RawSVEMultiplyHigh,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEMultiplyHigh)},
	{decode: decodeARM64RawSVEAddressGeneration,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEAddressGeneration)},
	{decode: decodeARM64RawSVEFloatDivideScale,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEFloatDivideScale)},
	{decode: decodeARM64RawSVEUnpack,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEUnpack)},
	{decode: decodeARM64RawSVEAddPairwiseLong,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEAbsoluteDifference)},
	{decode: decodeARM64RawSVEIntegerMinMax,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEMinMax)},
	{decode: decodeARM64RawSVEIntegerMinMaxReduction,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEMinMax)},
	{decode: decodeARM64RawSVEPTest,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEPredicateState)},
	{decode: decodeARM64RawSVEMOVPRFX,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVEMOVPRFX)},
	{decode: decodeARM64RawSVELast, gpResult: true,
		lower: arm64RawSVENamed((*arm64Ctx).lowerARM64SVELast)},
}

func decodeARM64RawSVEFamily(word uint32) (arm64RawSVEFamily, Instr, bool) {
	for _, family := range arm64RawSVEFamilies {
		if ins, ok := family.decode(word); ok {
			return family, ins, true
		}
	}
	return arm64RawSVEFamily{}, Instr{}, false
}

func (family arm64RawSVEFamily) effects(ins Instr) arm64RawSVEControlEffects {
	var effects arm64RawSVEControlEffects
	last := len(ins.Args) - 1
	for index, arg := range ins.Args {
		if arg.Kind == OpReg {
			if register, gp := arm64StackIndex(arg.Reg); gp {
				mask := uint32(1) << uint(register)
				if family.gpResult && index == last {
					effects.gpWrites |= mask
					if !family.readsResult {
						continue
					}
				}
				effects.gpReads |= mask
			}
		}
		if arg.Kind == OpMem {
			for _, reg := range []Reg{arg.Mem.Base, arg.Mem.Index} {
				if register, gp := arm64StackIndex(reg); gp {
					effects.gpReads |= uint32(1) << uint(register)
				}
			}
			if family.memory != arm64RawSVENoMemory {
				effects.accesses = true
				effects.stores = family.memory == arm64RawSVEMemoryOperand && index == last
			}
		}
	}
	return effects
}
