package plan9asm

import "fmt"

// This producer-specific descriptor distinguishes a finite architectural
// choice from an unavailable source. It is consumed only by the paired
// lowerer, after all actual data, count, carry and address inputs validate.
// flagsChoice is descriptive, not permission derived from flagsKilled.
type x86ScalarShiftOutcome struct {
	flagsFromOld uint8
	flagsFinite  uint8
	flagsChoice  uint8
	valueChoice  bool
}

func (f x86ScalarShiftForm) outcome() x86ScalarShiftOutcome {
	out := x86ScalarShiftOutcome{flagsFromOld: x86ByteFlagsAll}
	count, variable := f.maskedCount(), f.count.Kind == OpReg
	if f.bmi2 || !variable && count == 0 {
		return out
	}
	rotate := f.stem == "RCL" || f.stem == "RCR" || f.stem == "ROL" || f.stem == "ROR"
	if rotate {
		carry := f.stem == "RCL" || f.stem == "RCR"
		if !variable && carry && count%int64(f.bits+1) == 0 {
			return out // A zero-bit carry rotate retains every old flag.
		}
		if variable || count != 1 {
			out.flagsChoice = x86ByteFlagOF
		}
		if !variable {
			out.flagsFinite = x86ByteFlagCF | x86ByteFlagOF
			out.flagsFromOld &^= out.flagsFinite
		}
		return out
	}
	out.flagsChoice = x86ByteFlagAF
	if variable || count != 1 {
		out.flagsChoice |= x86ByteFlagOF
	}
	if f.double && f.bits == 16 && (variable || count > 16) {
		out.valueChoice, out.flagsChoice = true, x86ByteFlagsAll
	} else if !f.double && f.bits < 32 && f.stem != "SAR" && (variable || count >= int64(f.bits)) {
		out.flagsChoice |= x86ByteFlagCF
	}
	if !variable {
		out.flagsFromOld, out.flagsFinite = 0, x86ByteFlagsAll
	}
	// A variable count can be zero. Even if every nonzero arm defines a
	// finite flag, its zero-count arm still needs that actual old flag.
	return out
}

func (out x86ScalarShiftOutcome) availableFlags(before uint8) uint8 {
	return before&out.flagsFromOld | out.flagsFinite
}

// Freeze only a selected ISA-undefined output, once at its producer. The
// guarded consumer retains its original zero/defined arms; no missing input,
// unwritten byte, pointer, native flag or CFG-joined poison is frozen here.
func (c *amd64Ctx) emitScalarShiftArchitecturalChoice(typ LLVMType, when, otherwise string) string {
	choice, selected := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = freeze %s poison\n", choice, typ)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %%%s, %s %s\n", selected, when, typ, choice, typ, otherwise)
	return "%" + selected
}
