package plan9asm

// Zero is absent, not evidence for VEX. The complete decoder captures this
// physical mode/generation before any lowering-local numerical projection.
type x86RawCOMIIdentity struct {
	arch          string
	encoded, evex bool
}

func x86COMIRawIdentity(ins Instr, arch string) x86RawCOMIIdentity {
	form, known, err := x86COMIProperties(ins, arch)
	if !known || err != nil || !form.spec.vector {
		return x86RawCOMIIdentity{}
	}
	return x86RawCOMIIdentity{arch, ins.x86Encoded, ins.x86ScalarFlagCompareEVEX}
}

func x86RawCOMISource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	identity := x86COMIRawIdentity(ins, arch)
	return origin != nil && identity.arch != "" && origin.comi.arch == arch &&
		origin.comi == identity && x86RawOrdinaryVectorSource(ins, arch)
}

// Check immutable decoded inventory before named/strict success too. Erasing
// an origin cannot launder a physical comparison into a genuine named source.
// Replay is restriction-only: it supplies no numerical input or entry role.
func x86COMIRawReplayRequired(fn Func, arch string) bool {
	hasRaw := func(instructions []Instr) bool {
		for _, instruction := range instructions {
			form, known, _ := x86COMIProperties(instruction, arch)
			if known && form.spec.vector && (instruction.x86SourceRaw != nil ||
				instruction.x86Encoded || instruction.x86ScalarFlagCompareEVEX) {
				return true
			}
		}
		return false
	}
	return hasRaw(fn.Instrs) || fn.x86RawReplay != nil && hasRaw(fn.x86RawReplay.decoded)
}

// Only paired lowering projects an exact ordinary raw comparison onto the
// existing complete scalar byte/FLAGS effect. RIP DATA, native entry, private
// frames and reusable pointee facts retain their independent owners.
func x86LoweredRawCOMIStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	form, known, err := x86COMIProperties(ins, arch)
	if !known || !form.spec.vector {
		return false, false
	}
	if err != nil || !x86RawCOMISource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	return x86ResultCOMIStepWithRead(local, state, owned, arch, true)
}
