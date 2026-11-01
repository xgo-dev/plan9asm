package plan9asm

import "fmt"

// Project only named x86 memory syntax, not a pointer or initialized-byte
// witness. In Go's encoder an FS/GS Index is a segment annotation: prefixof
// selects it and asmandsz ignores its Scale. A segment used as Base cannot
// accompany a real scaled GP Index. Keep the original instruction untouched;
// each paired consumer uses this same normalized operand for proof/emission.
func x86NamedSegmentMemorySource(ins Instr, source Operand, arch string) (Operand, bool, error) {
	if source.Kind != OpMem || !x86ResultNamedPredicateInstruction(ins) {
		// The physical decoder already supplies normalized segment fields.
		// It must not be reclassified as named Go syntax or borrow a named
		// instruction's separate input/source proof.
		return source, false, nil
	}
	memory := source.Mem
	annotation := memory.Index == FS || memory.Index == GS
	if memory.Segment == "" && !annotation {
		return source, false, nil
	}
	fail := func() (Operand, bool, error) {
		return source, true, fmt.Errorf("%w: invalid %s named segment memory: %q", ErrProbeNeedsContext, arch, ins.Raw)
	}
	if arch != "386" && arch != "amd64" ||
		ins.x86NumericalRead != nil || memory.Sym != "" || memory.OffRaw != "" || memory.IndexExt != "" {
		return fail()
	}
	if annotation {
		if memory.Segment != "" || (memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8) {
			return fail()
		}
		memory.Segment, memory.Index, memory.Scale = memory.Index, "", 0
	}
	if memory.Segment != FS && memory.Segment != GS || memory.Index != "" || memory.Scale != 0 {
		return fail()
	}
	projected := source
	projected.Mem = memory
	if !x86PackedShiftMemoryValid(projected, arch) {
		return fail()
	}
	return projected, true, nil
}

// This is a mandatory source/result-proof selector, not an admission rule.
// Even a malformed segment form or physical SP/BP address must reach the
// complete check rather than disappear behind a MOV-store cost heuristic.
// Void functions also owe the actual numerical address inputs of dead reads.
func x86NamedSegmentMOVNeedsProof(ins Instr, arch string) bool {
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpMem || ins.Args[1].Kind != OpReg {
		return false
	}
	canonical := x86SourceMoveInstruction(ins, arch)
	width := x86RawReturnScalarMoveBytes(canonical.Op)
	if width == 0 {
		return false
	}
	register := ins.Args[1].Reg
	validRegister := isX86YrlRegisterForArch(register, arch)
	if width == 1 {
		validRegister = isGoYmbRegisterForArch(register, arch)
	}
	if !validRegister {
		return false // MMX, SIMD and system-register rows retain their own roles.
	}
	_, segment, _ := x86NamedSegmentMemorySource(ins, ins.Args[0], arch)
	return segment
}
