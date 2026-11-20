package plan9asm

import "fmt"

// Native-target preflights must not disguise malformed WORDs as missing
// target context. This is syntax-only: registered forms still require their
// original source, machine-entry, continuation and layout proofs later.
func arm64RawWordPreflightError(instruction Instr) error {
	if instruction.Op != OpWORD {
		return nil
	}
	word, err := arm64RawWordValue(instruction)
	if err != nil {
		return err
	}
	if arm64RawScalarConversion(word) {
		return nil
	}
	if _, valid := arm64RawContinuationEffectsForWord(word); valid {
		return nil
	}
	if _, valid := arm64RawSVEEffects(word); valid {
		return nil
	}
	// The placeholder only lets the decoder check PC-relative syntax. It is
	// never an edge or source-location witness consumed by translation.
	_, err = decodeARM64RawWordInstructionTarget(instruction, "preflight")
	return err
}

// Go's AWORD constant row is C_LCON, classified before case 14 truncates to
// uint32. Wide MOV/bitmask constants can satisfy that row; arbitrary C_VCON
// values cannot, even when their low word happens to encode a valid opcode.
func arm64RawWordValue(instruction Instr) (uint32, error) {
	for _, operand := range instruction.Args {
		if err := unresolvedSymbolicImmediateError(operand); err != nil {
			return 0, fmt.Errorf("arm64 WORD: %w", err)
		}
	}
	if len(instruction.Args) != 1 || instruction.Args[0].Kind != OpImm ||
		instruction.Args[0].ImmRaw != "" || instruction.Args[0].ImmIsFloat {
		return 0, fmt.Errorf("arm64 WORD expects exactly one resolved integer constant: %q", instruction.Raw)
	}
	value := instruction.Args[0].Imm
	if !arm64GoLCON(value) {
		return 0, fmt.Errorf("arm64 WORD constant does not satisfy Go's C_LCON operand class: %q", instruction.Raw)
	}
	return uint32(value), nil
}
