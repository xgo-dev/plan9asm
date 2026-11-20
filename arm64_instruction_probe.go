package plan9asm

import "fmt"

// The isolated coverage harness owns this source identity. It is not the
// original function's frame or a declaration of its native encoder layout.
// Its instructions end with B (ZR), never an executable caller-return claim.
const arm64InstructionProbeTEXT = "TEXT plan9asm_probe(SB),516,$0-0\n"

func arm64InstructionProbeFunc(instrs []Instr) (Func, error) {
	for _, ins := range instrs {
		if ins.Op == OpTEXT {
			return Func{}, fmt.Errorf("%w: isolated ARM64 probes cannot replace their compile-only TEXT fixture", ErrProbeNeedsContext)
		}
	}
	fixture, err := Parse(ArchARM64, arm64InstructionProbeTEXT)
	if err != nil {
		return Func{}, fmt.Errorf("parse ARM64 instruction probe TEXT fixture: %w", err)
	}
	fn := fixture.Funcs[0]
	// Keep the caller's actual operand/source representation and private
	// decoder markers. Parsing the fixed header never decodes a named pseudo
	// instruction or reconstructs operands from its diagnostic Raw text.
	fn.Instrs = append(fn.Instrs, instrs...)
	return fn, nil
}
