package plan9asm

import "fmt"

// Go has five VEX+EVEX D/Q members and four EVEX-only W/Q members.
// All use per-element counts, not the scalar count of VPSLL/PSRL/PSRA.
func decodedX86PerLaneVariableShiftInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	// F3.0F38 opcodes 10-12 are single-source narrowing instructions,
	// not a malformed 66.0F38 per-lane shift. Other wrong prefixes remain
	// owned here so callers get an explicit invalid-form diagnostic.
	if !matched || p.mapNumber != 2 || p.pp == 2 {
		return Instr{}, 0, false, nil
	}
	var op Op
	var spec amd64PerLaneVariableShiftSpec
	owned := false
	for name, candidate := range amd64PerLaneVariableShiftSpecs {
		if int(candidate.opcode) != p.opcode {
			continue
		}
		owned = true
		if p.w == (candidate.laneBits != 32) {
			op, spec = Op(name), candidate
			break
		}
	}
	if !owned {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("per-lane variable shift: %s", message)
	}
	if op == "" {
		return fail("invalid element width bit")
	}
	if !p.evex && !spec.vex {
		return fail("instruction requires EVEX encoding")
	}

	return decodedX86BinaryVectorOperands(code, p, mode, op, spec.laneBits)
}
