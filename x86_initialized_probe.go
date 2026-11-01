package plan9asm

import "fmt"

// InitializedMaskLogicalProbeSequence constructs a counterfactual source probe
// for the complete K-register logical family. It is not evidence about the
// original program's inputs, a source binding, or permission to access memory.
// The returned sequence explicitly initializes only the actual mask inputs and
// retains the original instruction. Callers must probe/translate it separately.
func InitializedMaskLogicalProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	spec, known, err := x86MaskLogicalProperties(ins.Op, ins, goarch)
	if !known || err != nil {
		return nil, known, err
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return nil, true, fmt.Errorf("initialized mask logical probe requires an exact named instruction, not raw encoding or address overrides")
	}
	inputs := 2
	if spec.kind == amd64MaskNot {
		inputs = 1
	}
	sequence := []Instr{{
		Op: "MOVL", Raw: "MOVL $3,AX",
		Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: "AX"}},
	}}
	seen := make(map[Reg]bool)
	for _, input := range ins.Args[:inputs] {
		if seen[input.Reg] {
			continue
		}
		seen[input.Reg] = true
		sequence = append(sequence, Instr{
			Op: "KMOVD", Raw: fmt.Sprintf("KMOVD AX,%s", input.Reg),
			Args: []Operand{{Kind: OpReg, Reg: "AX"}, input},
		})
	}
	return append(sequence, ins), true, nil
}
