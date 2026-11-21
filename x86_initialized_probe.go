package plan9asm

import (
	"fmt"
	"strings"
)

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

// InitializedVectorRegisterProbeSequence builds an object-only probe for
// named x86 forms with a typed effect and register or literal operands. It
// defines the explicit registers (including masked merge destinations) and
// any implicit register reads listed in the effect. The original instruction
// is retained unchanged.
func InitializedVectorRegisterProbeSequence(goarch string, ins Instr) ([]Instr, bool, error) {
	if goarch != "386" && goarch != "amd64" || !x86ResultNamedPredicateInstruction(ins) ||
		x86Mode32VectorRegisterContext(ins, goarch) != nil {
		return nil, false, nil
	}
	effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, goarch)
	if !known || err != nil || effect.dynamicMemory || effect.flagsRead != 0 {
		return nil, false, nil
	}

	var widths [32]int
	var masks [8]bool
	var gp []Reg
	seenGP := make(map[Reg]bool)
	hasVector := false
	add := func(operand Operand) bool {
		if operand.Kind == OpImm {
			return operand.ImmRaw == ""
		}
		if operand.Kind != OpReg {
			return false
		}
		reg := operand.Reg
		width := amd64VectorByteWidth(reg)
		if index, vector := amd64VectorRegisterIndex(reg, width); vector {
			if index >= len(widths) || goarch == "386" && index >= 8 {
				return false
			}
			if width > widths[index] {
				widths[index] = width
			}
			hasVector = true
			return true
		}
		if index, mask := amd64ParseKReg(reg); mask {
			masks[index] = true
			return true
		}
		root, valid := x86CallerGP(reg)
		if !valid || !isX86YrlRegisterForArch(root, goarch) || x86LogicalSourceFrameRegister(root, goarch) {
			return false
		}
		if !seenGP[root] {
			gp = append(gp, root)
			seenGP[root] = true
		}
		return true
	}
	for _, operand := range ins.Args {
		if !add(operand) {
			return nil, false, nil
		}
	}
	for _, input := range effect.operands {
		if input.operand.Kind == OpMem || input.operand.Kind == OpSym {
			return nil, false, nil
		}
		if input.read && !add(input.operand) {
			return nil, false, nil
		}
	}
	if !hasVector {
		return nil, false, nil
	}

	var sequence []Instr
	for index, used := range masks {
		if !used {
			continue
		}
		if len(sequence) == 0 {
			sequence = append(sequence, x86ProbeInstruction("MOVL", Operand{Kind: OpImm, Imm: -1}, Operand{Kind: OpReg, Reg: AX}))
		}
		mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", index))}
		sequence = append(sequence, x86ProbeInstruction("KMOVD", Operand{Kind: OpReg, Reg: AX}, mask))
	}
	for _, reg := range gp {
		sequence = append(sequence, x86ProbeInstruction("MOVL", Operand{Kind: OpImm, Imm: 1}, Operand{Kind: OpReg, Reg: reg}))
	}
	for index, width := range widths {
		if width == 0 {
			continue
		}
		switch {
		case index >= 16 || width == 64:
			z := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d", index))}
			sequence = append(sequence, x86ProbeInstruction("VPXORD", z, z, z))
		case width == 32:
			y := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", index))}
			sequence = append(sequence, x86ProbeInstruction("VXORPS", y, y, y))
		default:
			x := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", index))}
			sequence = append(sequence, x86ProbeInstruction("XORPS", x, x))
		}
	}
	return append(sequence, ins), true, nil
}

func x86ProbeInstruction(op Op, operands ...Operand) Instr {
	args := make([]string, len(operands))
	for i, operand := range operands {
		args[i] = operand.String()
	}
	return Instr{Op: op, Raw: string(op) + " " + strings.Join(args, ","), Args: operands}
}
