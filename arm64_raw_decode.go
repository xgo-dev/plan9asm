package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

// decodeARM64RawWordInstruction uses Go's architecture decoder to recover a
// Plan 9 instruction from a WORD that is not covered by a specialized decoder.
// The caller must run the returned instruction through the regular semantic
// lowerers; decoding by itself never counts as supported.
func decodeARM64RawWordInstruction(ins Instr) (Instr, error) {
	return decodeARM64RawWordInstructionTarget(ins, "")
}

// decodeARM64RawWordInstructionTarget decodes one raw instruction. When the
// instruction contains a PC-relative operand, target must be the exact source
// label established by normalizeARM64RawPCRelative. Keeping the layout proof
// out of this context-free decoder prevents guessed control-flow edges.
func decodeARM64RawWordInstructionTarget(ins Instr, target string) (Instr, error) {
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return Instr{}, fmt.Errorf("arm64 WORD expects exactly one resolved integer constant: %q", ins.Raw)
	}
	word := uint32(ins.Args[0].Imm)
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	decoded, err := arm64asm.Decode(code[:])
	if err != nil {
		return Instr{}, fmt.Errorf("decode ARM64 WORD %#08x: %w", word, err)
	}
	pcRelative := 0
	for _, arg := range decoded.Args {
		if arg == nil {
			break
		}
		if _, ok := arg.(arm64asm.PCRel); ok {
			pcRelative++
		}
	}
	if pcRelative != 0 && target == "" {
		return Instr{}, fmt.Errorf("ARM64 WORD %#08x is PC-relative and cannot be mapped safely to source labels: %q", word, ins.Raw)
	}
	if pcRelative > 1 {
		return Instr{}, fmt.Errorf("ARM64 WORD %#08x has %d PC-relative operands: %q", word, pcRelative, ins.Raw)
	}
	syntax := decodedARM64GoSyntax(decoded)
	file, err := Parse(ArchARM64, "TEXT decoded(SB), $0-0\n"+syntax+"\n")
	if err != nil {
		return Instr{}, fmt.Errorf("parse decoded ARM64 WORD %#08x as %q: %w", word, syntax, err)
	}
	if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 2 {
		return Instr{}, fmt.Errorf("decoded ARM64 WORD %#08x produced an invalid instruction sequence %q", word, syntax)
	}
	result := file.Funcs[0].Instrs[1]
	if pcRelative != 0 {
		replaced := 0
		for i := range result.Args {
			if result.Args[i].Kind == OpMem && result.Args[i].Mem.Base == PC {
				result.Args[i] = Operand{Kind: OpIdent, Ident: target}
				replaced++
			}
		}
		if replaced != pcRelative {
			return Instr{}, fmt.Errorf("decoded ARM64 WORD %#08x as %q but replaced %d/%d PC-relative operands", word, syntax, replaced, pcRelative)
		}
	}
	result.Raw = fmt.Sprintf("%s /* decoded from %s */", result.Raw, ins.Raw)
	return result, nil
}

func decodedARM64GoSyntax(inst arm64asm.Inst) string {
	// x/arch's typed decoder knows the complete structure family, but its
	// Plan 9 printer handles operand order and post-index suffixes only for
	// LD1/ST1. Reuse those printer rules with the original typed operands and
	// restore the real opcode. Guard on the arranged-list type: single-lane
	// instructions have a different operand grammar and their own lowerer.
	if _, arranged := inst.Args[0].(arm64asm.RegisterWithArrangement); arranged {
		original := inst.Op
		switch original {
		case arm64asm.LD2, arm64asm.LD3, arm64asm.LD4,
			arm64asm.LD1R, arm64asm.LD2R, arm64asm.LD3R, arm64asm.LD4R:
			inst.Op = arm64asm.LD1
		case arm64asm.ST2, arm64asm.ST3, arm64asm.ST4:
			inst.Op = arm64asm.ST1
		}
		if inst.Op != original {
			syntax := arm64asm.GoSyntax(inst, 0, nil, nil)
			return "V" + original.String() + strings.TrimPrefix(syntax, "V"+inst.Op.String())
		}
	}
	syntax := arm64asm.GoSyntax(inst, 0, nil, nil)
	op, rest, hasArgs := strings.Cut(syntax, " ")
	if !hasArgs {
		rest = ""
	}
	if op == "NOOP" {
		return "NOP"
	}
	// x/arch v0.14 predates cmd/asm spellings for the unscaled signed-offset
	// load aliases and prints names such as LDURBW. Canonicalize the complete
	// integer family to the same MOV forms used for the corresponding LDR
	// instructions so the regular width/sign-aware lowerers provide semantics.
	switch inst.Op {
	case arm64asm.MVN:
		// x/arch calls the Advanced SIMD bitwise-not alias MVN and
		// prints it as VMVN. Go's assembler names this form VNOT.
		// Keep the scalar integer MVN spelling untouched.
		if strings.HasPrefix(rest, "V") {
			op = "VNOT"
		}
	case arm64asm.LDURB:
		op = "MOVBU"
	case arm64asm.LDURH:
		op = "MOVHU"
	case arm64asm.LDURSB:
		op = "MOVB"
		if arm64DecodedDestinationIsWord(inst) {
			op = "MOVBW"
		}
	case arm64asm.LDURSH:
		op = "MOVH"
		if arm64DecodedDestinationIsWord(inst) {
			op = "MOVHW"
		}
	case arm64asm.LDURSW:
		op = "MOVW"
	}
	// x/arch v0.12 is the last decoder usable by this module's Go 1.20
	// baseline. Its Plan 9 printer omits the V prefix for these Advanced SIMD
	// forms; the operand arrangement tells them apart from their scalar forms.
	if strings.HasPrefix(rest, "V") {
		switch op {
		case "FABS", "FNEG", "FSQRT", "FRINTN", "FRINTP", "FRINTM", "FRINTZ", "FRINTA", "FRINTX", "FRINTI",
			"FCVTZS", "FCVTZU", "SCVTF", "UCVTF", "FMAXV", "FMINV", "FMAXNMV", "FMINNMV":
			op = "V" + op
		}
	}
	// Go's named reduction syntax spells the scalar destination as a bare V
	// register, while the architecture decoder prints the aliased F register.
	// Canonicalize raw reductions through the exact named-form lowerer.
	if op == "VFMAXV" || op == "VFMINV" || op == "VFMAXNMV" || op == "VFMINNMV" {
		if separator := strings.LastIndex(rest, ", F"); separator >= 0 {
			rest = rest[:separator] + ", V" + rest[separator+3:]
		}
	}
	// The x/arch printer emits LDPSW's two destinations as separate operands,
	// unlike the pair operand accepted by Go's assembler and our pair lowerer.
	if inst.Op == arm64asm.LDPSW {
		operands := strings.Split(rest, ", ")
		if len(operands) == 3 {
			// The printer also reverses Rt and Rt2 in this three-operand
			// spelling. The pair lowerer consumes them in memory order.
			rest = operands[0] + ", (" + operands[2] + ", " + operands[1] + ")"
		}
	}
	if rest == "" {
		return op
	}
	return op + " " + rest
}

func arm64DecodedDestinationIsWord(inst arm64asm.Inst) bool {
	reg, ok := inst.Args[0].(arm64asm.Reg)
	return ok && reg >= arm64asm.W0 && reg <= arm64asm.WZR
}
