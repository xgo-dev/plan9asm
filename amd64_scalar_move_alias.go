package plan9asm

import "fmt"

// These are opposite directions of the same 32-bit GP move. Direction is a
// source constraint: neither spelling inherits MOVL's other operand classes.
type x86ScalarMoveAliasSpec struct {
	canonical           Op
	bytes               int64
	load                bool
	rawExtension        bool
	requiresResultProof bool
}

func x86ScalarMoveAliasSpecification(op Op) (x86ScalarMoveAliasSpec, bool) {
	switch op {
	case "MOVQL":
		return x86ScalarMoveAliasSpec{canonical: "MOVL", bytes: 4, requiresResultProof: true}, true
	case "MOVLQZX":
		return x86ScalarMoveAliasSpec{canonical: "MOVL", bytes: 4, load: true, rawExtension: true}, true
	default:
		return x86ScalarMoveAliasSpec{}, false
	}
}

type x86ScalarMoveAliasForm struct {
	spec                x86ScalarMoveAliasSpec
	source, destination Operand
}

func x86ScalarMoveAliasProperties(op Op, ins Instr, arch string) (x86ScalarMoveAliasForm, bool, error) {
	spec, known := x86ScalarMoveAliasSpecification(op)
	if !known {
		return x86ScalarMoveAliasForm{}, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	// Existing physical scalar extensions retain their numerical consumer;
	// the source-only alias view cannot provide native/frame/caller authority.
	if !x86ResultNamedPredicateInstruction(ins) && spec.rawExtension {
		return x86ScalarMoveAliasForm{}, false, nil
	}
	fail := func() (x86ScalarMoveAliasForm, bool, error) {
		return x86ScalarMoveAliasForm{}, true, fmt.Errorf("%s %s requires its original directional 32-bit GP move form: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || ins.Op != op || len(ins.Args) != 2 ||
		!x86ResultNamedPredicateInstruction(ins) {
		return fail()
	}
	gp := func(operand Operand) bool {
		return operand.Kind == OpReg && isX86YrlRegisterForArch(operand.Reg, arch)
	}
	rm := func(operand Operand) bool {
		if gp(operand) {
			return true
		}
		if spec.load && operand.Kind == OpMem {
			// Keep the established extension grammar, including its source
			// offset/macro contract. Storage owners still bind each access.
			return x86MemoryRegistersValidForArch(operand.Mem, arch)
		}
		return isAMD64MemoryOperand(operand) && x86PackedShiftMemoryValid(operand, arch)
	}
	source, destination := ins.Args[0], ins.Args[1]
	memory := destination
	if spec.load {
		memory = source
	}
	if projected, segment, err := x86NamedSegmentMemorySource(ins, memory, arch); segment {
		if err != nil {
			return x86ScalarMoveAliasForm{}, true, err
		}
		if spec.load {
			source = projected
		} else {
			destination = projected
		}
	}
	if spec.load && (!rm(source) || !gp(destination)) || !spec.load && (!gp(source) || !rm(destination)) {
		return fail()
	}
	return x86ScalarMoveAliasForm{spec, source, destination}, true, nil
}

// Consumers use a local value only. Entry validation and each storage owner
// still check the actual mode and original instruction; this projection grants
// no source, address, NUM or producer identity. Ordinary opcodes return without
// allocation, case conversion or textual parsing.
func x86SourceMoveInstruction(ins Instr, arch string) Instr {
	switch ins.Op {
	case "MOVD", "MOVDQ2Q":
		return x86GoMOVQSourceInstruction(ins)
	case "MOVQL", "MOVLQZX":
		if form, known, err := x86ScalarMoveAliasProperties(ins.Op, ins, arch); known && err == nil {
			if !form.spec.load || arch == "386" {
				// The old 32->64 extension keeps its existing consumer. In
				// mode32 both aliases copy one unchanged ordinary GP word.
				ins.Op = form.spec.canonical
			}
		}
	}
	return ins
}

func x86TypedScalarMoveAliasEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86ScalarMoveAliasProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	writeWidth := form.spec.bytes
	if form.spec.load && arch != "386" {
		writeWidth = 8
	}
	return x86TypedByteEffect{requiresResultProof: form.spec.requiresResultProof, operands: []x86TypedByteOperand{
		{index: 0, operand: form.source, width: form.spec.bytes, read: true},
		{index: 1, operand: form.destination, width: writeWidth, write: true},
	}}, true, nil
}
