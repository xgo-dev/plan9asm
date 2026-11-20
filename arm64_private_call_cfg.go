package plan9asm

import "reflect"

// CALL helpers have no independently callable Go/LLVM signature. The original
// source, audited helper bodies and exact cloned CFG stay sealed through final
// lowering. Reusing a prepared Func after editing it cannot retain admission.
type arm64PrivateCallSource struct {
	original Func
	helpers  []Func
	prepared Func
}

func validateARM64PrivateCallSource(fn Func) error {
	proof := fn.arm64PrivateCallSource
	if proof == nil {
		if fn.arm64PrivateRegisterEntry {
			return arm64GoABIContext("private call root lost its complete source continuation")
		}
		return nil
	}
	if !fn.arm64PrivateRegisterEntry || len(proof.helpers) == 0 ||
		!reflect.DeepEqual(arm64PrivateTailSnapshot(fn), proof.prepared) ||
		proof.original.Sym != fn.Sym || proof.original.FrameSize != fn.FrameSize || proof.original.ArgSize != fn.ArgSize {
		return arm64GoABIContext("private call root changed its sealed source continuation")
	}
	if proof.prepared.arm64PrivateUnexposedFrame != arm64CallFrameUnexposed(proof.original) {
		return arm64GoABIContext("private call root changed its original frame-escape observation")
	}
	for _, helper := range proof.helpers {
		if err := arm64PrivateRegisterLeaf(helper); err != nil {
			return err
		}
	}
	return nil
}

func arm64PrivateCallDataRegister(reg Reg) bool {
	// R26 is ordinary explicitly initialized data here, not an implicit closure
	// input. The independent root closure/availability proofs still apply.
	// Floating/vector CALL continuations need their own initialized-input and
	// runtime contracts. Do not inherit the independently tested tail domain.
	return arm64PrivateDataGP(reg)
}

// CALL roots and their complete helpers independently reject every explicit
// R27 operand. Registered immediate rows may therefore materialize a constant
// in that unobserved scratch register. Reuse the exact ordered encoder grammar:
// no guessed opcode mask, arbitrary implicit effect or faulting expansion is
// admitted. Lowering and whole-root availability still record the real write.
func arm64PrivateCallImmediateScratch(op Op, ins Instr, form arm64GPDataForm) bool {
	immediate, handled, err := parseARM64GPImmediateForm(op, ins)
	return handled && err == nil && immediate.scratch && !immediate.trailingUDF &&
		form.scratch != nil && len(form.implicit) == 1 && form.implicit[0] == "R27"
}

// Check every original component, not only entry-reachable blocks. The bounded
// CALL family admits a DAG, including multiple RETs and lexical backward edges
// that do not form a cycle; recursion and loops need separate contracts.
func arm64PrivateCallAcyclic(fn Func) error {
	if len(fn.Instrs) > arm64PrivateRegisterExpansionBudget {
		return arm64GoABIContext("private call helper exceeds its bounded source graph")
	}
	labels := make(map[string]int)
	for i, ins := range fn.Instrs[1:] {
		if ins.Op == OpLABEL {
			labels[ins.Args[0].Sym] = i + 1
		}
	}
	edges := make([][]int, len(fn.Instrs))
	degree := make([]int, len(fn.Instrs))
	for i, ins := range fn.Instrs[1:] {
		index := i + 1
		if ins.Op == OpRET {
			continue
		}
		branch := ins.Op == "B" || ins.Op == "JMP" || arm64IsConditionalBranch(ins.Op)
		if branch {
			last := ins.Args[len(ins.Args)-1]
			target, found := labels[last.Ident]
			if !found {
				return arm64GoABIContext("private call helper has an unbound branch target")
			}
			edges[index] = append(edges[index], target)
			degree[target]++
		}
		if ins.Op != "B" && ins.Op != "JMP" {
			if index+1 == len(fn.Instrs) {
				return arm64GoABIContext("private call helper falls outside its original source")
			}
			edges[index] = append(edges[index], index+1)
			degree[index+1]++
		}
	}
	queue := make([]int, 0, len(fn.Instrs)-1)
	for i := 1; i < len(degree); i++ {
		if degree[i] == 0 {
			queue = append(queue, i)
		}
	}
	for next := 0; next < len(queue); next++ {
		for _, target := range edges[queue[next]] {
			degree[target]--
			if degree[target] == 0 {
				queue = append(queue, target)
			}
		}
	}
	if len(queue) != len(fn.Instrs)-1 {
		return arm64GoABIContext("private call helper has an unproved cyclic source CFG")
	}
	return nil
}
