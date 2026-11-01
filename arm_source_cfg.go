package plan9asm

// The source CFG is shared by native-input and status-initialization proofs.
// It uses the same label/PC-ordinal resolution as lowering, before any LLVM
// block traversal can turn an unreachable writer into an entry-state proof.
func armSourcePredecessors(blocks []armBlock) (preds [][]int, reachable []bool) {
	indices := map[string]int{}
	for i, block := range blocks {
		indices[block.name] = i
	}
	succ := make([][]int, len(blocks))
	ctx := armCtx{blocks: blocks}
	for i, block := range blocks {
		fall := i+1 < len(blocks)
		if len(block.instrs) != 0 {
			last := block.instrs[len(block.instrs)-1]
			op, _, _, _ := armDecodeOp(string(last.Op))
			condition, tail, branch := armKernelBranchForm(last)
			if op == "RET" || op == "UNDEF" || tail && (condition == "" || condition == "AL") {
				fall = false
			}
			if branch && tail && last.armKernelCall == nil && len(last.Args) == 1 {
				if name, ok := ctx.resolveBranchTarget(i, last.Args[0]); ok {
					if target, local := indices[name]; local {
						succ[i] = append(succ[i], target)
					}
				}
			}
		}
		if fall {
			succ[i] = append(succ[i], i+1)
		}
	}
	reachable = make([]bool, len(blocks))
	var visit func(int)
	visit = func(i int) {
		if reachable[i] {
			return
		}
		reachable[i] = true
		for _, target := range succ[i] {
			visit(target)
		}
	}
	if len(blocks) != 0 {
		visit(0)
	}
	preds = make([][]int, len(blocks))
	for i, targets := range succ {
		if reachable[i] {
			for _, target := range targets {
				preds[target] = append(preds[target], i)
			}
		}
	}
	return preds, reachable
}
