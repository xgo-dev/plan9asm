package plan9asm

import (
	"math/bits"
	"strings"

	"github.com/xgo-dev/llvm"
)

type armTailSlotEffects struct {
	reads, writes uint64
}

// Check the exact emitted register/flag/result-slot operations before LLVM
// promotion. An uninitialized read must fail even if optimization drops it.
func proveSDKARMTailDefinitions(fn llvm.Value) error {
	if fn.IsNil() || fn.BasicBlocksCount() == 0 {
		return sdkASMDataContext("ARM ABI0 caller has no emitted body")
	}
	var blocks []llvm.BasicBlock
	indices := make(map[llvm.BasicBlock]int)
	for b := fn.FirstBasicBlock(); !b.IsNil(); b = llvm.NextBasicBlock(b) {
		indices[b] = len(blocks)
		blocks = append(blocks, b)
	}
	slots := make(map[llvm.Value]uint64)
	var names []string
	for inst := blocks[0].FirstInstruction(); !inst.IsNil(); inst = llvm.NextInstruction(inst) {
		if inst.IsAAllocaInst().IsNil() || !sdkARMTailSlot(inst.Name()) {
			continue
		}
		if len(names) == 64 {
			return sdkASMDataContext("ARM ABI0 caller has too many virtual frame slots")
		}
		slots[inst] = uint64(1) << len(names)
		names = append(names, inst.Name())
	}
	effects := make([]armTailSlotEffects, len(blocks))
	edges := make([][]int, len(blocks))
	for i, block := range blocks {
		for inst := block.FirstInstruction(); !inst.IsNil(); inst = llvm.NextInstruction(inst) {
			for op := 0; op < inst.OperandsCount(); op++ {
				mask := slots[inst.Operand(op)]
				if mask == 0 {
					continue
				}
				switch {
				case !inst.IsALoadInst().IsNil() && op == 0:
					effects[i].reads |= mask &^ effects[i].writes
				case !inst.IsAStoreInst().IsNil() && op == 1:
					effects[i].writes |= mask
				default:
					return sdkASMDataContext("ARM ABI0 caller %q exposes virtual slot %q", fn.Name(), names[bits.TrailingZeros64(mask)])
				}
			}
		}
		term := block.LastInstruction()
		for j := 0; j < term.SuccessorsCount(); j++ {
			edges[i] = append(edges[i], indices[term.Successor(j)])
		}
	}
	preds, reachable := armSourcePredecessorsFromEdges(edges)
	// Meet at joins. Start reachable non-entry blocks at top and descend
	// until backedges can no longer change the set of guaranteed writes.
	in, out := make([]uint64, len(blocks)), make([]uint64, len(blocks))
	top := (uint64(1) << len(names)) - 1
	for i := range out {
		out[i] = top
	}
	for changed := true; changed; {
		changed = false
		for i, sources := range preds {
			if !reachable[i] {
				continue
			}
			before := top
			if i == 0 {
				before = 0
			}
			for _, pred := range sources {
				before &= out[pred]
			}
			in[i] = before
			after := before | effects[i].writes
			if out[i] != after {
				out[i], changed = after, true
			}
		}
	}
	for i := range blocks {
		missing := effects[i].reads &^ in[i]
		if reachable[i] && missing != 0 {
			return sdkASMDataContext("ARM ABI0 caller %q reads undefined %s in block %q", fn.Name(),
				names[bits.TrailingZeros64(missing)], blocks[i].AsValue().Name())
		}
	}
	return nil
}

func sdkARMTailSlot(name string) bool {
	return strings.HasPrefix(name, "reg_") || strings.HasPrefix(name, "flags_") || strings.HasPrefix(name, "fp_ret_")
}
