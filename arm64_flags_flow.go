package plan9asm

import "fmt"

// Record effects from lowering rather than duplicate the named/raw/SVE opcode
// tables. An incoming flag value is needed only for a read before a local write.
type arm64FlagFlowBlock struct {
	name       string
	successors []string
	writes     bool
	condition  string
	indirect   bool
	returns    bool
}

type arm64FlagFlow struct {
	current       int
	blocks        []arm64FlagFlowBlock
	indices       map[string]int
	continuations []int
}

func newARM64FlagFlow(blocks []arm64Block) *arm64FlagFlow {
	flow := &arm64FlagFlow{
		blocks:  make([]arm64FlagFlowBlock, len(blocks)),
		indices: make(map[string]int, len(blocks)),
	}
	for i, block := range blocks {
		flow.blocks[i].name = block.name
		flow.indices[block.name] = i
		if i+1 < len(blocks) && len(block.instrs) != 0 && arm64IsLocalBranchLink(block.instrs[len(block.instrs)-1]) {
			flow.continuations = append(flow.continuations, i+1)
		}
	}
	return flow
}

func (c *arm64Ctx) recordARM64FlagFlowEdges(targets ...string) {
	if c.flagFlow != nil {
		block := &c.flagFlow.blocks[c.flagFlow.current]
		block.successors = append(block.successors, targets...)
	}
}

func (c *arm64Ctx) emitPredicateBranch(predicate, target, fall string) {
	c.recordARM64FlagFlowEdges(target, fall)
	fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", predicate, arm64LLVMBlockName(target), arm64LLVMBlockName(fall))
}

func (flow *arm64FlagFlow) validate() error {
	if len(flow.blocks) == 0 {
		return nil
	}
	// Follow paths that have not written flags. A write stops propagation;
	// reaching a read first is an actual missing-context path. This worklist
	// handles joins, backedges and unreachable blocks in O(blocks + edges).
	seen := make([]bool, len(flow.blocks))
	seen[0] = true
	queue := []int{0}
	enqueue := func(i int) {
		if !seen[i] {
			seen[i] = true
			queue = append(queue, i)
		}
	}
	indirectExpanded, returnsExpanded := false, false
	for next := 0; next < len(queue); next++ {
		block := flow.blocks[queue[next]]
		if block.condition != "" {
			return fmt.Errorf("%w: arm64 condition %s has no prior flags write on a path to block %s",
				ErrProbeNeedsContext, block.condition, block.name)
		}
		if block.writes {
			continue
		}
		for _, name := range block.successors {
			i, ok := flow.indices[name]
			if !ok {
				// The ordinary IR verifier diagnoses undefined branch labels.
				continue
			}
			enqueue(i)
		}
		if block.indirect && !indirectExpanded {
			// A computed branch can reach an address-taken source label. Do
			// not misclassify its destination as unreachable. Expand once so
			// multiple indirect branches cannot create quadratic work.
			indirectExpanded = true
			for i := range flow.blocks {
				enqueue(i)
			}
		}
		if block.returns && !returnsExpanded {
			returnsExpanded = true
			for _, i := range flow.continuations {
				enqueue(i)
			}
		}
	}
	return nil
}
