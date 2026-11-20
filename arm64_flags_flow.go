package plan9asm

import "fmt"

type arm64FlagMask uint8

const (
	arm64FlagV arm64FlagMask = 1 << iota
	arm64FlagC
	arm64FlagZ
	arm64FlagN
	arm64FlagAll = arm64FlagN | arm64FlagZ | arm64FlagC | arm64FlagV
)

type arm64FlagEffect struct {
	read, write, invalidate arm64FlagMask
	condition               string
}

// Record effects from lowering rather than duplicate the named/raw/SVE opcode
// tables. An incoming flag value is needed only for a read before a local write.
type arm64FlagFlowBlock struct {
	name       string
	successors []string
	effects    []arm64FlagEffect
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
	if flow := c.machineAvailability; flow != nil && !flow.flagsOnly {
		block := &flow.blocks[flow.current]
		block.successors = append(block.successors, targets...)
	}
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
	// Track each original flag independently. Partial writes cannot define the
	// other bits, and an invalidation after a write cannot be hidden by a block
	// summary. OR joins retain an unknown bit from any actual predecessor.
	before := make([]arm64FlagMask, len(flow.blocks))
	before[0] = arm64FlagAll
	seen := make([]bool, len(flow.blocks))
	seen[0] = true
	queue := []int{0}
	queued := make([]bool, len(flow.blocks))
	queued[0] = true
	enqueue := func(i int, unknown arm64FlagMask) {
		changed := !seen[i] || before[i]|unknown != before[i]
		if changed {
			seen[i] = true
			before[i] |= unknown
			if !queued[i] {
				queued[i] = true
				queue = append(queue, i)
			}
		}
	}
	indirectExpanded, returnsExpanded := false, false
	var indirectUnknown, returnsUnknown arm64FlagMask
	for next := 0; next < len(queue); next++ {
		index := queue[next]
		queued[index] = false
		block, unknown := flow.blocks[index], before[index]
		for _, effect := range block.effects {
			if effect.read&unknown != 0 {
				return fmt.Errorf("%w: arm64 condition %s has unknown NZCV bits %#x on a path to block %s",
					ErrProbeNeedsContext, effect.condition, effect.read&unknown, block.name)
			}
			unknown = (unknown &^ effect.write) | effect.invalidate
		}
		for _, name := range block.successors {
			i, ok := flow.indices[name]
			if !ok {
				// The ordinary IR verifier diagnoses undefined branch labels.
				continue
			}
			enqueue(i, unknown)
		}
		if block.indirect && (!indirectExpanded || indirectUnknown|unknown != indirectUnknown) {
			// A computed branch can reach an address-taken source label. Do
			// not misclassify its destination as unreachable. Expand once so
			// multiple indirect branches cannot create quadratic work.
			indirectExpanded = true
			indirectUnknown |= unknown
			for i := range flow.blocks {
				enqueue(i, unknown)
			}
		}
		if block.returns && (!returnsExpanded || returnsUnknown|unknown != returnsUnknown) {
			returnsExpanded = true
			returnsUnknown |= unknown
			for _, i := range flow.continuations {
				enqueue(i, unknown)
			}
		}
	}
	return nil
}
