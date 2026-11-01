package plan9asm

import (
	"fmt"
	"strings"
)

type x86StringRepeatPair struct {
	prefixBlock, prefixInstruction int
	bodyBlock, bodyInstruction     int
}

// The lexical prefix carrier is safe only if every incoming source path to
// its body executes that exact adjacent prefix. Labels emit no instruction,
// but a branch to a label after the prefix must not acquire the skipped byte.
// This is a denial-only CFG check, not a string memory or initialized-byte role.
func (c *amd64Ctx) verifyStringRepeatPrefixes() error {
	_, err := c.stringRepeatSourceBindings()
	return err
}

// Both the result preflight and emission consume this exact complete CFG
// check. A returned pair identifies source nodes, never initialized bytes,
// repeat count, memory backing or permission to perform a native access.
func (c *amd64Ctx) stringRepeatSourceBindings() ([]x86StringRepeatPair, error) {
	hasRepeat := false
	for _, block := range c.blocks {
		for _, ins := range block.instrs {
			if strings.EqualFold(string(ins.Op), "REP") || strings.EqualFold(string(ins.Op), "REPN") {
				hasRepeat = true
				break
			}
		}
		if hasRepeat {
			break
		}
	}
	if !hasRepeat {
		return nil, nil
	}
	// First nonempty block at/after each position. Together with the transition
	// prefix sum below, arbitrarily long label chains are checked once, not once
	// per source prefix. No fixed-point traversal or cycle unrolling is needed.
	next := make([]int, len(c.blocks)+1)
	next[len(c.blocks)] = len(c.blocks)
	for block := len(c.blocks) - 1; block >= 0; block-- {
		next[block] = next[block+1]
		if len(c.blocks[block].instrs) != 0 {
			next[block] = block
		}
	}
	var pairs []x86StringRepeatPair
	for block, body := range c.blocks {
		for instruction, prefix := range body.instrs {
			op := strings.ToUpper(string(prefix.Op))
			if op != "REP" && op != "REPN" {
				continue
			}
			if len(prefix.Args) != 0 {
				return nil, fmt.Errorf("%s %s takes no operands: %q", c.goarch, op, prefix.Raw)
			}
			bodyBlock, bodyInstruction := block, instruction+1
			if bodyInstruction == len(body.instrs) {
				bodyBlock, bodyInstruction = next[block+1], 0
			}
			if bodyBlock == len(c.blocks) {
				return nil, fmt.Errorf("%s %s prefix has no following string instruction", c.goarch, op)
			}
			follower := c.blocks[bodyBlock].instrs[bodyInstruction]
			if _, known, err := x86StringInstructionProperties(follower, c.goarch); known {
				if err != nil {
					return nil, err
				}
			} else if _, _, known := x86PortStringProperties(follower.Op); known {
				// Preserve the existing port-string grammar and native I/O
				// emitter. The common prefix binding creates no I/O permission.
				if len(follower.Args) != 0 {
					return nil, fmt.Errorf("%s %s takes no operands: %q", c.goarch, follower.Op, follower.Raw)
				}
			} else {
				return nil, fmt.Errorf("%s %s prefix is unsupported for %s", c.goarch, op, strings.ToUpper(string(follower.Op)))
			}
			pairs = append(pairs, x86StringRepeatPair{block, instruction, bodyBlock, bodyInstruction})
		}
	}
	if len(pairs) == 0 {
		return nil, nil // Unprefixed source retains its original control contract.
	}
	context := func(reason string) error {
		return fmt.Errorf("%w: %s REP/REPN needs its exact source-adjacent CFG binding: %s", ErrProbeNeedsContext, c.goarch, reason)
	}
	labels := make(map[string]int, len(c.blocks))
	for block, body := range c.blocks {
		if _, duplicate := labels[body.name]; duplicate {
			return nil, context("ambiguous source label")
		}
		labels[body.name] = block
	}
	predecessors, onlyPredecessor := make([]int, len(c.blocks)), make([]int, len(c.blocks))
	for block := range c.blocks {
		successors, valid := c.sourceBlockSuccessors(block, labels)
		if !valid {
			return nil, context("indirect, external or unresolved source control flow")
		}
		for edge, target := range successors {
			if edge > 0 && target == successors[0] {
				continue // Both outcomes of one conditional edge have one predecessor.
			}
			predecessors[target]++
			onlyPredecessor[target] = block
		}
	}
	badThrough := make([]int, len(c.blocks))
	for block := 1; block < len(c.blocks); block++ {
		badThrough[block] = badThrough[block-1]
		if predecessors[block] != 1 || onlyPredecessor[block] != block-1 {
			badThrough[block]++
		}
	}
	for _, pair := range pairs {
		if badThrough[pair.bodyBlock] != badThrough[pair.prefixBlock] {
			return nil, context("a body or intervening label has an incoming edge that skips its prefix")
		}
	}
	return pairs, nil
}
