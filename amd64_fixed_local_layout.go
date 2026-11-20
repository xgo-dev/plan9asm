package plan9asm

import "reflect"

// Nodes are source CFG boundaries with distinct private layouts. Edge order is
// the source CFG order; -1 is infeasible and -2 is an ordinary final return.
type x86FixedLocalLayoutNode struct {
	pc, end int
	targets [2]int
}

type x86FixedLocalLayoutGraph struct {
	nodes    []x86FixedLocalLayoutNode
	retained int64 // First-phase graph and new layout series during final replay.
	series   int64 // Newly allocated layout series in the previous residue.
}

type x86FixedLocalLayouts struct {
	reference []x86FixedLocalLayoutNode
	nodes     []x86FixedLocalLayoutNode
	at        map[int][]int
}

func newFixedLocalLayouts(reference []x86FixedLocalLayoutNode) x86FixedLocalLayouts {
	count := len(reference)
	if count == 0 {
		count = 1
	}
	result := x86FixedLocalLayouts{reference: reference, nodes: make([]x86FixedLocalLayoutNode, count), at: map[int][]int{0: {0}}}
	for index := range result.nodes {
		result.nodes[index].targets = [2]int{-1, -1}
		if len(reference) != 0 {
			result.nodes[index].pc = reference[index].pc
			if index != 0 {
				pc := reference[index].pc
				result.at[pc] = append(result.at[pc], index)
			}
		}
	}
	return result
}

func (layouts *x86FixedLocalLayouts) target(states map[int]x86FixedLocalState, from, edge, pc int, next x86FixedLocalState,
	budget *x86FixedLocalBudget) (int, error) {
	match := -1
	for _, index := range layouts.at[pc] {
		prior, found := states[index]
		if err := budget.consumeOrigins(64 + 2*fixedLocalStateWork(prior) + fixedLocalStateWork(next)); err != nil {
			return 0, err
		}
		if !found {
			continue
		}
		if err := fixedLocalLayoutRoles(prior, next); err != nil {
			return 0, err
		}
		if reflect.DeepEqual(prior.pointers, next.pointers) && reflect.DeepEqual(prior.addresses, next.addresses) {
			match = index
		}
	}
	if len(layouts.reference) != 0 {
		match = layouts.reference[from].targets[edge]
		if match < 0 || match >= len(layouts.nodes) || layouts.nodes[match].pc != pc {
			return 0, goAMD64FrameContext("fixed local layout edge depends on original SP residue")
		}
	} else if match < 0 {
		match = len(layouts.nodes)
		layouts.nodes = append(layouts.nodes, x86FixedLocalLayoutNode{pc: pc, targets: [2]int{-1, -1}})
	}
	if _, found := states[match]; !found && len(layouts.reference) == 0 {
		layouts.at[pc] = append(layouts.at[pc], match)
	}
	layouts.nodes[from].targets[edge] = match
	return match, nil
}

func fixedLocalLayoutRoles(first, last x86FixedLocalState) error {
	if len(first.pointers) != len(last.pointers) || len(first.addresses) != len(last.addresses) || first.pointers[SP] != last.pointers[SP] {
		return goAMD64FrameContext("fixed local CFG private roles disagree")
	}
	for reg := range first.pointers {
		if _, found := last.pointers[reg]; !found {
			return goAMD64FrameContext("fixed local CFG private roles disagree")
		}
	}
	for offset := range first.addresses {
		if _, found := last.addresses[offset]; !found {
			return goAMD64FrameContext("fixed local CFG private spill roles disagree")
		}
	}
	_, err := mergeFixedLocalSavedBP(&first, last)
	return err
}

func (layouts *x86FixedLocalLayouts) finish() error {
	seen, work := map[int]bool{0: true}, []int{0}
	for head := 0; head < len(work); head++ {
		for _, target := range layouts.nodes[work[head]].targets {
			if target >= 0 && !seen[target] {
				seen[target] = true
				work = append(work, target)
			}
		}
	}
	if len(seen) != len(layouts.nodes) || len(layouts.reference) != 0 && !reflect.DeepEqual(layouts.reference, layouts.nodes) {
		return goAMD64FrameContext("fixed local final layout graph has new, missing or provisional edges")
	}
	return nil
}

// These are bounded logical payload charges, not an estimate of Go heap RSS.
// The node charge includes current/reference arrays with spare capacity, source
// indexes and the observation index. A completed first phase is reserved apart.
// Map bucket/allocator overhead remains outside this logical payload bound.
const fixedLocalLayoutNodeBytes int64 = 192

func fixedLocalLayoutAccessBytes(accesses map[int]x86FixedLocalAccess) int64 {
	bytes := int64(len(accesses)) * 192
	for _, access := range accesses {
		bytes += int64(cap(access.iterationOffsets)) * 64
	}
	return bytes
}

func fixedLocalAccessShapeEqual(first, last x86FixedLocalAccess) bool {
	return first.owner == last.owner && first.shape == last.shape && first.width == last.width &&
		first.write == last.write && first.nativeInput == last.nativeInput && first.ordinal == last.ordinal
}

func collectFixedLocalLayoutAccesses(nodes int, observations map[int]map[int]map[int]x86FixedLocalAccess,
	available int64) (map[int]map[int]x86FixedLocalAccess, int64, error) {
	result := make(map[int]map[int]x86FixedLocalAccess)
	groups := make(map[int][]map[int]x86FixedLocalAccess)
	for node := 0; node < nodes; node++ {
		for pc, current := range observations[node] {
			if first, found := result[pc]; found {
				if len(groups[pc]) == 0 {
					groups[pc] = append(groups[pc], first)
				}
				groups[pc] = append(groups[pc], current)
			} else {
				result[pc] = current
			}
		}
	}
	available -= int64(len(result)) * 16 // Temporary source-PC index, not old certificates.
	for _, group := range groups {
		available -= 40 + int64(cap(group))*8
	}
	var allocated int64
	for pc, group := range groups {
		for operand, first := range result[pc] {
			count := 0
			for _, current := range group {
				access, found := current[operand]
				if len(current) != len(result[pc]) || !found || !fixedLocalAccessShapeEqual(first, access) {
					return nil, 0, goAMD64FrameContext("fixed local layout access role changed")
				}
				count += len(access.iterationOffsets)
				if len(access.iterationOffsets) == 0 {
					count++
				}
			}
			allocated += int64(count) * 64
			if allocated > available {
				return nil, 0, goAMD64FrameContext("fixed local retained state storage budget exceeded")
			}
			offsets := make([][8]int64, 0, count)
			for _, current := range group {
				access := current[operand]
				if len(access.iterationOffsets) == 0 {
					offsets = append(offsets, access.offset)
				} else {
					offsets = append(offsets, access.iterationOffsets...)
				}
			}
			first.iterationOffsets = offsets
			result[pc][operand] = first
		}
	}
	if allocated > available {
		return nil, 0, goAMD64FrameContext("fixed local retained state storage budget exceeded")
	}
	return result, allocated, nil
}
