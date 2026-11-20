package plan9asm

// The SCC graph is only a structural decomposition. Each cyclic component
// still needs the existing bounded numerical proof, and replay keeps every
// feasible path separate. It never joins states or invents a loop invariant.
func deriveX86CallerCountedPlan(original, fn Func, instructions []int, labels map[string]int) *x86CallerCountedPlan {
	edges, valid := x86CallerCountedEdges(fn, instructions, labels)
	if !valid {
		return nil
	}

	// Tarjan visits only source-reachable nodes, in original successor order.
	index, low := make([]int, len(edges)), make([]int, len(edges))
	onStack, reachable := make([]bool, len(edges)), make([]bool, len(edges))
	for pc := range index {
		index[pc] = -1
	}
	var stack []int
	var components [][]int
	sequence := 0
	var visit func(int)
	visit = func(pc int) {
		index[pc], low[pc], sequence = sequence, sequence, sequence+1
		reachable[pc], onStack[pc] = true, true
		stack = append(stack, pc)
		for _, next := range edges[pc] {
			if index[next] < 0 {
				visit(next)
				if low[next] < low[pc] {
					low[pc] = low[next]
				}
			} else if onStack[next] && index[next] < low[pc] {
				low[pc] = index[next]
			}
		}
		if low[pc] != index[pc] {
			return
		}
		var component []int
		for {
			node := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[node] = false
			component = append(component, node)
			if node == pc {
				break
			}
		}
		components = append(components, component)
	}
	visit(0)

	plan := &x86CallerCountedPlan{edges: edges, headers: map[int]int{}, latches: map[int]int{}}
	for _, component := range components {
		cyclic := len(component) > 1
		for _, next := range edges[component[0]] {
			cyclic = cyclic || next == component[0]
		}
		if !cyclic {
			continue
		}
		body := make(map[int]bool, len(component))
		for _, pc := range component {
			body[pc] = true
		}
		header, latch := -1, -1
		entries, exits := 0, 0
		for pc, nexts := range edges {
			if !reachable[pc] {
				continue
			}
			for _, next := range nexts {
				if !body[pc] && body[next] {
					entries++
					header = next
				}
				if body[pc] && !body[next] {
					exits++
					latch = pc
				}
			}
		}
		if entries != 1 || exits != 1 {
			return nil
		}
		loop := deriveX86CallerCountedLoop(fn, instructions, edges, reachable, body, header, latch)
		if loop == nil || !x86CallerCountedBodyDAG(*loop, edges) {
			return nil
		}
		plan.headers[header], plan.latches[latch] = len(plan.loops), len(plan.loops)
		plan.loops = append(plan.loops, *loop)
	}
	if len(plan.loops) == 0 {
		return nil
	}
	var err error
	plan.original, err = x86CallerSourceFingerprint(original)
	if err != nil {
		return nil
	}
	plan.normalized, err = x86CallerSourceFingerprint(fn)
	if err != nil {
		return nil
	}
	return plan
}

// Removing exactly the proved latch backedge must eliminate every body cycle.
// A nested/alternate cycle cannot borrow another SCC's finite iteration cap.
func x86CallerCountedBodyDAG(loop x86CallerCountedLoop, edges [][]int) bool {
	indegree := map[int]int{}
	for pc := range loop.body {
		for _, next := range edges[pc] {
			if loop.body[next] && !(pc == loop.latch && next == loop.header) {
				indegree[next]++
			}
		}
	}
	var work []int
	for pc := range loop.body {
		if indegree[pc] == 0 {
			work = append(work, pc)
		}
	}
	removed := 0
	for len(work) > 0 {
		pc := work[0]
		work = work[1:]
		removed++
		for _, next := range edges[pc] {
			if loop.body[next] && !(pc == loop.latch && next == loop.header) {
				indegree[next]--
				if indegree[next] == 0 {
					work = append(work, next)
				}
			}
		}
	}
	return removed == len(loop.body)
}
