package plan9asm

import "strings"

// CALL is a source-control edge only inside this complete source graph.
// Nonzero roots and frame-unobserving leaves need the original-frame owner.
// The original instruction/relocation coordinates stay unchanged. Each static
// callsite gets its own return context; a tail edge keeps that context.
func (view *x86DirectTailRoot) expandPrivateCalls(limit int) (*x86DirectTailRoot, error) {
	ranges := make(map[int][2]int)
	called := make(map[int]bool)
	for pc, point := range view.points {
		span, found := ranges[point.text]
		if !found {
			span[0] = pc
		}
		span[1] = pc + 1
		ranges[point.text] = span
		if view.instructions[pc].Op == OpCALL {
			called[view.points[view.edges[pc][0]].text] = true
		}
	}
	queue := make([]int, 0, len(called))
	for text := range called {
		queue = append(queue, text)
	}
	for at := 0; at < len(queue); at++ {
		span := ranges[queue[at]]
		for pc := span[0]; pc < span[1]; pc++ {
			for _, target := range view.edges[pc] {
				text := view.points[target].text
				if !called[text] {
					called[text] = true
					queue = append(queue, text)
				}
			}
		}
	}
	for text, span := range ranges {
		fn := view.graph.original.Funcs[text]
		framedRoot := view.graph.fixedLocal != nil && text == view.text &&
			view.graph.fixedLocal.frames[view.graph.symbols[fn.Sym]]
		_, header := splitOpcode(fn.Instrs[0].Raw)
		parts := strings.Split(header, ",")
		if len(parts) != 3 && !framedRoot {
			return nil, x86DirectTailContext("private CALL needs explicit zero-frame source flags")
		}
		flags := map[string]bool{}
		var err error
		if len(parts) == 3 {
			flags, err = nativeFlags(parts[1], "NOSPLIT", "NOFRAME", "DUPOK")
		}
		frame, args, frameErr := parseTEXTFrame(parts)
		if err != nil || !flags["NOSPLIT"] && !framedRoot || frameErr != nil || frame != fn.FrameSize || args != fn.ArgSize {
			return nil, x86DirectTailContext("private CALL source prologue/frame is not closed: %s", fn.Sym)
		}
		hasCall, hasTail := false, false
		for pc := span[0]; pc < span[1]; pc++ {
			ins := view.instructions[pc]
			hasCall = hasCall || ins.Op == OpCALL
			hasTail = hasTail || ins.Op == OpJMP && len(ins.Args) == 1 && ins.Args[0].Kind == OpSym
			if _, stack, _ := x86StackWidthProperties(ins, view.graph.goarch); stack {
				return nil, x86DirectTailContext("private CALL cannot borrow implicit source stack storage")
			}
			if called[text] {
				if view.externalTails[pc] {
					return nil, x86DirectTailContext("called helper cannot borrow the root's external tail ABI")
				}
				for _, operand := range ins.Args {
					if operand.Kind == OpFP {
						return nil, x86DirectTailContext("called helper cannot borrow its caller's FP frame")
					}
				}
			}
		}
		// Go saves BP on entry to an AMD64 non-leaf, even with $0 locals.
		// RET restores it; a plain cross-TEXT JMP does not. An explicit NOFRAME
		// source avoids that hidden push. Register-only CALL/RET preserves FLAGS.
		if view.graph.goarch == "amd64" && hasCall && hasTail && !flags["NOFRAME"] {
			return nil, x86DirectTailContext("non-leaf private tail needs explicit NOFRAME")
		}
	}

	type returnContext struct{ parent, entry, resume int }
	type instance struct{ text, context int }
	contexts := []returnContext{{parent: -1, entry: view.text, resume: -1}}
	starts := make(map[instance]int)
	var instances []instance
	result := &x86DirectTailRoot{graph: view.graph, text: view.text}
	add := func(key instance) (int, error) {
		if start, found := starts[key]; found {
			return start, nil
		}
		span := ranges[key.text]
		count, start := span[1]-span[0], len(result.points)
		if count <= 0 || count > limit-start {
			return 0, x86DirectTailContext("private CALL expansion instruction budget exhausted")
		}
		starts[key] = start
		instances = append(instances, key)
		result.points = append(result.points, view.points[span[0]:span[1]]...)
		result.instructions = append(result.instructions, view.instructions[span[0]:span[1]]...)
		result.ordinals = append(result.ordinals, view.ordinals[span[0]:span[1]]...)
		result.externalTails = append(result.externalTails, view.externalTails[span[0]:span[1]]...)
		result.edges = append(result.edges, make([][]int, count)...)
		return start, nil
	}
	if _, err := add(instance{view.text, 0}); err != nil {
		return nil, err
	}
	for at := 0; at < len(instances); at++ {
		key := instances[at]
		span, start := ranges[key.text], starts[key]
		for source := span[0]; source < span[1]; source++ {
			pc := start + source - span[0]
			ins := view.instructions[source]
			if ins.Op == OpRET && key.context != 0 {
				result.edges[pc] = []int{contexts[key.context].resume}
				continue
			}
			context := key.context
			if ins.Op == OpCALL {
				callee := view.points[view.edges[source][0]].text
				if source+1 >= span[1] || callee == key.text {
					return nil, x86DirectTailContext("private CALL has no continuation or is recursive")
				}
				for parent := context; parent >= 0; parent = contexts[parent].parent {
					if contexts[parent].entry == callee {
						return nil, x86DirectTailContext("recursive private CALL source")
					}
				}
				context = len(contexts)
				contexts = append(contexts, returnContext{key.context, callee, pc + 1})
			}
			for _, target := range view.edges[source] {
				text := view.points[target].text
				targetStart, err := add(instance{text, context})
				if err != nil {
					return nil, err
				}
				result.edges[pc] = append(result.edges[pc], targetStart+target-ranges[text][0])
			}
		}
	}
	return result, nil
}

func (view *x86DirectTailRoot) privateCallTransition(pc int) bool {
	return view != nil && pc >= 0 && pc < len(view.instructions) && pc < len(view.edges) &&
		len(view.edges[pc]) == 1 && (view.instructions[pc].Op == OpCALL || view.instructions[pc].Op == OpRET)
}
