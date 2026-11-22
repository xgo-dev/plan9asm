package plan9asm

import (
	"fmt"
	"sort"
	"strings"
)

type wasmResumeJump struct {
	pc, entry int
}

type wasmGoCallPC struct {
	returnPC        int
	propagateUnwind bool
}

// A Go label names a logical PC. BrTable selects the region containing that
// PC, so even a label in the middle of a region jumps to the region's entry.
type wasmResumePlan struct {
	starts  []int       // first logical PC in each region, including entry
	entries map[int]int // source RESUMEPOINT or CALL index to first PC
	calls   map[int]wasmGoCallPC
	jumps   map[int]wasmResumeJump
}

func wasmLocalJumpLabel(ins Instr, op string) string {
	if op != "JMP" || len(ins.Args) != 1 {
		return ""
	}
	arg := ins.Args[0]
	switch arg.Kind {
	case OpIdent:
		return arg.Ident
	case OpLabel:
		return arg.Sym
	}
	return ""
}

func wasmSigpanicCall(ins Instr) bool {
	return len(ins.Args) == 1 && ins.Args[0].Kind == OpSym &&
		ins.Args[0].Sym == "runtime·sigpanic<ABIInternal>(SB)"
}

func planWASMResume(fn Func) (*wasmResumePlan, error) {
	plan := &wasmResumePlan{
		starts:  []int{0},
		entries: make(map[int]int),
		calls:   make(map[int]wasmGoCallPC),
		jumps:   make(map[int]wasmResumeJump),
	}

	pc := 0
	if fn.FrameSize != 0 {
		// cmd/internal/obj/wasm marks the generated SP update as Spadj.
		pc++
	}
	depth := 0
	labels := make(map[string]int)
	var pendingLabels []string
	nonResumableCall := -1
	for i, ins := range fn.Instrs {
		op := normalizeInstructionOpcode(ins.Op)
		if op == "LABEL" {
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpLabel {
				return nil, fmt.Errorf("wasm label expects one name")
			}
			pendingLabels = append(pendingLabels, ins.Args[0].Sym)
			continue
		}
		switch op {
		case "IF", "BLOCK", "LOOP":
			depth++
		case "END":
			depth--
		case "RESUMEPOINT":
			if len(ins.Args) != 0 {
				return nil, fmt.Errorf("RESUMEPOINT takes no operands")
			}
			if depth != 0 {
				return nil, fmt.Errorf("RESUMEPOINT requires top-level control")
			}
			pc++
			plan.entries[i] = pc
			plan.starts = append(plan.starts, pc)
		case "CALL":
			if depth != 0 {
				return nil, fmt.Errorf("resumable CALL requires top-level control")
			}
		}
		for _, label := range pendingLabels {
			labels[label] = pc
		}
		pendingLabels = pendingLabels[:0]
		if nonResumableCall >= 0 {
			// Go saves call.Link.Pc. An explicit RESUMEPOINT increments
			// before assigning its own PC, unlike Nop or CALLNORESUME.
			call := plan.calls[nonResumableCall]
			call.returnPC = pc
			if call.propagateUnwind {
				call.returnPC-- // sigpanic's caller expects PC at the call.
			}
			plan.calls[nonResumableCall] = call
			nonResumableCall = -1
		}
		switch op {
		case "CALL":
			// The Go preprocessor inserts a resume point after CALL.
			pc++
			plan.entries[i] = pc
			plan.starts = append(plan.starts, pc)
			returnPC := pc
			if wasmSigpanicCall(ins) {
				returnPC--
			}
			plan.calls[i] = wasmGoCallPC{returnPC: returnPC, propagateUnwind: true}
		case "CALLNORESUME":
			pc++
			if wasmSigpanicCall(ins) {
				// Go allocates an extra logical PC so Caller can subtract
				// one while still reporting the original callsite.
				pc++
				plan.calls[i] = wasmGoCallPC{propagateUnwind: true}
			}
			nonResumableCall = i
		case "NOP":
			pc++
		}
	}
	if nonResumableCall >= 0 {
		return nil, fmt.Errorf("CALLNORESUME requires a following instruction")
	}
	if pc >= 1<<16 {
		return nil, fmt.Errorf("wasm logical PC exceeds 16 bits")
	}
	for i, ins := range fn.Instrs {
		label := wasmLocalJumpLabel(ins, normalizeInstructionOpcode(ins.Op))
		if label == "" {
			continue
		}
		targetPC, found := labels[label]
		if !found {
			return nil, fmt.Errorf("unknown wasm JMP label %q", label)
		}
		region := sort.SearchInts(plan.starts, targetPC+1) - 1
		plan.jumps[i] = wasmResumeJump{pc: targetPC, entry: plan.starts[region]}
	}
	return plan, nil
}

func wasmResumeLabel(pc int) string {
	if pc == 0 {
		return "wasm_entry_body"
	}
	return fmt.Sprintf("wasm_resume_%d", pc)
}

func (plan *wasmResumePlan) emitDispatch(b *strings.Builder) {
	last := len(plan.starts) - 1
	if last == 0 {
		b.WriteString("  br label %wasm_entry_body\n")
		return
	}
	fmt.Fprintf(b, "  switch i32 %%pc_b, label %%%s [", wasmResumeLabel(plan.starts[last]))
	for i, start := range plan.starts[:last] {
		label := wasmResumeLabel(start)
		for pc := start; pc < plan.starts[i+1]; pc++ {
			fmt.Fprintf(b, " i32 %d, label %%%s", pc, label)
		}
	}
	b.WriteString(" ]\n")
}
