package plan9asm

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	armLinkRegister = "R14"
	armCallerLink   = 0
	armNumericValue = -1
)

func armPlainBranchMemory(op Operand) bool {
	m := op.Mem
	return op.Kind == OpMem && m.Sym == "" && m.OffRaw == "" &&
		m.Index == "" && m.IndexExt == "" && m.Scale == 0 && m.Segment == ""
}

func armLocalPCOffset(op Operand) (int64, bool) {
	return op.Mem.Off, armPlainBranchMemory(op) && op.Mem.Base == PC
}

func armNamedLocalCall(ins Instr) bool {
	// Most instructions never enter operand or suffix decoding here.
	switch ins.Op {
	case "BL", "CALL":
	default:
		if !strings.HasPrefix(string(ins.Op), "BL.") && !strings.HasPrefix(string(ins.Op), "CALL.") {
			return false
		}
	}
	if len(ins.Args) != 1 {
		return false
	}
	op := ins.Args[0]
	return op.Kind == OpIdent || op.Kind == OpLabel || op.Kind == OpMem && op.Mem.Base == PC
}

func armLinkControlCandidates(fn Func) (localCall, callerReturn bool) {
	var branches uint16
	var copies [15]uint16
	for _, ins := range fn.Instrs {
		if armNamedLocalCall(ins) {
			return true, false
		}
		if armRegisterReturnCandidate(ins) {
			if index, ok := armLocalLinkIndex(ins.Args[0].Mem.Base); ok {
				branches |= 1 << uint(index)
			}
		}
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			continue
		}
		op, _, _ := strings.Cut(string(ins.Op), ".")
		if op != "MOVW" {
			continue
		}
		from, src := armLocalLinkIndex(ins.Args[0].Reg)
		to, dst := armLocalLinkIndex(ins.Args[1].Reg)
		if src && dst {
			copies[from] |= 1 << uint(to)
		}
	}
	if branches == 0 {
		return false, false
	}
	// This only selects the proof. Reachability, predication and overwrites
	// are checked on the CFG before any register can be used as a return.
	links := uint16(1 << 14)
	for links&branches == 0 {
		before := links
		for index, destinations := range copies {
			if links&(1<<uint(index)) != 0 {
				links |= destinations
			}
		}
		if links == before {
			return false, false
		}
	}
	return false, true
}

func armRegisterReturnCandidate(ins Instr) bool {
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base == PC {
		return false
	}
	op, _, _ := strings.Cut(string(ins.Op), ".")
	return op == "B" || op == "JMP" || op == "BX"
}

func armLocalReturnCandidate(ins Instr) bool {
	op, _, _, _ := armDecodeOp(string(ins.Op))
	return op == "RET" || armRegisterReturnCandidate(ins)
}

func armCallerLinkLeaf(fn Func) bool {
	// Go suppresses the frame for zero-local leaves. As in arm.preprocess,
	// even an unreachable call-shaped source instruction makes it nonleaf.
	if fn.FrameSize != 0 {
		return false
	}
	for _, ins := range fn.Instrs {
		op, _, _ := strings.Cut(string(ins.Op), ".")
		switch op {
		case "BL", "CALL", "BX", "DIV", "DIVU", "MOD", "MODU", "DUFFCOPY", "DUFFZERO":
			return false
		}
	}
	return true
}

type armLocalControl struct {
	names     *assemblyBlockNames
	entry     string
	successor [][]int
	transfers []armLocalTransfer
}

type armLocalTransferKind uint8

const (
	armLocalOrdinary armLocalTransferKind = iota
	armLocalCall
	armLocalReturn
	armLocalFrameReturn
)

type armLocalTransfer struct {
	kind      armLocalTransferKind
	condition string
	callee    int
	link      Reg
	returns   []int
	exchange  bool // A Go BX rewrites LR and scratch R11 before transferring.
}

// An ordinary integer has no link set. At joins it can coexist with link IDs,
// in which case the register cannot be used as a return destination.
type armLocalLinks [15][]int

func armLocalLinkIndex(reg Reg) (int, bool) {
	if len(reg) < 2 || reg[0] != 'R' {
		return 0, false
	}
	n, err := strconv.Atoi(string(reg[1:]))
	return n, err == nil && n >= 0 && n <= 14 && n != 13 && strconv.Itoa(n) == string(reg[1:])
}

func armAddLink(links []int, id int) []int {
	for _, existing := range links {
		if existing == id {
			return links
		}
	}
	return append(links, id)
}

func armMergeLinks(left, right []int) []int {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	if len(left) == 0 {
		left = []int{armNumericValue}
	}
	if len(right) == 0 {
		right = []int{armNumericValue}
	}
	for _, link := range right {
		// Incoming states share immutable links until a new ID is added.
		left = armAddLink(left[:len(left):len(left)], link)
	}
	return left
}

func (c *armCtx) prepareARMLocalControl(fn Func) error {
	localCall, callerReturn := armLinkControlCandidates(fn)
	if !localCall && (!callerReturn || c.sig.ARMEntry != nil) {
		return nil
	}
	noFrame, err := armSourceNoFrame(fn)
	if err != nil {
		return err
	}
	if c.sig.ARMEntry != nil || noFrame && fn.FrameSize != 0 && fn.FrameSize != -4 {
		return fmt.Errorf("%w: ARM local calls in %q require an ordinary source TEXT frame", ErrProbeNeedsContext, fn.Sym)
	}
	for i, reg := range c.sig.ArgRegs {
		if i < len(c.sig.Args) && reg == armLinkRegister {
			if !localCall {
				return nil // This signature binds R14 as an explicit input.
			}
			return fmt.Errorf("%w: ARM local calls in %q require LR as a return link", ErrProbeNeedsContext, fn.Sym)
		}
	}
	noFrame = noFrame || !localCall && armCallerLinkLeaf(fn)

	names := newAssemblyBlockNames(fn)
	indices := make(map[string]int, len(c.blocks))
	for i, block := range c.blocks {
		indices[block.name] = i
		names.used[block.name] = true
	}
	control := &armLocalControl{
		names: names, entry: names.fresh("local_call_entry"),
		successor: armSourceSuccessors(c.blocks),
		transfers: make([]armLocalTransfer, len(c.blocks)),
	}
	for i, block := range c.blocks {
		if len(block.instrs) == 0 {
			continue
		}
		last := block.instrs[len(block.instrs)-1]
		if !armNamedLocalCall(last) && !armLocalReturnCandidate(last) {
			continue
		}
		if err := armRequireConditionOnlySuffix(last); err != nil {
			return err
		}
		op, condition, _, _ := armDecodeOp(string(last.Op))
		if condition == "AL" {
			condition = ""
		}
		control.successor[i] = nil
		if condition != "" {
			if i+1 >= len(c.blocks) {
				return armLocalLinkError(fn, last, "conditional transfer has no fallthrough")
			}
			control.successor[i] = []int{i + 1}
		}
		transfer := &control.transfers[i]
		transfer.condition = condition
		switch {
		case armNamedLocalCall(last):
			name, _ := c.resolveBranchTarget(i, last.Args[0])
			target, ok := indices[name]
			if !ok || i+1 >= len(c.blocks) || target == 0 {
				return armLocalLinkError(fn, last, "call requires a local destination and an instruction to resume")
			}
			transfer.kind, transfer.callee = armLocalCall, target
			control.successor[i] = armAddLink(control.successor[i], target)
		case op == "RET" && len(last.Args) == 0 && !noFrame:
			transfer.kind = armLocalFrameReturn
		case op == "RET" && len(last.Args) == 0:
			transfer.kind, transfer.link = armLocalReturn, armLinkRegister
		case op == "BX" && armRegisterReturnCandidate(last):
			reg, err := armBranchExchangeTarget(last)
			if err != nil {
				return err
			}
			if _, ok := armLocalLinkIndex(reg); !ok {
				return armLocalLinkError(fn, last, "has no modeled exchange register")
			}
			transfer.kind, transfer.link, transfer.exchange = armLocalReturn, reg, true
		default:
			// B/JMP register forms have no condition except AL in Go's optab.
			registerForm := (op == "B" || op == "JMP") && condition == ""
			if len(last.Args) == 1 && (registerForm || op == "RET" && noFrame) {
				arg := last.Args[0]
				if _, ok := armLocalLinkIndex(arg.Mem.Base); ok && armPlainBranchMemory(arg) && arg.Mem.Off == 0 {
					transfer.kind, transfer.link = armLocalReturn, arg.Mem.Base
					break
				}
			}
			return armLocalLinkError(fn, last, "return requires a zero-offset link register or the source frame epilogue")
		}
	}
	if err := control.proveLinks(fn, c.blocks, c.sig, noFrame); err != nil {
		return err
	}
	c.localControl = control
	return nil
}

func armLocalLinkError(fn Func, ins Instr, reason string) error {
	return fmt.Errorf("%w: ARM local continuation in %q %s: %s", ErrProbeNeedsContext, fn.Sym, reason, ins.Raw)
}

func (plan *armLocalControl) proveLinks(fn Func, blocks []armBlock, sig FuncSig, noFrame bool) error {
	states := make([]armLocalLinks, len(blocks))
	reached := make([]bool, len(blocks))
	pending := make([]bool, len(blocks))
	queue := []int{0}
	states[0][14] = []int{armCallerLink}
	reached[0], pending[0] = true, true
	send := func(to int, incoming armLocalLinks) {
		changed := !reached[to]
		if changed {
			states[to] = incoming
			reached[to] = true
		} else {
			for reg, links := range incoming {
				before := states[to][reg]
				after := armMergeLinks(before, links)
				states[to][reg] = after
				changed = changed || len(after) != len(before)
			}
		}
		if changed && !pending[to] {
			pending[to] = true
			queue = append(queue, to)
		}
	}
	for len(queue) != 0 {
		i := queue[0]
		queue = queue[1:]
		pending[i] = false
		state := states[i]
		instructions := blocks[i].instrs
		transfer := &plan.transfers[i]
		var last Instr
		if transfer.kind != armLocalOrdinary {
			last = instructions[len(instructions)-1]
			instructions = instructions[:len(instructions)-1]
		}
		for _, ins := range instructions {
			if err := armLinkInstruction(fn, &state, ins); err != nil {
				return err
			}
		}
		if transfer.condition != "" {
			send(i+1, state)
		}
		switch transfer.kind {
		case armLocalOrdinary:
			if len(plan.successor[i]) == 0 {
				if len(instructions) == 0 || instructions[len(instructions)-1].Op != "UNDEF" {
					return fmt.Errorf("%w: ARM local continuation in %q leaves TEXT without a proven return or trap", ErrProbeNeedsContext, fn.Sym)
				}
			}
			for _, to := range plan.successor[i] {
				send(to, state)
			}
		case armLocalCall:
			state[14] = []int{i + 1}
			send(transfer.callee, state)
		case armLocalFrameReturn:
			if !armLocalResultLinksSafe(sig, state) {
				return armLocalLinkError(fn, last, "would return a link as data")
			}
		case armLocalReturn:
			reg, _ := armLocalLinkIndex(transfer.link)
			if len(state[reg]) == 0 {
				return armLocalLinkError(fn, last, "has no proven register link")
			}
			for _, link := range state[reg] {
				switch link {
				case armNumericValue:
					return armLocalLinkError(fn, last, "can branch to a numeric register value")
				case armCallerLink:
					if !noFrame || !armLocalResultLinksSafe(sig, state) {
						return armLocalLinkError(fn, last, "cannot exit through this caller link")
					}
				default:
					if transfer.exchange {
						return armLocalLinkError(fn, last, "BX rewrites LR before a local continuation")
					}
					send(link, state)
					plan.successor[i] = armAddLink(plan.successor[i], link)
				}
				transfer.returns = armAddLink(transfer.returns, link)
			}
		}
	}
	for i := range plan.transfers {
		sort.Ints(plan.transfers[i].returns)
	}
	return nil
}

func armLocalResultLinksSafe(sig FuncSig, state armLocalLinks) bool {
	// Existing frame-result lowering can fall back to R0/R1.
	return sig.Ret == Void || len(state[0]) == 0 && len(state[1]) == 0
}

func armLinkInstruction(fn Func, state *armLocalLinks, ins Instr) error {
	op, condition, _, _ := armDecodeOp(string(ins.Op))
	switch op {
	case "BL", "CALL", "BX", "SWI", "SVC", "DIV", "DIVU", "MOD", "MODU",
		"DUFFZERO", "DUFFCOPY", "WORD", "BYTE", "LONG":
		return armLocalLinkError(fn, ins, "has an unmodeled machine link effect")
	}
	if ins.armKernelCall != nil {
		return armLocalLinkError(fn, ins, "mixes native and local links")
	}
	if _, tail, branch := armKernelBranchForm(ins); branch && tail {
		if len(ins.Args) != 1 || ins.Args[0].Kind == OpSym {
			return armLocalLinkError(fn, ins, "has an unproved tail transfer")
		}
	}
	for _, arg := range ins.Args {
		if armKernelOperandUsesReg(arg, "R13") || armKernelOperandUsesReg(arg, SP) ||
			armKernelOperandUsesReg(arg, "R15") {
			return armLocalLinkError(fn, ins, "accesses physical SP or PC")
		}
	}
	if op == "MOVW" && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg &&
		armRequireConditionOnlySuffix(ins) == nil {
		if dst, ok := armLocalLinkIndex(ins.Args[1].Reg); ok && ins.Args[0].Kind == OpReg {
			var links []int
			if src, general := armLocalLinkIndex(ins.Args[0].Reg); general {
				links = state[src]
			}
			if len(links) != 0 && ins.Args[1].Reg == "R11" {
				return armLocalLinkError(fn, ins, "copies a link to Go's instruction expansion scratch R11")
			}
			if condition != "" && condition != "AL" {
				links = armMergeLinks(state[dst], links)
			}
			state[dst] = links
			return nil
		}
	}
	for reg, links := range state {
		if len(links) == 0 {
			continue
		}
		source := Reg("R" + strconv.Itoa(reg))
		for i, arg := range ins.Args {
			if !armKernelOperandUsesReg(arg, source) {
				continue
			}
			if i == 1 && len(ins.Args) == 2 && op == "MOVW" && arg.Kind == OpReg &&
				armRequireConditionOnlySuffix(ins) == nil {
				if condition == "" || condition == "AL" {
					state[reg] = nil
				} else {
					state[reg] = armMergeLinks(links, nil)
				}
				continue
			}
			return armLocalLinkError(fn, ins, "observes a code address outside a link copy or return")
		}
	}
	return nil
}

func (c *armCtx) lowerARMLocalTransfer(bi int, transfer armLocalTransfer, emitBr armEmitBr, emitCondBr armEmitCondBr) error {
	names := c.localControl.names
	if transfer.condition != "" {
		taken := names.fresh("local_link_taken")
		if err := emitCondBr(transfer.condition, taken, c.blocks[bi+1].name); err != nil {
			return err
		}
		fmt.Fprintf(c.b, "\n%s:\n", armLLVMBlockName(taken))
	}
	switch transfer.kind {
	case armLocalCall:
		if err := c.storeReg(armLinkRegister, strconv.Itoa(bi+1)); err != nil {
			return err
		}
		emitBr(c.blocks[transfer.callee].name)
	case armLocalFrameReturn:
		return c.lowerRET()
	case armLocalReturn:
		return c.lowerARMLocalReturn(transfer, emitBr)
	}
	return nil
}

func (c *armCtx) lowerARMLocalReturn(transfer armLocalTransfer, emitBr armEmitBr) error {
	switch len(transfer.returns) {
	case 0:
		// No path from this TEXT's entry reached this branch.
		c.b.WriteString("  unreachable\n")
		return nil
	case 1:
		target := transfer.returns[0]
		if target == armCallerLink {
			return c.lowerRET()
		}
		emitBr(c.blocks[target].name)
		return nil
	}

	names := c.localControl.names
	invalid := names.fresh("invalid_local_link")
	outer := ""
	if transfer.returns[0] == armCallerLink {
		outer = names.fresh("local_caller_return")
	}
	id, err := c.loadReg(transfer.link)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  switch i32 %s, label %%%s [\n", id, armLLVMBlockName(invalid))
	for _, target := range transfer.returns {
		label := c.blocks[target].name
		if target == armCallerLink {
			label = outer
		}
		fmt.Fprintf(c.b, "    i32 %d, label %%%s\n", target, armLLVMBlockName(label))
	}
	fmt.Fprintf(c.b, "  ]\n\n%s:\n  unreachable\n", armLLVMBlockName(invalid))
	if outer != "" {
		fmt.Fprintf(c.b, "\n%s:\n", armLLVMBlockName(outer))
		return c.lowerRET()
	}
	return nil
}
