package plan9asm

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Local code addresses stay opaque LLVM blockaddresses. A reaching-definition proof,
// not an address comparison, distinguishes local control flow from native calls.
// Memory provenance is retained only for exactly identified owned frame cells.
// Values are immutable after publication. Clones share exact set roots;
// transforms replace roots instead of mutating a reaching definition.
type arm64ControlState struct {
	targetTriple string // one exact translator target, never inferred from state
	regs         map[Reg]arm64ControlValue
	memory       map[string]arm64ControlValue
	escaped      arm64ControlValue
	unexposedSP  bool                  // original/normalized source and fresh-entry proof, not FP
	privateStore *arm64PrivateDataSpan // only the instruction currently being transferred
}

type arm64LocalControlPlan struct {
	before      map[[2]int]arm64ControlValue
	stackBefore map[[2]int]arm64ControlValue
	linkBefore  map[[2]int]arm64ControlValue
	reachable   []bool
	outer       string
	autoFrame   bool
}

type arm64GoFrame struct {
	present      bool
	restoresLink bool
}

// Go obj7 marks only source ABL instructions nonleaf, before expanding raw
// AWORD instructions. A decoded WORD BL must not invent a Go LR/FP prologue.
func arm64SourceGoFrame(fn Func) arm64GoFrame {
	noFrame, leaf := fn.FrameSize == -8, true
	for _, ins := range fn.Instrs {
		op := arm64ControlOp(ins)
		if (op == "BL" || op == "CALL") && !ins.arm64RawLocalCall {
			leaf = false
		}
		if op != OpTEXT {
			continue
		}
		_, rest := splitOpcode(ins.Raw)
		parts := strings.Split(rest, ",")
		if len(parts) != 3 {
			continue
		}
		if flags, ok := parseImmExpr(strings.TrimSpace(parts[1])); ok {
			noFrame = noFrame || flags&512 != 0 // objabi.NOFRAME
		} else {
			for _, flag := range strings.Split(parts[1], "|") {
				noFrame = noFrame || strings.TrimSpace(flag) == "NOFRAME"
			}
		}
	}
	present := !noFrame && (!leaf || fn.FrameSize > 0)
	return arm64GoFrame{present: present, restoresLink: present && !leaf}
}

func arm64ControlExternal() arm64ControlValue { return arm64ControlFromMap(map[string]bool{"": true}) }

func arm64ControlRead(values map[Reg]arm64ControlValue, reg Reg) arm64ControlValue {
	reg = arm64ControlBase(reg)
	value := values[reg]
	// F, V lanes and SVE Z views share physical storage. Provenance cannot
	// disappear merely because the next typed read uses another view. Retain
	// all alias witnesses conservatively; this is not a partial-write proof.
	root := arm64MachineRegister(reg)
	if strings.HasPrefix(root, "V") {
		for alias, witness := range values {
			if arm64MachineRegister(alias) == root {
				value = arm64ControlUnion(value, witness)
			}
		}
	}
	if value == nil {
		return arm64ControlExternal()
	}
	return value
}

func (state *arm64ControlState) clone() *arm64ControlState {
	next := &arm64ControlState{
		targetTriple: state.targetTriple,
		regs:         make(map[Reg]arm64ControlValue),
		memory:       make(map[string]arm64ControlValue),
		escaped:      state.escaped,
		unexposedSP:  state.unexposedSP,
	}
	for reg, value := range state.regs {
		next.regs[reg] = value
	}
	for key, value := range state.memory {
		next.memory[key] = value
	}
	return next
}

func (state *arm64ControlState) merge(other *arm64ControlState) bool {
	changed := false
	var operations arm64ControlMergeOperations
	if state.unexposedSP && !other.unexposedSP {
		state.unexposedSP, changed = false, true
	}
	escaped := operations.union(state.escaped, state.escaped, other.escaped)
	if escaped.changed {
		state.escaped, changed = escaped.value, true
	}
	for reg, value := range other.regs {
		merged := operations.union(state.regs[reg], arm64ControlRead(state.regs, reg), value)
		if merged.changed {
			state.regs[reg], changed = merged.value, true
		}
	}
	for reg, value := range state.regs {
		if other.regs[reg] == nil {
			merged := operations.union(value, value, arm64ControlExternal())
			if merged.changed {
				state.regs[reg], changed = merged.value, true
			}
		}
	}
	for key, value := range other.memory {
		old := state.memory[key]
		if old == nil {
			old = arm64ControlExternal()
		}
		merged := operations.union(state.memory[key], old, value)
		if merged.changed {
			state.memory[key], changed = merged.value, true
		}
	}
	for key, value := range state.memory {
		if other.memory[key] == nil {
			merged := operations.union(value, value, arm64ControlExternal())
			if merged.changed {
				state.memory[key], changed = merged.value, true
			}
		}
	}
	return changed
}

func arm64ControlBase(reg Reg) Reg {
	if reg == Reg("RSP") {
		return SP
	}
	return reg
}

func arm64ControlOffset(value arm64ControlValue, off int64) arm64ControlValue {
	if off != 0 {
		for _, token := range arm64ControlKeys(value) {
			if strings.HasPrefix(token, "label:") || token == "code-derived:" {
				// A native-PC transform is not a pure escaped code pointer.
				// Retain this fact even when a CFG join already has unknown data.
				return arm64ControlFromMap(map[string]bool{"": true, "code-derived:": true})
			}
		}
	}
	if arm64ControlCount(value) != 1 {
		return arm64ControlExternal()
	}
	for _, token := range arm64ControlKeys(value) {
		if strings.HasPrefix(token, "fpa:") {
			if off == 0 {
				return value
			}
			// FP-address allocas are per scalar slot, unlike the contiguous
			// SP backing frame. Adding bytes cannot prove the adjacent slot.
			return arm64ControlExternal()
		}
		if !strings.HasPrefix(token, "sp:") && !strings.HasPrefix(token, "fp:") {
			return arm64ControlExternal()
		}
		base, err := strconv.ParseInt(token[3:], 10, 64)
		if err != nil || (off > 0 && base > int64(1<<63-1)-off) || (off < 0 && base < int64(-1<<63)-off) {
			return arm64ControlExternal()
		}
		return arm64ControlFromMap(map[string]bool{token[:3] + strconv.FormatInt(base+off, 10): true})
	}
	return arm64ControlExternal()
}

func (state *arm64ControlState) memoryKey(op Operand, post bool) string {
	if op.Kind == OpFP || op.Kind == OpFPAddr {
		return "fp:" + strconv.FormatInt(op.FPOffset, 10)
	}
	if op.Kind != OpMem || op.Mem.Index != "" || op.Mem.OffRaw != "" {
		return ""
	}
	off := op.Mem.Off
	if post {
		off = 0
	}
	value := arm64ControlOffset(arm64ControlRead(state.regs, arm64ControlBase(op.Mem.Base)), off)
	if arm64ControlCount(value) == 1 {
		for _, token := range arm64ControlKeys(value) {
			if strings.HasPrefix(token, "fpa:") {
				return "fp:" + token[4:]
			}
			return token
		}
	}
	return ""
}

func (state *arm64ControlState) source(op Operand, post bool) arm64ControlValue {
	if op.Kind == OpReg {
		return arm64ControlRead(state.regs, arm64ControlBase(op.Reg))
	}
	if op.Kind == OpFPAddr {
		return arm64ControlFromMap(map[string]bool{"fpa:" + strconv.FormatInt(op.FPOffset, 10): true})
	}
	if key := state.memoryKey(op, post); key != "" && state.memory[key] != nil {
		if state.unexposedSP && strings.HasPrefix(key, "sp:") && arm64ControlEscapedOnlyCode(state.escaped) {
			return state.memory[key]
		}
		return arm64ControlUnion(state.memory[key], arm64ControlLabels(state.escaped))
	}
	if op.Kind == OpMem || op.Kind == OpFP || op.Kind == OpSym {
		return arm64ControlUnion(arm64ControlExternal(), state.escaped)
	}
	return arm64ControlExternal()
}

func (state *arm64ControlState) write(op Operand, value arm64ControlValue, post bool) {
	if op.Kind == OpReg && op.Reg != ZR {
		state.regs[arm64ControlBase(op.Reg)] = value
	} else if key := state.memoryKey(op, post); key != "" {
		// Any nonidentical cell may overlap (including through unknown aliases).
		// Preserve a tainted local address rather than silently reclassify a
		// partially overwritten pointer as an external native address.
		state.invalidateOverlappingControlCells(key, 8)
		state.memory[key] = value
	} else if op.Kind == OpMem || op.Kind == OpFP || op.Kind == OpSym {
		state.invalidateUnknownStore(op, value)
	} else if op.Kind == OpRegList {
		for _, reg := range op.RegList {
			state.write(Operand{Kind: OpReg, Reg: reg}, value, false)
		}
	}
}

func (state *arm64ControlState) invalidateUnknownStore(destination Operand, value arm64ControlValue) {
	state.escaped = arm64ControlUnion(state.escaped, arm64ControlAddressTaint(value))
	// The whole-function proof excludes escaping this allocation's address.
	// Locally read affine aliases remain explicit SP tokens below; an incoming
	// pointer or SB global therefore cannot name its SP
	// cells. Explicit SP-relative indexing remains potentially overlapping even
	// when the exact displacement is unknown; it must not borrow this exception.
	preserveSP := state.unexposedSP && arm64ControlEscapedOnlyCode(state.escaped)
	if destination.Kind == OpMem {
		for _, reg := range []Reg{destination.Mem.Base, destination.Mem.Index} {
			base := arm64ControlBase(reg)
			if state.privateStore == nil {
				preserveSP = preserveSP && base != SP
			}
			for _, token := range arm64ControlKeys(arm64ControlRead(state.regs, base)) {
				if token == "code-derived:" || state.privateStore == nil && strings.HasPrefix(token, "sp:") {
					preserveSP = false
				}
			}
		}
	}
	for key, old := range state.memory {
		if state.privateStore != nil && strings.HasPrefix(key, "sp:") {
			start, err := strconv.ParseInt(key[3:], 10, 64)
			if err == nil && start >= 0 && start <= int64(1<<63-1)-8 {
				if start+8 <= state.privateStore.low || start >= state.privateStore.end {
					if preserveSP {
						continue
					}
				} else {
					state.memory[key] = arm64ControlUnion(arm64ControlUnion(old, value), arm64ControlExternal())
					continue
				}
			}
		}
		if preserveSP && strings.HasPrefix(key, "sp:") {
			continue
		}
		state.memory[key] = arm64ControlUnion(old, arm64ControlExternal())
	}
}

func arm64ControlEscapedOnlyCode(value arm64ControlValue) bool {
	for _, token := range arm64ControlKeys(value) {
		if !strings.HasPrefix(token, "label:") {
			return false
		}
	}
	return true
}

func (state *arm64ControlState) invalidateOverlappingControlCells(key string, width int64) {
	if len(key) < 4 {
		return
	}
	off, err := strconv.ParseInt(key[3:], 10, 64)
	if err != nil {
		return
	}
	for other, value := range state.memory {
		if len(other) < 4 || other[:3] != key[:3] {
			continue
		}
		start, err := strconv.ParseInt(other[3:], 10, 64)
		if err != nil {
			continue
		}
		// Unsigned distances avoid signed overflow at either int64 boundary.
		overlaps := (start <= off && uint64(off)-uint64(start) < 8) ||
			(start > off && uint64(start)-uint64(off) < uint64(width))
		if overlaps {
			state.memory[other] = arm64ControlUnion(value, arm64ControlExternal())
		}
	}
}

func arm64ControlElement(op Operand, offset int64) Operand {
	if op.Kind == OpFP {
		op.FPOffset += offset
	} else if op.Kind == OpMem {
		op.Mem.Off += offset
	}
	return op
}

func arm64ControlOp(ins Instr) Op {
	op := strings.ToUpper(string(ins.Op))
	if dot := strings.IndexByte(op, '.'); dot >= 0 {
		op = op[:dot]
	}
	return Op(op)
}

func arm64ControlDecode(ins Instr) Instr {
	if ins.Op == OpWORD {
		if len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
			if form, ok := decodeARM64RawDCZVA(uint32(ins.Args[0].Imm)); ok {
				decoded := arm64DCZVAInstruction(form)
				decoded.Raw = ins.Raw
				return decoded
			}
		}
		if decoded, err := decodeARM64RawWordInstruction(ins); err == nil {
			return arm64HardwareReturnAsBranch(decoded)
		}
	}
	return ins
}

// A hardware RET word has no Go-generated frame epilogue. Its branch effect
// must not be confused with the source-level RET pseudo instruction.
func arm64HardwareReturnAsBranch(ins Instr) Instr {
	if ins.Op != OpRET {
		return ins
	}
	target, ok := arm64RegisterReturnTarget(ins, false)
	if !ok {
		return ins
	}
	if target.Kind == OpReg {
		target = Operand{Kind: OpMem, Mem: MemRef{Base: target.Reg}}
	}
	ins.Op, ins.Args = "B", []Operand{target}
	return ins
}

func (c *arm64Ctx) prepareLocalControl() error {
	if c.nanosleepRequired && c.nanosleepInput == nil {
		return fmt.Errorf("%w: Linux nanosleep needs a complete initialized private input", ErrProbeNeedsContext)
	}
	plan := &arm64LocalControlPlan{
		before:      make(map[[2]int]arm64ControlValue),
		stackBefore: make(map[[2]int]arm64ControlValue),
		linkBefore:  make(map[[2]int]arm64ControlValue),
	}
	plan.autoFrame = c.sourceGoFrame.present
	indices := make(map[string]int, len(c.blocks))
	for index, block := range c.blocks {
		indices[block.name] = index
	}
	// The caller link has a distinguished abstract return destination. Its
	// actual value comes from llvm.returnaddress, never a fake blockaddress.
	plan.outer = "__arm64_caller_return"
	for indices[plan.outer] != 0 || c.blocks[0].name == plan.outer {
		plan.outer += "_"
	}
	if precise := c.rawZeroContextControlPlan(plan.outer); precise != nil {
		c.localControl = precise
		return nil
	}
	entry := &arm64ControlState{
		targetTriple: c.targetTriple,
		regs: map[Reg]arm64ControlValue{
			SP:         arm64ControlFromMap(map[string]bool{"sp:0": true}),
			Reg("R30"): arm64ControlFromMap(map[string]bool{"label:" + plan.outer: true}),
		},
		memory:      make(map[string]arm64ControlValue),
		unexposedSP: c.unexposedCallFrame,
	}
	if c.sourceGoFrame.present {
		entry.memory["sp:0"] = entry.regs[Reg("R30")]
	}
	if c.sourceFrameR20 {
		entry.regs["R20"] = arm64ControlFromMap(map[string]bool{"sp:0": true})
	}
	for _, reg := range c.sig.ArgRegs {
		entry.regs[reg] = arm64ControlExternal()
	}
	before := make([]*arm64ControlState, len(c.blocks))
	before[0] = entry
	queue, queued := []int{0}, make([]bool, len(c.blocks))
	queued[0] = true
	propagate := func(index int, state *arm64ControlState) {
		if index < 0 || index >= len(before) {
			return
		}
		changed := false
		if before[index] == nil {
			before[index], changed = state.clone(), true
		} else {
			changed = before[index].merge(state)
		}
		if changed && !queued[index] {
			queue, queued[index] = append(queue, index), true
		}
	}
	for next := 0; next < len(queue); next++ {
		bi := queue[next]
		queued[bi] = false
		state := before[bi].clone()
		terminated := false
		for ii, original := range c.blocks[bi].instrs {
			ins := arm64ControlDecode(original)
			op := arm64ControlOp(ins)
			post := strings.HasSuffix(string(ins.Op), ".P")
			if op == "SVC" {
				if _, err := parseARM64SyscallForm(c.targetTriple, ins); err != nil {
					return err
				}
				if err := c.requireSyscallCallerFrameDisjointAt(state, ins, [2]int{bi, ii}); err != nil {
					return err
				}
			}
			if op == "B" || op == "JMP" || op == OpRET {
				plan.stackBefore[[2]int{bi, ii}] = arm64ControlRead(state.regs, SP)
				link := arm64ControlRead(state.regs, Reg("R30"))
				if op == OpRET && c.sourceGoFrame.restoresLink {
					link = state.source(Operand{Kind: OpMem, Mem: MemRef{Base: SP}}, false)
				}
				plan.linkBefore[[2]int{bi, ii}] = link
			}
			if op == "BL" || op == "BLR" || op == "CALL" {
				if len(ins.Args) != 1 || bi+1 >= len(c.blocks) {
					continue // The ordinary grammar diagnoses malformed calls.
				}
				if ins.Args[0].Kind == OpReg || (ins.Args[0].Kind == OpMem && ins.Args[0].Mem.Base != PC) {
					value := state.branchValue(ins.Args[0])
					plan.before[[2]int{bi, ii}] = value
					state.regs[Reg("R30")] = arm64ControlFromMap(map[string]bool{"label:" + c.blocks[bi+1].name: true})
					for _, token := range arm64ControlKeys(value) {
						if strings.HasPrefix(token, "label:") {
							if target, ok := indices[token[6:]]; ok {
								propagate(target, state)
							}
						} else {
							nativeState := state.clone()
							c.invalidateControlCallResults(nativeState, Operand{})
							propagate(bi+1, nativeState)
						}
					}
					terminated = true
					break
				}
				state.regs[Reg("R30")] = arm64ControlFromMap(map[string]bool{"label:" + c.blocks[bi+1].name: true})
				if arm64IsLocalBranchLink(ins) {
					if name, ok := arm64BranchTarget(ins.Args[0]); ok {
						if target, ok := indices[name]; ok {
							propagate(target, state)
						}
					}
				} else {
					c.invalidateControlCallResults(state, ins.Args[0])
					propagate(bi+1, state)
				}
				terminated = true
				break
			}
			if op == "B" || op == "JMP" {
				if len(ins.Args) == 1 {
					if ins.Args[0].Kind == OpReg || ins.Args[0].Kind == OpMem {
						value := state.branchValue(ins.Args[0])
						plan.before[[2]int{bi, ii}] = value
						for _, token := range arm64ControlKeys(value) {
							if strings.HasPrefix(token, "label:") {
								if target, ok := indices[token[6:]]; ok {
									propagate(target, state)
								}
							}
						}
					} else if name, ok := arm64BranchTarget(ins.Args[0]); ok {
						if target, ok := indices[name]; ok {
							propagate(target, state)
						}
					}
				}
				terminated = true
				break
			}
			if op == OpRET {
				if target, register := arm64RegisterReturnTarget(ins, plan.autoFrame); register {
					value := state.branchValue(target)
					plan.before[[2]int{bi, ii}] = value
					for _, token := range arm64ControlKeys(value) {
						if strings.HasPrefix(token, "label:") {
							if target, ok := indices[token[6:]]; ok {
								propagate(target, state)
							}
						}
					}
				}
				terminated = true
				break
			}
			if arm64IsConditionalBranch(op) {
				if len(ins.Args) != 0 {
					if name, ok := arm64BranchTarget(ins.Args[len(ins.Args)-1]); ok {
						if target, ok := indices[name]; ok {
							propagate(target, state)
						}
					}
				}
				propagate(bi+1, state)
				terminated = true
				break
			}
			if c.unexposedCallFrame {
				if span, bounded := c.privateDataStores[[2]int{bi, ii}]; bounded {
					state.privateStore = &span
				}
			}
			if !state.transferStructureMemory(original) {
				state.transfer(ins, op, post, c.rawDataGlobals)
			}
			state.privateStore = nil
		}
		if !terminated {
			propagate(bi+1, state)
		}
	}
	plan.reachable = make([]bool, len(before))
	for index, state := range before {
		plan.reachable[index] = state != nil
	}
	c.localControl = plan
	return nil
}

// Eliding a scheduler hook does not make the intervening syscall memory-neutral.
// The emitted syscall bridge transports GP arguments, not the virtual SP root.
// Preserve an automatic frame's saved caller LR only under the existing complete
// fresh/non-escaping source proof and with no reaching frame/code-derived input.
// R8 and R16 cover both number-register alternatives in lowerSyscall. This is a
// disjointness guard, not a contract for arbitrary native exception effects or
// an assertion that the syscall's result/NZCV mapping is complete.
func (c *arm64Ctx) requireSyscallCallerFrameDisjoint(state *arm64ControlState, ins Instr) error {
	return c.requireSyscallCallerFrameDisjointAt(state, ins, [2]int{c.currentBlock, c.currentInstruction})
}

func (c *arm64Ctx) requireSyscallCallerFrameDisjointAt(state *arm64ControlState, ins Instr, point [2]int) error {
	if !c.sourceGoFrame.present {
		return nil
	}
	if input, present := c.nanosleepInputAt(point); present {
		address := arm64ControlRead(state.regs, "R0")
		expected := arm64ControlFromMap(map[string]bool{fmt.Sprintf("sp:%d", input.span.low): true})
		if c.unexposedCallFrame && state.unexposedSP && arm64ControlEscapedOnlyCode(state.escaped) &&
			arm64ControlEqual(address, expected) {
			return nil // exact read-only span; never an unknown-store exemption
		}
	}
	exposed := state.escaped
	for _, reg := range []Reg{"R0", "R1", "R2", "R3", "R4", "R5", "R8", "R16"} {
		exposed = arm64ControlUnion(exposed, arm64ControlAddressTaint(arm64ControlRead(state.regs, reg)))
	}
	if !c.unexposedCallFrame || !state.unexposedSP || !arm64ControlEscapedOnlyCode(exposed) {
		return fmt.Errorf("%w: ARM64 syscall has no disjoint saved caller-frame memory proof: %q", ErrProbeNeedsContext, ins.Raw)
	}
	return nil
}

// A dead source terminator has neither an unknown native target nor a caller
// return. Retain its grammar validation, then terminate its LLVM block without
// fabricating execution. Other instructions in the block are still lowered.
func (c *arm64Ctx) lowerProvenUnreachableControl(bi int) bool {
	if c.localControl == nil || bi < 0 || bi >= len(c.localControl.reachable) || c.localControl.reachable[bi] {
		return false
	}
	c.b.WriteString("  unreachable\n")
	return true
}

// The implicit Go frame is separate from explicit source-level SP arithmetic.
// Go's RET epilogue pops a constant implicit frame; it does not repair a manual
// SP delta. LLVM also restores its native frame on return, so synthesizing an
// LLVM return is valid only when every reaching path restored the virtual SP.
func (c *arm64Ctx) requireCallerSPRestored(bi int, ins Instr) error {
	if c.localControl == nil {
		return fmt.Errorf("%w: ARM64 caller return has no SP reaching-definition proof: %q", ErrProbeNeedsContext, ins.Raw)
	}
	value := c.localControl.stackBefore[[2]int{bi, c.currentInstruction}]
	if arm64ControlCount(value) != 1 || !arm64ControlHas(value, "sp:0") {
		return fmt.Errorf("%w: ARM64 caller return requires restored entry SP on every reaching path: %q", ErrProbeNeedsContext, ins.Raw)
	}
	return nil
}

func (c *arm64Ctx) requireCallerLinkRestored(bi int, ins Instr) error {
	if c.localControl == nil {
		return fmt.Errorf("%w: ARM64 caller return has no LR reaching-definition proof: %q", ErrProbeNeedsContext, ins.Raw)
	}
	value := c.localControl.linkBefore[[2]int{bi, c.currentInstruction}]
	if arm64ControlCount(value) != 1 || !arm64ControlHas(value, "label:"+c.localControl.outer) {
		return fmt.Errorf("%w: ARM64 caller return requires the caller LR on every reaching path: %q", ErrProbeNeedsContext, ins.Raw)
	}
	return nil
}

func (state *arm64ControlState) branchValue(op Operand) arm64ControlValue {
	reg := op.Reg
	if op.Kind == OpMem {
		reg = op.Mem.Base
		// Branch register encoding 31 reads XZR, never the memory-address SP.
		if reg == SP || reg == Reg("RSP") {
			return arm64ControlExternal()
		}
	}
	return arm64ControlRead(state.regs, reg)
}

func arm64RegisterReturnTarget(ins Instr, hasGoFrame bool) (Operand, bool) {
	if len(ins.Args) == 0 {
		return Operand{Kind: OpReg, Reg: Reg("R30")}, !hasGoFrame
	}
	if len(ins.Args) == 1 && ins.Args[0].Kind == OpImm {
		return Operand{Kind: OpReg, Reg: Reg("R30")}, !hasGoFrame
	}
	if len(ins.Args) != 1 || (ins.Args[0].Kind != OpReg && ins.Args[0].Kind != OpMem) {
		return Operand{}, false
	}
	target := ins.Args[0]
	reg := target.Reg
	if target.Kind == OpMem {
		reg = target.Mem.Base
		target.Mem.Off, target.Mem.OffRaw, target.Mem.Index = 0, "", ""
	}
	if reg == SP || reg == Reg("RSP") {
		target = Operand{Kind: OpReg, Reg: ZR}
	}
	return target, !hasGoFrame || reg != Reg("R30")
}

func arm64IsConditionalBranch(op Op) bool {
	switch op {
	case "BEQ", "BNE", "BLO", "BHI", "BLT", "BGE", "BLE", "BGT", "BHS", "BLS", "BMI", "BPL", "BVS", "BVC", "BCC", "BCS", "CBZ", "CBNZ", "CBZW", "CBNZW", "TBZ", "TBNZ":
		return true
	}
	return false
}

func (state *arm64ControlState) transfer(ins Instr, op Op, post bool, data map[string]string) {
	if immediate, handled, err := parseARM64GPImmediateForm(op, ins); handled && err == nil && immediate.scratch {
		state.regs["R27"] = arm64ControlExternal()
	}
	if state.transferStructureMemory(ins) {
		return
	}
	if op == "SVC" {
		// Retain input PC taint for new results. Only the target's real
		// outputs lose their old continuation; Linux does not write R1.
		result := arm64ControlExternal()
		for _, reg := range []Reg{"R0", "R1", "R2", "R3", "R4", "R5", "R8", "R16"} {
			result = arm64ControlUnion(result, arm64ControlLabels(arm64ControlRead(state.regs, reg)))
		}
		form, err := parseARM64SyscallForm(state.targetTriple, ins)
		writes := uint32(3) // Unknown contexts cannot invent preservation.
		if err == nil {
			writes = form.gpWrites
		}
		for register := 0; register < 31; register++ {
			if writes&(1<<uint(register)) != 0 {
				state.regs[Reg(fmt.Sprintf("R%d", register))] = result
			}
		}
		return
	}
	if len(ins.Args) == 0 {
		return
	}
	if form, handled, err := parseARM64CacheForm(op, ins); handled && err == nil && form.operation == "ZVA" {
		// Neither address nor GP/NZCV state is written. The granule size and
		// downward alignment are architectural runtime values, so no owned
		// continuation cell can remain a known saved LR/FP pointer contents.
		for key, value := range state.memory {
			state.memory[key] = arm64ControlUnion(value, arm64ControlExternal())
		}
		return
	}
	if op == OpWORD {
		writes, known := uint32(0), false
		stores := true
		if len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
			word := uint32(ins.Args[0].Imm)
			if effects, ok := arm64RawContinuationEffectsForWord(word); ok {
				writes, stores, known = effects.gpWrites, effects.stores, true
			} else if effects, ok := arm64RawSVEEffects(word); ok {
				writes, stores, known = effects.gpWrites, effects.stores, true
			} else {
				writes, known = arm64RawPoolGPWrites(word)
			}
		}
		for reg, value := range state.regs {
			index, gp := arm64StackIndex(reg)
			if gp && (!known || writes&(1<<uint(index)) != 0) {
				state.regs[reg] = arm64ControlUnion(value, arm64ControlExternal())
			}
		}
		if stores {
			for key, value := range state.memory {
				state.memory[key] = arm64ControlUnion(value, arm64ControlExternal())
			}
		}
		return
	}
	if form, handled, err := parseARM64AtomicPairForm(op, ins); handled && err == nil {
		state.transferAtomicPair(form)
		return
	}
	if state.transferScalarAtomicStore(ins, op) {
		return
	}
	if state.transferTypedMemory(ins) {
		return
	}
	if inputs, destination, valid := arm64ScalarMultiplyInputs(op, ins); valid {
		value := arm64ControlExternal()
		for _, input := range inputs {
			value = arm64ControlUnion(value, arm64ControlLabels(state.source(input, false)))
		}
		if arm64ControlCount(arm64ControlLabels(value)) != 0 {
			value = arm64ControlWithToken(value, "code-derived:") // Multiplication is not a pure PC copy.
		}
		state.write(destination, value, false)
		return
	}
	if op == "ADR" && len(ins.Args) == 2 {
		if target, ok := arm64BranchTarget(ins.Args[0]); ok && data[target] == "" {
			state.write(ins.Args[1], arm64ControlFromMap(map[string]bool{"label:" + target: true}), false)
			return
		}
	}
	if form, handled, err := parseARM64RegisterAddressForm(op, ins); handled && err == nil {
		if form.usesScratch {
			state.regs[Reg("R27")] = arm64ControlExternal()
		}
		value := state.source(Operand{Kind: OpReg, Reg: form.base}, false)
		if form.offset != 0 {
			value = arm64ControlUnion(arm64ControlOffset(value, form.offset), arm64ControlLabels(value))
		}
		state.write(ins.Args[1], value, false)
		return
	}
	if state.transferGPRegisterMove(ins) {
		return
	}
	if op == "MOVD" && len(ins.Args) == 2 && !(ins.Args[0].Kind == OpImm && ins.Args[0].ImmIsFloat) {
		value := state.source(ins.Args[0], post)
		state.write(ins.Args[1], value, post)
	} else if (op == "LDP" || op == "STP") && len(ins.Args) == 2 {
		memory, pair := ins.Args[0], ins.Args[1]
		if op == "STP" {
			pair, memory = ins.Args[0], ins.Args[1]
		}
		if pair.Kind != OpRegList || len(pair.RegList) != 2 {
			return // The typed operand grammar rejects the malformed pair.
		}
		if post && memory.Kind == OpMem {
			memory.Mem.Off = 0
		}
		var values [2]arm64ControlValue
		for index, reg := range pair.RegList {
			source := Operand{Kind: OpReg, Reg: reg}
			if op == "LDP" {
				source = arm64ControlElement(memory, int64(index)*8)
			}
			values[index] = state.source(source, false)
		}
		for index, reg := range pair.RegList {
			destination := arm64ControlElement(memory, int64(index)*8)
			if op == "LDP" {
				destination = Operand{Kind: OpReg, Reg: reg}
			}
			state.write(destination, values[index], false)
		}
	} else if (op == "ADD" || op == "SUB") && len(ins.Args) >= 2 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
		src, dst := ins.Args[1], ins.Args[len(ins.Args)-1]
		off := ins.Args[0].Imm
		if op == "SUB" {
			if off == int64(-1<<63) {
				state.write(dst, arm64ControlExternal(), false)
				return
			}
			off = -off
		}
		value := state.source(src, false)
		if off != 0 {
			value = arm64ControlUnion(arm64ControlOffset(value, off), arm64ControlLabels(value))
		}
		state.write(dst, value, false)
	} else if state.transferGPData(ins) {
		return
	} else {
		switch op {
		case "CMP", "CMPW", "CMN", "CMNW", "TST", "TSTW", "CCMP", "CCMPW", "CCMN", "CCMNW", "PCDATA", "FUNCDATA":
			return
		}
		// Unmodeled transforms of code addresses are tainted, not native
		// addresses. This deliberately fails closed even if a bit trick could
		// happen to reconstitute the original blockaddress at runtime.
		value := arm64ControlExternal()
		for _, arg := range ins.Args {
			value = arm64ControlUnion(value, arm64ControlLabels(state.source(arg, post)))
			for _, reg := range arg.RegList {
				value = arm64ControlUnion(value, arm64ControlLabels(arm64ControlRead(state.regs, reg)))
			}
		}
		destination := ins.Args[len(ins.Args)-1]
		if destination.Kind == OpReg && arm64ControlCount(value) > 1 {
			for _, token := range arm64ControlKeys(value) {
				if strings.HasPrefix(token, "label:") {
					value = arm64ControlWithToken(value, "code-derived:")
					break
				}
			}
		}
		if key := state.memoryKey(destination, post); key != "" {
			state.invalidateOverlappingControlCells(key, 64)
			value = arm64ControlUnion(value, arm64ControlLabels(state.memory[key]))
		}
		state.write(destination, value, post)
	}
	if post || strings.HasSuffix(string(ins.Op), ".W") {
		for _, operand := range ins.Args {
			if operand.Kind == OpMem {
				base := arm64ControlBase(operand.Mem.Base)
				state.regs[base] = arm64ControlOffset(arm64ControlRead(state.regs, base), operand.Mem.Off)
			}
		}
	}
}

func (c *arm64Ctx) invalidateControlCallResults(state *arm64ControlState, operand Operand) {
	name := c.resolve(strings.TrimSuffix(operand.Sym, "(SB)"))
	if operand.Kind == OpSym && strings.HasSuffix(operand.Sym, "(SB)") && arm64ElidesSchedulerHook(name) {
		return
	}
	sig, known := c.sigs[name]
	possibleCode := arm64ControlLabels(state.escaped)
	returnValue := arm64ControlUnion(arm64ControlExternal(), possibleCode)
	mayWriteFrame := !known || arm64ControlCount(state.escaped) != 0
	internal := strings.HasSuffix(strings.TrimSuffix(operand.Sym, "(SB)"), "<ABIInternal>")
	inputs, transport := arm64ControlCallInputs(state, sig, internal)
	callTransportKnown := known && operand.Kind == OpSym && transport
	mayWriteFrame = mayWriteFrame || !callTransportKnown
	for _, value := range inputs {
		state.escaped = arm64ControlUnion(state.escaped, arm64ControlAddressTaint(value))
		returnValue = arm64ControlUnion(returnValue, arm64ControlLabels(value))
		for _, token := range arm64ControlKeys(value) {
			if strings.HasPrefix(token, "sp:") || strings.HasPrefix(token, "fp:") || strings.HasPrefix(token, "fpa:") {
				mayWriteFrame = true
			}
		}
	}
	for _, typ := range sig.Args {
		mayWriteFrame = mayWriteFrame || arm64CallTypeMayContainPointer(typ)
	}
	// The typed LLVM call transports only the inputs above, not virtual GP
	// allocas or the automatic R30 continuation blockaddress. This distinction
	// requires the whole-function fresh/non-escaping SP proof. Unknown ABI,
	// hidden context and exposed frames retain the conservative all-GP model.
	// Actual transported/escaped source PC taint remains in returnValue; old
	// GP witnesses are still retained below, without caller-save preservation.
	privateInputs := callTransportKnown && c.sourceGoFrame.present && c.unexposedCallFrame && state.unexposedSP &&
		(arm64ControlCount(state.escaped) == 0 || arm64ControlEscapedOnlyCode(state.escaped))
	if !privateInputs {
		for _, value := range state.regs {
			returnValue = arm64ControlUnion(returnValue, arm64ControlLabels(value))
		}
	}
	for index := 0; index < 31; index++ {
		reg := Reg(fmt.Sprintf("R%d", index))
		if reg != Reg("R30") {
			state.regs[reg] = arm64ControlUnion(arm64ControlRead(state.regs, reg), returnValue)
		}
	}
	if mayWriteFrame {
		// FP slots can alias an incoming pointer and must still be invalidated.
		// Only this invocation's fresh, unexposed SP object is disjoint from
		// declared call values. Actual frame-address arguments, prior escape,
		// unknown calls and unproved source/raw forms retain the old clobber.
		// A conservative callee result may carry the caller's code address.
		// Storing that value does not reveal this fresh allocation's address.
		// Only the separately proven entry/source state can distinguish this
		// case; legacy/default states keep the original any-escape clobber.
		unexposed := arm64ControlCount(state.escaped) == 0 || state.unexposedSP && arm64ControlEscapedOnlyCode(state.escaped)
		preserveSP := callTransportKnown && c.sourceGoFrame.present && c.unexposedCallFrame && unexposed
		for key, value := range state.memory {
			if preserveSP && strings.HasPrefix(key, "sp:") {
				continue
			}
			state.memory[key] = arm64ControlUnion(value, returnValue)
		}
	}
	if !known {
		return
	}
	arm64ControlWriteCallResults(state, sig, internal, returnValue)
}

func arm64ControlWriteCallResults(state *arm64ControlState, sig FuncSig, internal bool, value arm64ControlValue) {
	if internal && sig.ARM64GoRegisterABI != nil {
		for _, result := range sig.ARM64GoRegisterABI.Results {
			state.regs[result.Register] = value
		}
		return
	}
	if !internal && len(sig.ArgRegs) == 0 && len(sig.Frame.Results) != 0 {
		for _, result := range sig.Frame.Results {
			if result.Offset > 1<<63-1-8 {
				continue // The ordinary ABI0 result lowerer rejects this offset.
			}
			key := state.memoryKey(Operand{Kind: OpMem, Mem: MemRef{Base: SP, Off: result.Offset + 8}}, false)
			if key != "" {
				written := value
				if arm64MachineScalarWidth(result.Type) < 64 {
					// Partial results cannot erase code bits in an overlapping
					// cell which a later full-width read could observe.
					old := arm64ControlCallFrameRead(state, result.Offset+8, 64)
					written = arm64ControlUnion(written, arm64ControlLabels(old))
				}
				state.memory[key] = written
			}
		}
		return
	}
	if sig.Ret == Void {
		return
	}
	fields, aggregate := parseLiteralStructFields(sig.Ret)
	if !aggregate {
		fields = []LLVMType{sig.Ret}
	}
	// Match storeABIRegisterResult, including floating results and mixed
	// aggregate GP/FP banks. A floating value can carry source PC bits.
	var cursor arm64ABIRegisterCursor
	for _, field := range fields {
		reg, err := cursor.next(field)
		if err != nil {
			return // The ordinary typed result lowerer rejects this shape.
		}
		state.regs[reg] = value
	}
}

func (c *arm64Ctx) localControlTargets(bi int) ([]string, error) {
	if c.localControl == nil {
		return nil, nil
	}
	value := c.localControl.before[[2]int{bi, c.currentInstruction}]
	var targets []string
	external := false
	for _, token := range arm64ControlKeys(value) {
		if strings.HasPrefix(token, "label:") {
			targets = append(targets, token[6:])
		} else {
			external = true
		}
	}
	if len(targets) != 0 && external {
		return nil, fmt.Errorf("%w: ARM64 register branch has mixed local-code and external/unknown reaching definitions", ErrProbeNeedsContext)
	}
	if len(targets) > 1 && arm64ControlHas(value, "label:"+c.localControl.outer) {
		return nil, fmt.Errorf("%w: ARM64 register branch mixes a native caller link with local blockaddresses", ErrProbeNeedsContext)
	}
	sort.Strings(targets)
	return targets, nil
}
