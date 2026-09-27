package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// The allocation is bounded by source control flow, not by an arbitrary extra
// stack cushion. A cycle with a net SP change cannot fit a static local object.
const arm64MaxLocalStackSpan = int64(1 << 20)

type arm64StackRange struct {
	low, high int64
	local     bool
	unknown   bool
}

// Index 31 is SP; other entries describe aliases of this function's allocation.
// Non-local pointers need no storage in that allocation. An unknown local alias
// must never be mistaken for an externally supplied stack pointer.
type arm64StackState [32]arm64StackRange

func arm64StackIndex(reg Reg) (int, bool) {
	if arm64StackReg(reg) {
		return 31, true
	}
	if reg == "g" {
		return 28, true
	}
	name := string(reg)
	if len(name) < 2 || name[0] != 'R' {
		return 0, false
	}
	index, err := strconv.Atoi(name[1:])
	return index, err == nil && index >= 0 && index < 31
}

func (state arm64StackState) value(reg Reg) arm64StackRange {
	if index, ok := arm64StackIndex(reg); ok {
		return state[index]
	}
	return arm64StackRange{}
}

func arm64MergeStackRange(a, b arm64StackRange) arm64StackRange {
	if !a.local {
		return b
	}
	if !b.local {
		return a
	}
	if a.unknown || b.unknown {
		return arm64StackRange{local: true, unknown: true}
	}
	if b.low < a.low {
		a.low = b.low
	}
	if b.high > a.high {
		a.high = b.high
	}
	return a
}

func arm64StackReg(reg Reg) bool { return reg == SP || reg == "RSP" }

func arm64StackInstruction(ins Instr) Instr {
	if ins.Op == OpWORD {
		if len(ins.Args) == 1 {
			if form, ok := decodeARM64RawSVEAddress(uint32(ins.Args[0].Imm)); ok {
				reg := func(index int) Operand {
					if index == 31 {
						return Operand{Kind: OpReg, Reg: SP}
					}
					return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("R%d", index))}
				}
				args := []Operand{{Kind: OpImm, Imm: int64(form.immediate)}}
				if form.op != "RDVL" {
					args = append(args, reg(form.source))
				}
				args = append(args, reg(form.destination))
				return Instr{Op: form.op, Args: args, Raw: ins.Raw}
			}
		}
		if decoded, err := decodeARM64RawWordInstruction(ins); err == nil {
			return decoded
		}
	}
	return ins
}

func (c *arm64Ctx) stackMovementRange() (minimum, maximum int64, err error) {
	if len(c.blocks) == 0 {
		return 0, 0, nil
	}
	c.dynamicStack = c.planDynamicStack()
	labels := make(map[string]int)
	zeroRegisters := c.stackUnwrittenZeroRegisters()
	for i, block := range c.blocks {
		labels[block.name] = i
	}
	inputs := make([]arm64StackState, len(c.blocks))
	seen := make([]bool, len(c.blocks))
	queued := make([]bool, len(c.blocks))
	visits := make([]int, len(c.blocks))
	inputs[0][31] = arm64StackRange{local: true}
	seen[0], queued[0] = true, true
	queue := []int{0}
	steps := 0
	for len(queue) != 0 {
		at := queue[0]
		queue = queue[1:]
		queued[at] = false
		visits[at]++
		steps++
		if steps > 64*len(c.blocks)+64 {
			return 0, 0, fmt.Errorf("ARM64 local stack movement proof exhausted its convergence budget")
		}
		state := inputs[at]
		returned := false
		for _, original := range c.blocks[at].instrs {
			ins := arm64StackInstruction(original)
			ins.Args = append([]Operand(nil), ins.Args...)
			for i := range ins.Args {
				arg := &ins.Args[i]
				if arg.Kind == OpMem {
					if index, ok := arm64StackIndex(arg.Mem.Index); ok && zeroRegisters&(1<<uint(index)) != 0 {
						arg.Mem.Index = ""
					}
				}
			}
			if ins.Op == OpRET {
				returned = true
				break
			}
			// A restored SP need not be bounded if it is never dereferenced
			// again (for example asmcgocall's final restore before RET).
			// Require bounds at each actual local-memory use instead.
			call := ins.Op == "BL" || ins.Op == "CALL" || ins.Op == "BLR"
			for _, arg := range ins.Args {
				if arg.Kind != OpMem || call || !arm64StackReg(arg.Mem.Base) && arg.Mem.Base != ZR {
					continue
				}
				address := state[31]
				if !address.local {
					continue
				}
				offsetLow, offsetHigh, width, err := arm64StackMemoryExtent(ins, arg.Mem)
				if address.unknown || err != nil {
					return 0, 0, fmt.Errorf("ARM64 cannot bound dynamic local stack access: %q", original.Raw)
				}
				if arg.Mem.Off < -arm64MaxLocalStackSpan || arg.Mem.Off > arm64MaxLocalStackSpan {
					return 0, 0, fmt.Errorf("ARM64 local stack operand exceeds %d bytes", arm64MaxLocalStackSpan)
				}
				low, high := address.low+offsetLow, address.high+offsetHigh+width
				if low < minimum {
					minimum = low
				}
				if high > maximum {
					maximum = high
				}
			}
			if call && state[31].unknown {
				return 0, 0, fmt.Errorf("ARM64 cannot bound call frame after dynamic stack restore: %q", original.Raw)
			}
			amount, dynamic := arm64DynamicStackAmount(ins)
			if !dynamic || c.dynamicStack == nil || amount != c.dynamicStack.amount {
				if err := arm64StackStep(&state, original, ins); err != nil {
					return 0, 0, err
				}
			}
			sp := state[31]
			if !sp.local || sp.unknown {
				continue
			}
			if sp.low < -arm64MaxLocalStackSpan || sp.high > arm64MaxLocalStackSpan {
				return 0, 0, fmt.Errorf("ARM64 local stack movement exceeds %d bytes at %q", arm64MaxLocalStackSpan, original.Raw)
			}
			if sp.low < minimum {
				minimum = sp.low
			}
			if sp.high > maximum {
				maximum = sp.high
			}
		}
		if returned {
			continue
		}
		for _, next := range c.stackSuccessors(at, labels) {
			merged := inputs[next]
			changed := !seen[next]
			for reg := range state {
				value := arm64MergeStackRange(merged[reg], state[reg])
				if reg != 31 && visits[next] >= 2 && value.local && value != merged[reg] {
					// Widen changing aliases, not SP itself. Walking a pointer
					// need not enlarge the allocation; restoring an unbounded
					// alias into SP still fails when that SP is dereferenced.
					value = arm64StackRange{local: true, unknown: true}
				}
				changed = changed || value != merged[reg]
				merged[reg] = value
			}
			if changed {
				inputs[next], seen[next] = merged, true
				if !queued[next] {
					queue, queued[next] = append(queue, next), true
				}
			}
		}
	}
	return minimum, maximum, nil
}

func arm64StackStep(state *arm64StackState, original, ins Instr) error {
	op := strings.ToUpper(string(ins.Op))
	base, suffix, _ := strings.Cut(op, ".")
	adjust := func(value arm64StackRange, delta int64) arm64StackRange {
		if value.unknown {
			return arm64StackRange{local: value.local, unknown: true}
		}
		if value.local {
			if delta < -arm64MaxLocalStackSpan || delta > arm64MaxLocalStackSpan ||
				value.low < -arm64MaxLocalStackSpan || value.high > arm64MaxLocalStackSpan {
				value.unknown = true
			} else {
				value.low += delta
				value.high += delta
			}
		}
		return value
	}
	if len(ins.Args) != 0 {
		destination := ins.Args[len(ins.Args)-1]
		index, register := arm64StackIndex(destination.Reg)
		if destination.Kind == OpReg && register {
			switch base {
			case "ADDVL", "ADDPL":
				if len(ins.Args) == 3 && ins.Args[0].Kind == OpImm && ins.Args[1].Kind == OpReg {
					value := state.value(ins.Args[1].Reg)
					unit := int64(16)
					if base == "ADDPL" {
						unit = 2
					}
					// Cover every architectural VL, not just the host's VL.
					low, high := unit*ins.Args[0].Imm, 16*unit*ins.Args[0].Imm
					if low > high {
						low, high = high, low
					}
					if value.local && !value.unknown {
						value.low += low
						value.high += high
					}
					state[index] = value
					return nil
				}
			case "RDVL":
				state[index] = arm64StackRange{}
				return nil
			case "MOVD":
				if len(ins.Args) == 2 && ins.Args[0].Kind == OpReg {
					state[index] = state.value(ins.Args[0].Reg)
					return nil
				}
				if len(ins.Args) == 2 && suffix == "" {
					// A context switch may install externally owned storage.
					// Reloading from our own stack is not proof of that: it may
					// be a saved local SP, whose offset needs a separate proof.
					local := ins.Args[0].Kind == OpMem && state.value(ins.Args[0].Mem.Base).local
					state[index] = arm64StackRange{local: local, unknown: local}
					return nil
				}
			case "ADD", "SUB":
				value := state[index]
				if len(ins.Args) == 3 && ins.Args[1].Kind == OpReg {
					value = state.value(ins.Args[1].Reg)
				}
				if ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
					delta := ins.Args[0].Imm
					if delta < -arm64MaxLocalStackSpan || delta > arm64MaxLocalStackSpan {
						value.unknown = value.local
					} else if base == "SUB" {
						delta = -delta
					}
					state[index] = adjust(value, delta)
					return nil
				}
			case "AND", "BIC":
				if ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
					mask := uint64(ins.Args[0].Imm)
					if base == "AND" {
						mask = ^mask
					}
					if mask <= uint64(arm64MaxLocalStackSpan) && mask&(mask+1) == 0 {
						value := state[index]
						if len(ins.Args) == 3 && ins.Args[1].Kind == OpReg {
							value = state.value(ins.Args[1].Reg)
						}
						// Alignment rounds an address down by at most mask,
						// irrespective of the alloca's actual base alignment.
						if value.local && !value.unknown {
							value.low -= int64(mask)
						}
						state[index] = value
						return nil
					}
				}
			}
		}
	}
	arm64StackInvalidateWrites(state, original, ins)
	if suffix == "P" || suffix == "W" {
		for _, operand := range ins.Args {
			if operand.Kind == OpMem && (arm64StackReg(operand.Mem.Base) || operand.Mem.Base == ZR) {
				if state[31].local && (operand.Mem.Index != "" && operand.Mem.Index != ZR || operand.Mem.OffRaw != "") {
					return fmt.Errorf("ARM64 cannot bound indexed stack writeback: %q", ins.Raw)
				}
				state[31] = adjust(state[31], operand.Mem.Off)
				return nil
			}
		}
	}
	return nil
}

func arm64StackInvalidateWrites(state *arm64StackState, original, ins Instr) {
	// Unmodeled arithmetic can retain a local address but loses its bounds.
	// Stores and flag-only/branch operations do not overwrite their GP inputs.
	op := strings.ToUpper(string(ins.Op))
	base, _, _ := strings.Cut(op, ".")
	if strings.HasPrefix(base, "CMP") || strings.HasPrefix(base, "CMN") ||
		strings.HasPrefix(base, "TST") || base == "NOP" || base == "B" || base == "JMP" ||
		strings.HasPrefix(base, "CB") || strings.HasPrefix(base, "TB") {
		return
	}
	var writes uint32
	var derived bool
	for _, arg := range ins.Args {
		if arg.Kind == OpReg || arg.Kind == OpRegShift || arg.Kind == OpRegExtend {
			derived = derived || state.value(arg.Reg).local
			if index, ok := arm64StackIndex(arg.Reg); ok {
				writes |= 1 << uint(index)
			}
		}
	}
	if original.Op == OpWORD && len(original.Args) == 1 {
		if mask, known := arm64RawPoolGPWrites(uint32(original.Args[0].Imm)); known {
			writes = mask
		} else {
			writes = 0x7fffffff
			for index, value := range state {
				if index != 31 {
					derived = derived || value.local
				}
			}
		}
	} else if len(ins.Args) != 0 {
		last := ins.Args[len(ins.Args)-1]
		if last.Kind == OpMem || base == "STP" || base == "STNP" {
			writes = 0
		} else if last.Kind == OpReg {
			writes = 0
			if index, ok := arm64StackIndex(last.Reg); ok {
				writes = 1 << uint(index)
			}
		} else if last.Kind == OpRegList {
			writes = 0
			for _, reg := range last.RegList {
				if index, ok := arm64StackIndex(reg); ok {
					writes |= 1 << uint(index)
				}
			}
		}
	}
	for index := range state {
		if writes&(1<<uint(index)) != 0 {
			state[index] = arm64StackRange{local: derived, unknown: derived}
		}
	}
}

func (c *arm64Ctx) stackSuccessors(at int, labels map[string]int) []int {
	block := c.blocks[at]
	var successors []int
	canFallThrough := true
	if len(block.instrs) != 0 {
		last := arm64StackInstruction(block.instrs[len(block.instrs)-1])
		op := strings.ToUpper(string(last.Op))
		switch op {
		case "RET", "UNDEF", "BRK":
			canFallThrough = false
		case "B", "JMP", "BR", "BEQ", "BNE", "BLO", "BHI", "BLT", "BGE", "BLE", "BGT", "BHS", "BLS",
			"BMI", "BPL", "BVS", "BVC", "BCC", "BCS", "CBZ", "CBNZ", "CBZW", "CBNZW", "TBZ", "TBNZ", "BL", "BLR", "CALL":
			canFallThrough = op != "B" && op != "JMP" && op != "BR"
			if len(last.Args) != 0 {
				target := last.Args[len(last.Args)-1]
				if name, ok := arm64BranchTarget(target); ok {
					if next, local := labels[name]; local {
						successors = append(successors, next)
					}
				} else if target.Kind == OpReg && !canFallThrough {
					// Computed local branches must not hide a stack-changing path.
					for next := range c.blocks {
						successors = append(successors, next)
					}
				}
			}
		}
	}
	if canFallThrough && at+1 < len(c.blocks) {
		successors = append(successors, at+1)
	}
	return successors
}
