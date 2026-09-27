package plan9asm

import (
	"fmt"
	"sort"
	"strings"
)

type arm64DynamicStackPlan struct {
	amount  Reg
	aliases uint32
}

func arm64DynamicStackAmount(ins Instr) (Reg, bool) {
	if ins.Op != "SUB" || len(ins.Args) < 2 || len(ins.Args) > 3 || ins.Args[0].Kind != OpReg {
		return "", false
	}
	for _, arg := range ins.Args[1:] {
		if arg.Kind != OpReg || !arm64StackReg(arg.Reg) {
			return "", false
		}
	}
	index, gp := arm64StackIndex(ins.Args[0].Reg)
	return ins.Args[0].Reg, gp && index < 31
}

// A single runtime-sized extension can move this function's private backing
// only before a local address has escaped or been observed numerically. Copy
// the original bytes and relocate every live alias together, preserving saved
// SPs, address differences and accesses to the original frame. Arbitrary
// dynamic restores, multiple extensions and re-entry remain unproved.
func (c *arm64Ctx) planDynamicStack() *arm64DynamicStackPlan {
	blockAt, instructionAt := -1, -1
	var amount Reg
	labels := make(map[string]int)
	for block, body := range c.blocks {
		labels[body.name] = block
		for at, original := range body.instrs {
			if reg, ok := arm64DynamicStackAmount(arm64StackInstruction(original)); ok {
				if blockAt >= 0 {
					return nil
				}
				blockAt, instructionAt, amount = block, at, reg
			}
		}
	}
	if blockAt < 0 {
		return nil
	}
	for block := range c.blocks {
		for _, next := range c.stackSuccessors(block, labels) {
			if next <= blockAt && (block >= blockAt || next != block+1) {
				return nil // Only the straight-line prefix may reach the extension.
			}
		}
	}
	var state arm64StackState
	state[31] = arm64StackRange{local: true}
	for block := 0; block <= blockAt; block++ {
		for at, original := range c.blocks[block].instrs {
			if block == blockAt && at == instructionAt {
				if state.value(amount).local || !state[31].local {
					return nil
				}
				plan := &arm64DynamicStackPlan{amount: amount}
				for index, value := range state {
					if value.local {
						if value.unknown || index == 28 {
							return nil
						}
						plan.aliases |= 1 << uint(index)
					}
				}
				return plan
			}
			ins := arm64StackInstruction(original)
			if !arm64StackRelocatablePrefix(state, ins) {
				return nil
			}
			if err := arm64StackStep(&state, original, ins); err != nil {
				return nil
			}
		}
	}
	return nil
}

func arm64StackRelocatablePrefix(state arm64StackState, ins Instr) bool {
	op := strings.ToUpper(string(ins.Op))
	// No hidden state observation: unknown/system effects and calls cannot
	// be inferred safe from the absence of an explicit SP operand.
	switch op {
	case "TEXT", "NOP", "MOVD", "MOVW", "MOVWU", "MOVH", "MOVHU", "MOVB", "MOVBU",
		"STP", "LDP", "STP.P", "LDP.P", "STP.W", "LDP.W",
		"ADD", "SUB", "AND", "BIC", "LSL", "LSR", "ASR", "MUL",
		"CMP", "CMN", "TST", "B", "BEQ", "BNE", "BLO", "BHI", "BLT", "BGE", "BLE", "BGT", "BHS", "BLS",
		"BMI", "BPL", "BVS", "BVC", "BCC", "BCS", "CBZ", "CBNZ", "CBZW", "CBNZW", "TBZ", "TBNZ":
	default:
		return false
	}
	usesAddress := false
	for _, arg := range ins.Args {
		switch arg.Kind {
		case OpReg, OpRegShift, OpRegExtend:
			usesAddress = usesAddress || state.value(arg.Reg).local
		case OpRegList:
			for _, reg := range arg.RegList {
				usesAddress = usesAddress || state.value(reg).local
			}
		case OpMem:
			if state.value(arg.Mem.Index).local {
				return false
			}
		case OpSym:
			// Effective-address operands are values, not memory reads. Their
			// destinations are not in the register-copy alias proof above;
			// never relocate storage while leaving such a hidden alias behind.
			if strings.HasPrefix(arg.Sym, "$") {
				memory, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$")))
				if ok && (state.value(memory.Base).local || state.value(memory.Index).local || memory.Base == ZR) {
					return false
				}
			}
		}
	}
	if !usesAddress {
		return true
	}
	// A memory base is not an escaped value, but a GP/list source in a store,
	// comparison, system write or vector insertion can expose the old address.
	last := ins.Args[len(ins.Args)-1]
	if last.Kind != OpReg {
		return false
	}
	if op == "MOVD" && len(ins.Args) == 2 && ins.Args[0].Kind == OpReg {
		return true
	}
	if (op == "ADD" || op == "SUB") && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
		return true
	}
	return false
}

func (c *arm64Ctx) lowerDynamicStack(ins Instr) (bool, error) {
	amount, ok := arm64DynamicStackAmount(ins)
	if !ok || c.dynamicStack == nil || amount != c.dynamicStack.amount {
		return false, nil
	}
	value, err := c.loadReg(amount)
	if err != nil {
		return true, err
	}
	negative, negated, absolute := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %s, 0\n", negative, value)
	fmt.Fprintf(c.b, "  %%%s = sub i64 0, %s\n", negated, value)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %s\n", absolute, negative, negated, value)
	valid, ready, invalid := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ule i64 %%%s, %d\n", valid, absolute, int64(1<<63-1)-c.localStackSize-15)
	fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n%s:\n", valid, ready, invalid, invalid)
	c.b.WriteString("  call void @llvm.trap()\n  unreachable\n")
	fmt.Fprintf(c.b, "%s:\n", ready)
	rounded, extent, bytes := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, 15\n", rounded, absolute)
	fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, -16\n", extent, rounded)
	fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %d\n", bytes, extent, c.localStackSize)
	storage, prefix, original := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = alloca i8, i64 %%%s, align 16\n", storage, bytes)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 0, i64 %%%s\n", prefix, negative, extent)
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %%%s, i64 %%%s\n", original, storage, prefix)
	fmt.Fprintf(c.b, "  call void @llvm.memcpy.p0.p0.i64(ptr %%%s, ptr %s, i64 %d, i1 false)\n", original, c.localStackSlot, c.localStackSize)
	oldAddress, newAddress, shift := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", oldAddress, c.localStackSlot)
	fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", newAddress, original)
	fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, %%%s\n", shift, newAddress, oldAddress)
	var aliases []string
	for reg := range c.regSlot {
		if index, ok := arm64StackIndex(reg); ok && c.dynamicStack.aliases&(1<<uint(index)) != 0 {
			aliases = append(aliases, string(reg))
		}
	}
	sort.Strings(aliases)
	for _, name := range aliases {
		reg := Reg(name)
		old, err := c.loadReg(reg)
		if err != nil {
			return true, err
		}
		rebased := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", rebased, old, shift)
		result := "%" + rebased
		if arm64StackReg(reg) {
			adjusted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", adjusted, result, value)
			result = "%" + adjusted
		}
		if err := c.storeReg(reg, result); err != nil {
			return true, err
		}
	}
	return true, nil
}
