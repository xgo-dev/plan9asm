package plan9asm

import "strings"

// This is a private logical-storage consumer, not a native frame/return ABI.
// Its complete proof must finish at exact traps on every reachable path before
// the byte adapter may update a numeric parameter shadow. Existing bound entry
// contracts and pointer/canonical-bool storage remain independent.
func x86TrapOnlyLogicalFPSourceRole(fn Func, sig FuncSig, arch string) bool {
	if arch != "amd64" && arch != "386" || fn.FrameSize != 0 || strings.Contains(fn.Sym, "<") ||
		len(sig.ArgRegs) != 0 || sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil ||
		sig.WASMContext != "" || sig.WASMNative || sig.amd64GoArguments != nil || sig.x86FixedLocal != nil ||
		sig.x86CallerRegions != nil || sig.x86BorrowedBoolTail || len(fn.X86RawText) != 0 ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86RawReplay != nil ||
		fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil || len(fn.x86ContinuationAddresses) != 0 ||
		len(fn.x86IndirectLabels) != 0 || fn.x86BoolCalls != nil || fn.x86BoolReadonlyInputs {
		return false
	}
	for _, typ := range append(append([]LLVMType(nil), sig.Args...), sig.Ret) {
		switch typ {
		case I8, I16, I32, I64, LLVMType("float"), LLVMType("double"), Void:
		default:
			return false
		}
	}
	trap := false
	for _, ins := range fn.Instrs {
		if ins.Op == OpCALL || isX86RawDirective(ins) || ins.x86Encoded || ins.x86SourceRaw != nil ||
			ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
			return false
		}
		if _, stack, _ := x86StackWidthProperties(ins, arch); stack {
			return false // This new role does not supplement independent stack storage.
		}
		if _, known, err := x86UndefinedTrapProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false
			}
			// A terminal encoding does not access its written memory operand.
			// Earlier ordinary instructions retain their independent checks.
			trap = true
			continue
		}
		for _, operand := range ins.Args {
			if operand.Kind == OpMem || operand.Kind == OpFPAddr {
				return false
			}
		}
	}
	return trap
}

func (c *amd64Ctx) checkTrapOnlyLogicalFPResultInitialization() error {
	transfer := func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
		if _, known, err := x86UndefinedTrapProperties(ins.Op, ins, arch); known {
			return err == nil
		}
		width := x86IntegerFPMoveWidth(ins, arch)
		if width != 0 && len(ins.Args) == 2 && ins.Args[1].Kind == OpFP {
			if _, err := c.bitTestFPSpan(ins.Args[1].FPOffset, int(width)); err != nil {
				return false
			}
			// Only the logical shadow boundary changes. All source byte/flag
			// requirements still come from the same ordinary typed transfer.
			return x86ScalarFPResultTransfer(ins, state, owned, 0, arch)
		}
		return x86ScalarFPResultTransfer(ins, state, owned, offset, arch)
	}
	return checkX86ABI0ResultInitializationWithTrapOnly(c.fpScalarSource, c.sig, c.goarch, transfer, true, true, false)
}

// Reverse closure requires every successor to terminate, not merely one path
// to a trap. A reachable cyclic SCC never closes, even beside a trapping path.
func x86ResultAllPathsTerminateInTrap(instructions []Instr, edges [][]int, states map[int]x86ResultState, arch string) bool {
	closed, pending, previous := make([]bool, len(instructions)), make([]int, len(instructions)), make([][]int, len(instructions))
	var queue []int
	for pc := range states {
		_, trap, err := x86UndefinedTrapProperties(instructions[pc].Op, instructions[pc], arch)
		if trap && err == nil {
			closed[pc] = true
			queue = append(queue, pc)
			continue
		}
		pending[pc] = len(edges[pc])
		for _, target := range edges[pc] {
			previous[target] = append(previous[target], pc)
		}
	}
	for len(queue) != 0 {
		pc := queue[0]
		queue = queue[1:]
		for _, predecessor := range previous[pc] {
			pending[predecessor]--
			if !closed[predecessor] && pending[predecessor] == 0 {
				closed[predecessor] = true
				queue = append(queue, predecessor)
			}
		}
	}
	for pc := range states {
		if !closed[pc] {
			return false
		}
	}
	return len(states) != 0
}
