package plan9asm

import "fmt"

// Private 386 TEXT storage begins at physical SP after frame allocation.
// Offsets are retained separately from numerical and caller address values.
// A spill stores an actual caller pointer, with zero meaning no complete cell.
type x86Mode32FrameState struct {
	addresses [8]int16 // offset plus one, so zero means no reaching address
	spills    []uint16
}

const x86Mode32SpillUnknownOrigin = ^uint16(0)

func x86Mode32FixedFrameCandidate(fn Func, arch string) bool {
	if arch != "386" || fn.FrameSize <= 0 || fn.x86RawReplay != nil ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil ||
		fn.x86ContinuationFlow != nil || fn.x86DirectTailRoot != nil || fn.x86BoolCalls != nil {
		return false
	}
	for _, ins := range fn.Instrs {
		if x86InertNOP(ins, arch) {
			continue
		}
		for _, operand := range ins.Args {
			if operand.Kind == OpReg && operand.Reg == SP ||
				operand.Kind == OpMem && operand.Mem.Base == SP && operand.Mem.Off >= 0 && operand.Mem.Sym == "" {
				return true
			}
		}
	}
	return false
}

func x86CheckMode32FixedFrame(fn Func) error {
	fail := func(reason string, src string) error {
		return fmt.Errorf("%w: 386 fixed TEXT frame: %s: %q", ErrProbeNeedsContext, reason, src)
	}
	if fn.FrameSize > 4096 || len(fn.Instrs) == 0 || len(fn.Instrs) > 4096 ||
		fn.Instrs[0].Op != OpTEXT || fn.FrameSize%4 != 0 {
		return fail("requires a bounded word-aligned frame", fn.Sym)
	}
	if err := x86ResultLocalSourceReplay(fn, "386", "physical frame"); err != nil {
		return err
	}
	for _, ins := range fn.Instrs {
		if !x86ResultNamedPredicateInstruction(ins) || x86LinuxSyscallCandidate(ins) {
			return fail("requires original named effects and an ordinary return", ins.Raw)
		}
		if _, stack, _ := x86StackWidthProperties(ins, "386"); stack || models386SPWrite(ins) ||
			ins.Op == "ADJSP" || ins.Op == "CALL" {
			return fail("changes or exposes physical SP", ins.Raw)
		}
		_, rest := splitOpcode(ins.Raw)
		for _, literal := range splitTopLevelCSV(rest) {
			// Named AUTO and physical SP have distinct source roles. The
			// physical proof uses only resolved displacements on the real SP.
			match := x86ResultAUTOLiteral.FindStringSubmatch(literal)
			if match == nil {
				continue
			}
			if _, named := parseNamedStackConstantOffset(match[1]); named {
				return fail("mixed logical AUTO and physical SP operands", ins.Raw)
			}
		}
	}
	return nil
}

func (frame *x86Mode32FrameState) registerOffset(reg Reg) (int64, bool) {
	if reg == SP {
		return 0, true
	}
	index, _, valid := x86ResultGP(reg, 4, "386")
	if !valid || frame.addresses[index] == 0 {
		return 0, false
	}
	return int64(frame.addresses[index] - 1), true
}

func (frame *x86Mode32FrameState) offset(arg Operand, width int64) (int, bool) {
	if arg.Kind != OpMem {
		return 0, false
	}
	base, local := frame.registerOffset(arg.Mem.Base)
	disp := arg.Mem.Off
	if !local || arg.Mem != (MemRef{Base: arg.Mem.Base, Off: disp}) || width < 0 ||
		disp < -base || disp > int64(len(frame.spills))-base-width {
		return 0, false
	}
	return int(base + disp), true
}

func (frame *x86Mode32FrameState) clearSpills(start, width int) {
	// A write can intersect a pointer cell beginning up to three bytes
	// before it. The exact cell is restored only by a whole-pointer store.
	lo := start - 3
	if lo < 0 {
		lo = 0
	}
	for i := lo; i < start+width; i++ {
		frame.spills[i] = 0
	}
}

func x86Mode32FrameEffect(ins Instr) (x86TypedByteEffect, bool) {
	if form, known, err := x86ScalarPhysicalMoveProperties(ins, "386"); known {
		width := int64(form.bits / 8)
		return x86TypedByteEffect{operands: []x86TypedByteOperand{
			{operand: form.source, width: width, read: true},
			{operand: form.destination, width: width, write: true},
		}}, err == nil
	}
	if form, known, err := x86ScalarCompareProperties(ins.Op, ins, "386"); known {
		width := int64(form.bits / 8)
		return x86TypedByteEffect{operands: []x86TypedByteOperand{
			{operand: form.args[0], width: width, read: true},
			{operand: form.args[1], width: width, read: true},
		}}, err == nil
	}
	effect, known, err := x86TypedGPByteEffect(ins.Op, ins, "386")
	return effect, known && err == nil && !effect.dynamicMemory
}

// Run the existing paired transfer for all ordinary effects. This observer
// only introduces private addresses and word spills and guards their uses.
// It never passes an instruction with rewritten operands to a consumer.
func x86Mode32FrameStep(ins Instr, state *x86ResultState, ordinary func() bool) (bool, int, uint16) {
	frame := state.mode32Frame
	if x86InertNOP(ins, "386") {
		return ordinary(), -1, 0
	}
	touches := false
	for _, operand := range ins.Args {
		switch operand.Kind {
		case OpReg:
			_, local := frame.registerOffset(operand.Reg)
			touches = touches || local
		case OpMem:
			_, local := frame.registerOffset(operand.Mem.Base)
			if _, indexLocal := frame.registerOffset(operand.Mem.Index); indexLocal {
				return false, -1, 0
			}
			touches = touches || local
		}
	}
	if !touches && (frame.addresses == [8]int16{} || ins.Op == OpJMP ||
		isAMD64ConditionalBranch(ins.Op) && x86ByteBranchFlags(ins.Op) != 0) {
		return ordinary(), -1, 0
	}
	if len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		destination, _, gp := x86ResultGP(ins.Args[1].Reg, 4, "386")
		if gp && touches {
			source := ins.Args[0]
			offset, local := frame.offset(source, 0)
			switch ins.Op {
			case "LEAL":
				if local {
					if _, err := x86LEAOperandWidth(ins, "386"); err != nil {
						return false, -1, 0
					}
					frame.addresses[destination] = int16(offset + 1)
					state.gp[destination], state.canonicalGP[destination] = 0, 0
					state.pointerGP[destination] = false
					return true, -1, 0
				}
			case "MOVL":
				if source.Kind == OpReg {
					if registerOffset, local := frame.registerOffset(source.Reg); local {
						frame.addresses[destination] = int16(registerOffset + 1)
						state.gp[destination], state.canonicalGP[destination] = 0, 0
						state.pointerGP[destination] = false
						return true, -1, 0
					}
				}
				if offset, local = frame.offset(source, 4); local && frame.spills[offset] != 0 {
					frame.addresses[destination] = 0
					state.gp[destination], state.canonicalGP[destination] = 0, 0
					state.pointerGP[destination] = true
					return true, destination, frame.spills[offset]
				}
			}
		}
		if ins.Op == "LEAL" {
			// A local LEA may only create another bounded address.
			if ins.Args[0].Kind == OpMem {
				if _, local := frame.registerOffset(ins.Args[0].Mem.Base); local {
					return false, -1, 0
				}
			}
		}
	}
	if ins.Op == "MOVL" && len(ins.Args) == 2 {
		source, destination := ins.Args[0], ins.Args[1]
		if offset, local := frame.offset(destination, 4); local &&
			x86ResultPointerOperand(source, state.callerAddressGP, state.callerAddressFP, "386") {
			if _, _, err := x86ScalarPhysicalMoveProperties(ins, "386"); err != nil {
				return false, -1, 0
			}
			origin := x86Mode32SpillUnknownOrigin
			if i, _, reg := x86ResultGP(source.Reg, 4, "386"); source.Kind == OpReg && reg &&
				state.callerAddressOrigin[i] != 0 {
				origin = state.callerAddressOrigin[i]
			}
			frame.clearSpills(offset, 4)
			frame.spills[offset] = origin
			for i := offset; i < offset+4; i++ {
				state.auto[i] = false
			}
			return true, -1, 0
		}
	}
	effect, valid := x86Mode32FrameEffect(ins)
	if !valid {
		return false, -1, 0
	}
	next := frame.addresses
	for _, use := range effect.operands {
		switch arg := use.operand; arg.Kind {
		case OpMem:
			if _, local := frame.registerOffset(arg.Mem.Base); local {
				if _, bound := frame.offset(arg, use.width); !bound {
					return false, -1, 0
				}
			}
		case OpReg:
			root, _ := x86CallerGP(arg.Reg)
			if _, local := frame.registerOffset(root); local && use.read || arg.Reg == SP {
				return false, -1, 0
			}
			if index, _, gp := x86ResultGP(arg.Reg, use.width, "386"); use.write && gp {
				next[index] = 0
			}
		}
	}
	if !ordinary() {
		return false, -1, 0
	}
	state.mode32Frame.addresses = next
	return true, -1, 0
}

func (state *x86ResultState) localOffset(arg Operand, width int64) (int, bool) {
	if state.mode32Frame != nil {
		return state.mode32Frame.offset(arg, width)
	}
	return x86ResultAUTOOffset(arg, width, len(state.auto))
}
