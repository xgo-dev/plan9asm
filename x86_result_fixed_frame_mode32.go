package plan9asm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/goabi"
)

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
		if ins.Op == "ADJSP" || x86InertNOP(ins, arch) {
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

func x86CheckMode32FixedFrame(fn Func, layout FrameLayout, calls map[string]x86Mode32FrameCall) error {
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
	if len(layout.Params) == 0 && len(layout.Results) == 0 {
		// An FP address needs an incoming typed slot even when the
		// instruction itself lives in a bounded physical TEXT frame.
		for _, ins := range fn.Instrs {
			if _, _, _, address := x86LogicalFPLEAWriteShape(ins, "386"); address {
				return x86UnboundFPAddress("386", ins.Args[0].FPOffset)
			}
		}
	}
	for _, ins := range fn.Instrs {
		if !x86ResultNamedPredicateInstruction(ins) || x86LinuxSyscallCandidate(ins) {
			return fail("requires original named effects and an ordinary return", ins.Raw)
		}
		_, boundCall := x86Mode32FrameCallAt(ins, calls)
		if _, stack, _ := x86StackWidthProperties(ins, "386"); stack || models386SPWrite(ins) ||
			ins.Op == "ADJSP" || ins.Op == OpCALL && !boundCall {
			return fail("changes or exposes physical SP", ins.Raw)
		}
		var literals []string
		for index, operand := range ins.Args {
			if operand.Kind != OpMem || operand.Mem.Base != SP || operand.Mem.Sym != "" {
				continue
			}
			if literals == nil {
				_, rest := splitOpcode(ins.Raw)
				literals = splitTopLevelCSV(rest)
			}
			if len(literals) != len(ins.Args) || operand.Mem.OffRaw != "" {
				return fail("unbound SP operand spelling", ins.Raw)
			}
			offset, named := int64(0), false
			if match := x86ResultAUTOLiteral.FindStringSubmatch(literals[index]); match != nil {
				offset, named = parseNamedStackConstantOffset(match[1])
			}
			// Go's virtual SP is at the top of the allocated frame. Only
			// negative named offsets reach into it. Bare physical offsets
			// are relative to the bottom of the same frame.
			if named && (offset != operand.Mem.Off || offset >= 0) || !named && operand.Mem.Off < 0 {
				return fail("SP operand outside its source frame role", ins.Raw)
			}
		}
	}
	return nil
}

type x86Mode32FrameCall struct {
	name   string
	sig    FuncSig
	extent int
}

func x86Mode32FrameCallAt(ins Instr, calls map[string]x86Mode32FrameCall) (x86Mode32FrameCall, bool) {
	if ins.Op != OpCALL || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
		return x86Mode32FrameCall{}, false
	}
	call, bound := calls[strings.TrimSpace(ins.Args[0].Sym)]
	return call, bound
}

// Use the same symbol and typed outgoing layout as the LLVM call emitter.
// Indirect calls, entry selectors and calls without stack slots cannot supply
// a bounded SP effect. Bool bytes require the separate canonical-byte role.
func (c *amd64Ctx) mode32FrameCalls(fn Func) map[string]x86Mode32FrameCall {
	if c.resolve == nil || fn.FrameSize > 4096 || len(fn.Instrs) > 4096 ||
		!x86Mode32FixedFrameCandidate(fn, c.goarch) {
		return nil
	}
	var calls map[string]x86Mode32FrameCall
	for _, ins := range fn.Instrs {
		if ins.Op != OpCALL || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
			continue
		}
		target := strings.TrimSpace(ins.Args[0].Sym)
		if _, known := calls[target]; known {
			continue
		}
		name, offset, valid := parseSBRef(target)
		if !valid || offset != 0 || target != name+"(SB)" ||
			strings.HasPrefix(name, "*") || strings.Contains(strings.TrimSuffix(name, "<>"), "<") {
			continue
		}
		resolved := c.resolve(name)
		sig, found := c.sigs[resolved]
		if !found || arm64ElidesSchedulerHook(resolved) || len(sig.Frame.Params)+len(sig.Frame.Results) == 0 ||
			!x86ABI0FrameLayout(sig, fn.FrameSize, "386") {
			continue
		}
		var end int64
		for _, slots := range [][]FrameSlot{sig.Frame.Params, sig.Frame.Results} {
			for _, slot := range slots {
				if slot.Type == I1 {
					valid = false
				}
				end = slot.Offset + x86FrameScalarBytes(slot.Type, "386")
			}
		}
		extent, bounded := goabi.ABI0StackSize("386", end)
		if !valid || !bounded || extent > fn.FrameSize {
			continue
		}
		if calls == nil {
			calls = make(map[string]x86Mode32FrameCall)
		}
		calls[target] = x86Mode32FrameCall{name: resolved, sig: sig, extent: int(extent)}
	}
	return calls
}

func (call x86Mode32FrameCall) transfer(state *x86ResultState) bool {
	frame := state.mode32Frame
	for _, slot := range call.sig.Frame.Params {
		offset := int(slot.Offset)
		width := int(x86FrameScalarBytes(slot.Type, "386"))
		if slot.Type == Ptr && frame.spills[offset] != 0 {
			continue // A complete caller-pointer spill can cross the call.
		}
		for _, initialized := range state.auto[offset : offset+width] {
			if !initialized {
				return false
			}
		}
	}

	// The callee may overwrite its whole outgoing area. Preserve disjoint
	// local storage and revoke register, flags and frame-alias facts.
	for i := range state.auto[:call.extent] {
		state.auto[i] = false
	}
	frame.clearSpills(0, call.extent)
	for _, slot := range call.sig.Frame.Results {
		offset := int(slot.Offset)
		if slot.Type == Ptr {
			frame.spills[offset] = x86Mode32SpillUnknownOrigin
			continue
		}
		width := int(x86FrameScalarBytes(slot.Type, "386"))
		for i := offset; i < offset+width; i++ {
			state.auto[i] = true
		}
	}
	frame.addresses = [8]int16{}
	state.revokeABICallRegisters()
	return true
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
	if arg.Mem.Base == SP && disp < 0 {
		disp += int64(len(frame.spills)) // The source check bound this as a named AUTO.
	}
	if !local || arg.Mem != (MemRef{Base: arg.Mem.Base, Off: arg.Mem.Off}) || width < 0 ||
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
	if effect, known, err := x86SystemOperandProperties(ins.Op, ins, "386"); known {
		if err != nil {
			return x86TypedByteEffect{}, false
		}
		return x86TypedByteEffect{operands: []x86TypedByteOperand{effect}}, true
	}
	if _, known, err := x86CacheLineWritebackProperties(ins.Op, ins, "386"); known {
		if err != nil {
			return x86TypedByteEffect{}, false
		}
		return x86TypedByteEffect{operands: []x86TypedByteOperand{{operand: ins.Args[0], width: 1}}}, true
	}
	if site, known, err := x86NativeMMXInstruction(ins, "386"); known {
		if err != nil {
			return x86TypedByteEffect{}, false
		}
		return x86TypedByteEffect{operands: site.frameOperands()}, true
	}
	if form, known, err := x86ScalarPhysicalMoveProperties(ins, "386"); known {
		width := int64(form.bits / 8)
		return x86TypedByteEffect{operands: []x86TypedByteOperand{
			{operand: form.source, width: width, read: true},
			{operand: form.destination, width: width, write: true},
		}}, err == nil
	}
	if form, known, err := amd64ScalarVectorMoveProperties(ins, "386"); known {
		if err != nil || form.memory < 0 {
			return x86TypedByteEffect{}, false
		}
		return x86TypedByteEffect{operands: []x86TypedByteOperand{{
			operand: ins.Args[form.memory], width: int64(form.spec.bits / 8),
			read: !form.memoryWrite, write: form.memoryWrite,
		}}}, true
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
	if x86InertNOP(ins, "386") || ins.Op == OpCALL {
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
