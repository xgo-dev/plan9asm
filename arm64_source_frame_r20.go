package plan9asm

import "strings"

// Go obj7's large-frame prologue assigns R20 before entering the source body:
// SUB autosize,SP,R20; STP (BP,LR),-8(R20); MOVD R20,SP. This is the new
// private SP root, not an arbitrary incoming pointer or the native caller SP.
// Keep this producer tied to the complete source TEXT contract.
func arm64SourceFrameR20(fn Func) bool {
	if !arm64SourceFrameR20Candidate(fn) {
		return false
	}
	texts := 0
	for _, ins := range fn.Instrs {
		if ins.Op != OpTEXT {
			continue
		}
		texts++
		_, rest := splitOpcode(ins.Raw)
		parts := strings.Split(rest, ",")
		if len(parts) < 2 || len(parts) > 3 {
			return false
		}
		// An omitted args suffix is Go's ArgsSizeUnknown, not an explicit
		// zero-sized caller frame (the parser retains zero for both).
		spec := strings.TrimSpace(parts[len(parts)-1])
		if !strings.HasPrefix(spec, "$") || strings.LastIndex(spec, "-") <= 1 {
			return false
		}
		size, args, err := parseTEXTFrame(parts)
		if err != nil || size != fn.FrameSize || args != fn.ArgSize {
			return false
		}
	}
	return texts == 1
}

// Only a large source-leaf frame may require the separate R20 producer. A
// software definition in an ordinary small function must not replace its
// existing stack/control proof with the framed raw-leaf proof.
//
// Keep malformed or incomplete large TEXT metadata on this checked path:
// arm64SourceFrameR20 must independently establish the complete producer before
// R20 becomes available. An omitted argument suffix cannot turn that read into
// an unchecked, zero-initialized virtual register.
func arm64SourceFrameR20Required(fn Func) bool {
	return arm64SourceFrameR20Candidate(fn) && arm64SourceUsesR20(fn)
}

// This is only a cost/routing predicate, not permission to initialize R20.
// Larger dynamic allocations, ordinary nonleaf calls and existing source-local
// register helpers keep their own stack and entry contracts.
func arm64SourceFrameR20Candidate(fn Func) bool {
	frame := arm64SourceGoFrame(fn)
	return frame.present && !frame.restoresLink && arm64SourceFrameFlagsKnown(fn) &&
		fn.FrameSize > 0 && fn.FrameSize <= arm64MaxLocalStackSpan && fn.FrameSize&7 == 0 &&
		arm64SourceFrameAutosize(fn.FrameSize) > 0xf0
}

// The bounded scalar-word transport requires reaching definitions even when
// software overwrites R20. Other existing entry contracts retain their own
// availability checks; legacy format-only signatures acquire no new contract.
func arm64SourceFrameR20Checked(fn Func, sig FuncSig, resolve func(string) string) bool {
	return arm64SourceUsesR20(fn) && (arm64SourceFrameR20Required(fn) ||
		(len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 0) &&
			arm64SourceFrameR20Transport(fn, &arm64PrivateFrameTransport{entry: sig, resolve: resolve}))
}

func arm64SourceUsesR20(fn Func) bool {
	for _, original := range fn.Instrs {
		ins := arm64ControlDecode(original)
		for _, arg := range ins.Args {
			regs := []Reg{arg.Reg, arg.ShiftReg, arg.Mem.Base, arg.Mem.Index}
			regs = append(regs, arg.RegList...)
			if arg.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(arg.Sym), "$") {
				if mem, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$"))); ok {
					regs = append(regs, mem.Base, mem.Index)
				}
			}
			for _, reg := range regs {
				if arm64MachineRegister(reg) == "R20" {
					return true
				}
			}
		}
	}
	return false
}

// This bounded family uses the ordinary complete ABI0 scalar-word frame,
// including explicit result slots. A manual equivalent must be just as
// complete; no default/fallback signature, hidden context, custom register ABI
// or aggregate layout grants dead-scratch transport at RET.
func arm64SourceFrameR20Transport(fn Func, transport *arm64PrivateFrameTransport) bool {
	if transport == nil || fn.arm64PrivateRegisterEntry || strings.HasSuffix(fn.Sym, "<ABIInternal>") {
		return false
	}
	sig := transport.entry
	name := fn.Sym
	if transport.resolve != nil {
		name = transport.resolve(name)
	}
	if sig.Name != name || len(sig.ArgRegs) != 0 || sig.ARM64GoRegisterABI != nil ||
		sig.ARM64ClosureABI != nil || sig.ARMEntry != nil || sig.WASMContext != "" || sig.WASMNative ||
		len(sig.Frame.Params) != len(sig.Args) {
		return false
	}
	for index, typ := range sig.Args {
		if !arm64SourceFrameR20Scalar(typ) || !arm64SourceFrameR20Slot(sig.Frame.Params[index], typ, index, int64(index)*8) {
			return false
		}
	}
	bytes := int64(len(sig.Args)) * 8
	if sig.Ret == Void {
		if len(sig.Frame.Results) != 0 {
			return false
		}
	} else {
		// Floating FP-slot fallback currently reads a GP ordinal, whereas
		// typed call results use the FP bank. Do not borrow that separate
		// unfinished result contract to make a private address dead.
		if (sig.Ret != I64 && sig.Ret != Ptr) || len(sig.Frame.Results) != 1 ||
			!arm64SourceFrameR20Slot(sig.Frame.Results[0], sig.Ret, 0, bytes) {
			return false
		}
		bytes += 8
	}
	if bytes != fn.ArgSize {
		return false
	}
	for _, ins := range fn.Instrs {
		if ins.Op != OpTEXT {
			continue
		}
		_, rest := splitOpcode(ins.Raw)
		parts := strings.Split(rest, ",")
		if len(parts) == 3 {
			expression := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
				if value, ok := goTextFlagValues[name]; ok {
					return value
				}
				return name
			})
			flags, known := parseImmExpr(expression)
			if !known || flags&64 != 0 { // NEEDCTXT is an unproved hidden input.
				return false
			}
		}
	}
	return true
}

func arm64SourceFrameR20Scalar(typ LLVMType) bool {
	return typ == I64 || typ == Ptr || typ == "double"
}

func arm64SourceFrameR20Slot(slot FrameSlot, typ LLVMType, index int, offset int64) bool {
	return slot.Type == typ && slot.Index == index && slot.Offset == offset &&
		slot.Field == -1 && len(slot.Fields) == 0
}
