package plan9asm

import "strings"

// A complete typed forwarding adapter uses the existing ABI0 call allocation.
// This only chooses that existing route. It grants no initialized bytes, FLAGS,
// native backing, caller extent or source authority to its later translation.
func x86ABI0OutgoingForwarder(fn Func, options Options) bool {
	if options.Goarch != "amd64" || options.ResolveSym == nil ||
		fn.FrameSize <= 0 || fn.FrameSize > 4096 || fn.ArgSize < 0 || fn.ArgSize > 4096 ||
		len(fn.Instrs) > 8192 || len(fn.X86RawText) != 0 || strings.Contains(fn.Sym, "<") {
		return false
	}
	resolvedCaller := options.ResolveSym(fn.Sym)
	caller, found := options.Sigs[resolvedCaller]
	if !found || caller.Name != "" && caller.Name != resolvedCaller || !x86ABI0ForwardLayout(caller, fn.ArgSize) {
		return false
	}
	sourceFrames := [2]map[int64]FrameSlot{make(map[int64]FrameSlot), make(map[int64]FrameSlot)}
	for group, slots := range [][]FrameSlot{caller.Frame.Params, caller.Frame.Results} {
		for _, slot := range slots {
			sourceFrames[group][slot.Offset] = slot
		}
	}
	instructions := x86ABI0ForwardInstructions(fn)
	if len(instructions) == 0 || instructions[len(instructions)-1].Op != OpRET ||
		len(instructions[len(instructions)-1].Args) != 0 {
		return false
	}
	start, calls := 0, 0
	for start < len(instructions)-1 {
		at := start
		for at < len(instructions) && instructions[at].Op != OpCALL {
			at++
		}
		if at == len(instructions) || len(instructions[at].Args) != 1 || instructions[at].Args[0].Kind != OpSym {
			return false
		}
		call := instructions[at]
		name, offset, valid := parseSBRef(call.Args[0].Sym)
		if !valid || offset != 0 || strings.Contains(name, "<") || !x86ResultNamedPredicateInstruction(call) {
			return false
		}
		resolved := options.ResolveSym(name)
		callee, declared := options.Sigs[resolved]
		if !declared || callee.Name != "" && callee.Name != resolved || !x86ABI0ForwardLayout(callee, fn.FrameSize) ||
			at-start != 2*len(callee.Frame.Params) || at+1+2*len(callee.Frame.Results) >= len(instructions) ||
			len(caller.Frame.Results) != len(callee.Frame.Results) {
			return false
		}
		writtenResults := make(map[int64]bool, len(caller.Frame.Results))
		for group, slots := range [][]FrameSlot{callee.Frame.Params, callee.Frame.Results} {
			incoming, begin := group == 0, start
			if !incoming {
				begin = at + 1
			}
			for index, slot := range slots {
				load, store := instructions[begin+2*index], instructions[begin+2*index+1]
				if len(load.Args) != 2 || len(store.Args) != 2 {
					return false
				}
				fp, sp, memoryIndex := load.Args[0], store, 1
				if !incoming {
					fp, sp, memoryIndex = store.Args[1], load, 0
				}
				memory, err := fixedLocalMemoryAddress(sp, memoryIndex, fn.FrameSize)
				if err != nil || memory != sp.Args[memoryIndex].Mem || memory.Off != slot.Offset {
					return false
				}
				source, matched := sourceFrames[group][fp.FPOffset]
				if !matched || fp.Kind != OpFP || slot.Type != source.Type || !x86ABI0ForwardCopy(load, store, source, incoming) {
					return false
				}
				if !incoming {
					if writtenResults[source.Offset] {
						return false
					}
					writtenResults[source.Offset] = true
				}
			}
		}
		start = at + 1 + 2*len(callee.Frame.Results)
		calls++
	}
	return calls != 0 && start == len(instructions)-1
}

func x86ABI0ForwardLayout(sig FuncSig, limit int64) bool {
	return x86ABI0FrameLayout(sig, limit, "amd64")
}

func x86ABI0FrameLayout(sig FuncSig, limit int64, arch string) bool {
	if len(sig.ArgRegs) != 0 || sig.ARMEntry != nil || sig.WASMContext != "" ||
		sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil ||
		len(sig.Frame.Params)+len(sig.Frame.Results) > 4096 {
		return false
	}
	results := []LLVMType{sig.Ret}
	if sig.Ret == Void {
		results = nil
	} else if fields, aggregate := parseLiteralStructFields(sig.Ret); aggregate {
		results = fields
	}
	if len(results) != len(sig.Frame.Results) {
		return false
	}
	end := int64(0)
	roles := make(map[string]bool)
	for group, slots := range [][]FrameSlot{sig.Frame.Params, sig.Frame.Results} {
		for index, slot := range slots {
			width := x86FrameScalarBytes(slot.Type, arch)
			if width == 0 || slot.Offset < end || slot.Offset > limit-width {
				return false
			}
			if group == 0 {
				role, valid := x86ResultParameterRole(sig.Args, slot)
				if !valid || roles[role] {
					return false
				}
				roles[role] = true
			} else if slot.Index != index || !x86RawReturnSlotMatchesSignature(slot, 1, sig) {
				return false
			}
			end = slot.Offset + width
		}
	}
	remaining := len(sig.Frame.Params)
	for _, argument := range sig.Args {
		// The existing role check proves every supplied leaf is unique. Count
		// all actual leaves as well, so missing aggregate fields cannot pass.
		err := goLLVMScalarLeaves(argument, nil, uint64(len(sig.Frame.Params)), func(LLVMType, []int) error {
			if remaining == 0 {
				return ErrProbeNeedsContext
			}
			remaining--
			return nil
		})
		if err != nil {
			return false
		}
	}
	return remaining == 0
}
