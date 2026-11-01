package plan9asm

import "strings"

// The virtual SP initialized by emitEntryAllocasAndArgInit points into a fresh
// function-local LLVM allocation, not into the native caller's incoming stack.
// A typed call transports only its declared values, never that virtual SP as an
// implicit ABI0 frame. Incoming pointers therefore cannot name this allocation
// unless the source first exposes its address. This bounded, whole-function
// check also admits bounded affine temporaries used only by known local reads
// and fully overwritten before calls/returns, before and after normalization.
// Dead escapes and unknown effects still disable the complete source proof.
// It does not establish ownership of incoming pointers or the separate FP slots.
func arm64CallFrameUnexposed(fn Func) bool {
	return arm64CallFrameUnexposedForTransport(fn, nil)
}

func arm64CallFrameUnexposedTyped(fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig) bool {
	return arm64CallFrameUnexposedTypedTarget(fn, sig, resolve, sigs, "")
}

func arm64CallFrameUnexposedTypedTarget(fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, target string) bool {
	if !arm64CallFrameFreshEntry(sig) || sig.ARM64ClosureABI != nil {
		return false
	}
	if sig.ARM64GoRegisterABI != nil && arm64ValidateGoRegisterABI(sig) != nil {
		return false
	}
	transport := &arm64PrivateFrameTransport{entry: sig, resolve: resolve, sigs: sigs}
	proof, required := arm64NanosleepInputForSource(fn, transport, target)
	if required && proof == nil {
		return false
	}
	transport.nanosleep = proof
	return arm64CallFrameUnexposedForTransport(fn, transport)
}

func arm64CallFrameUnexposedForTransport(fn Func, transport *arm64PrivateFrameTransport) bool {
	if !arm64SourceGoFrame(fn).present {
		return arm64RawZeroFrameUnexposedForTransport(fn, transport)
	}
	if arm64HasRawFrameCode(fn) || arm64SourceFrameR20Required(fn) {
		return arm64RawPrivateFrameUnexposedForTransport(fn, transport)
	}
	text, affine := false, false
	for _, original := range fn.Instrs {
		if original.Op == OpTEXT {
			_, rest := splitOpcode(original.Raw)
			parts := strings.Split(rest, ",")
			if len(parts) < 2 || len(parts) > 3 || !strings.HasPrefix(strings.TrimSpace(parts[len(parts)-1]), "$") {
				return false
			}
			frame, _, err := parseTEXTFrame(parts)
			if err != nil || frame != fn.FrameSize {
				return false
			}
			text = true
		}
		ins := arm64StackInstruction(arm64ControlDecode(original))
		op := arm64ControlOp(ins)
		switch op {
		case OpWORD, "DWORD", arm64RawDataOp, "ADR", "ADRP", "BLR":
			return false
		case "CALL", "BL":
			if len(ins.Args) != 1 {
				return false
			}
			if ins.Args[0].Kind != OpSym && !(fn.arm64PrivateUnexposedFrame && ins.Args[0].Kind == OpIdent) {
				return false
			}
		}
		for _, operand := range ins.Args {
			if operand.Kind == OpFPAddr {
				return false
			}
			// An ordinary SP-relative load/store uses the private allocation
			// without transporting its address as a scalar. An SP index or a
			// register/shift/extension/list operand can expose that address.
			registers := []Reg{operand.Reg, operand.ShiftReg, operand.Mem.Index}
			registers = append(registers, operand.RegList...)
			if operand.Kind == OpSym {
				symbol := strings.TrimSpace(operand.Sym)
				if strings.HasPrefix(symbol, "$") {
					if strings.Contains(symbol, "(FP)") {
						return false
					}
					if memory, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(symbol, "$"))); ok {
						registers = append(registers, memory.Base, memory.Index)
					}
				}
			}
			for _, reg := range registers {
				if arm64StackReg(reg) {
					affine = true
				}
			}
		}
	}
	return text && (!affine || arm64PrivateFrameReadProofForTransport(fn, transport))
}

// Entry transport is emitted after the fresh SP initialization. A custom
// incoming SP assignment would replace that root; it cannot borrow this proof.
// Standard Go register contracts assign only GP/FP banks, but retain a
// conservative check here as well for a caller-supplied malformed contract.
func arm64CallFrameFreshEntry(sig FuncSig) bool {
	for _, reg := range sig.ArgRegs {
		if arm64StackReg(reg) {
			return false
		}
	}
	if sig.ARM64GoRegisterABI != nil {
		for _, param := range sig.ARM64GoRegisterABI.Params {
			if arm64StackReg(param.Register) {
				return false
			}
		}
	}
	return true
}

// Reuse the complete scalar/aggregate traversal. Its bounded register grammar
// does not recognize every stack-ABI aggregate; an unrecognized type remains
// possibly pointer-containing, rather than acquiring an invented noalias fact.
func arm64CallTypeMayContainPointer(typ LLVMType) bool {
	pointer := false
	err := arm64GoABILeaves(typ, nil, func(leaf LLVMType, _ []int) error {
		pointer = pointer || leaf == Ptr
		return nil
	})
	return pointer || err != nil
}
