package plan9asm

// This is a cost predicate, not storage or initialization authority. A named
// result-field FP LEA must not bypass the cached whole-source
// proof merely because no GP/X transfer or scalar-vector probe follows it.
func x86OrdinaryResultAddressNeedsProof(fn Func, sig FuncSig, arch string) bool {
	if arch != "386" && arch != "amd64" {
		return false
	}
	for _, ins := range fn.Instrs {
		if (ins.Op == "LEAW" || ins.Op == "LEAL" || ins.Op == "LEAQ") && len(ins.Args) == 2 && ins.Args[0].Kind == OpFP {
			for _, slot := range sig.Frame.Results {
				width := x86ResultScalarBytes(slot.Type, arch)
				if x86OrdinaryNumericAddressSlot(slot) && slot.Offset >= 0 && slot.Offset <= 4096-width &&
					ins.Args[0].FPOffset >= slot.Offset && ins.Args[0].FPOffset < slot.Offset+width {
					return true
				}
			}
		}
	}
	return false
}

func x86IntegerResultSlot(slot FrameSlot) bool {
	return slot.Type == I8 || slot.Type == I16 || slot.Type == I32 || slot.Type == I64
}

// Logical numeric storage has the same byte ownership for integer and floating
// fields. This does not widen integer-only return, bool or pointer contracts.
func x86OrdinaryNumericAddressSlot(slot FrameSlot) bool {
	return x86IntegerResultSlot(slot) || slot.Type == "float" || slot.Type == "double"
}

// Only the private lowering observer has logical result backing. Its existing
// typed layout validation and bounded must-state proof remain mandatory. No
// native incoming frame, parameter address, padding, CALL, raw entry, caller
// extent, or canonical bool role is inferred here.
func x86OrdinaryResultAddressRole(fn Func, sig FuncSig, arch string) bool {
	if !x86OrdinaryResultAddressNeedsProof(fn, sig, arch) || fn.FrameSize != 0 ||
		len(fn.X86RawText) != 0 || fn.x86SourceStack != nil || fn.x86FixedLocal != nil ||
		fn.x86RawReplay != nil || len(fn.x86ContinuationAddresses) != 0 || len(fn.x86IndirectLabels) != 0 {
		return false
	}
	for _, slot := range sig.Frame.Results {
		if !x86OrdinaryNumericAddressSlot(slot) {
			return false
		}
	}
	for _, ins := range fn.Instrs {
		if ins.Op == "CALL" || isX86RawDirective(ins) || ins.x86Encoded || ins.x86SourceRaw != nil ||
			ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
			return false
		}
	}
	return true
}

// Ordinary scalar ABI0 parameters have private logical copies, including the
// physical byte of a bool input. Mode32's classic frame is contiguous; AMD64
// instead retains each actual field's separate allocation and bounds. Neither
// role grants canonical bool results, native incoming frames or caller memory.
func x86OrdinaryParameterAddressRole(fn Func, sig FuncSig, arch string) bool {
	if arch != "386" && arch != "amd64" || !x86OrdinaryParameterAddressNeedsProof(fn, sig, arch) ||
		fn.FrameSize != 0 || len(fn.X86RawText) != 0 || fn.x86SourceStack != nil ||
		fn.x86FixedLocal != nil || fn.x86RawReplay != nil || fn.x86DirectTailRoot != nil ||
		fn.x86ContinuationFlow != nil || fn.x86BoolCalls != nil ||
		len(fn.x86ContinuationAddresses) != 0 || len(fn.x86IndirectLabels) != 0 {
		return false
	}
	for _, slot := range sig.Frame.Params {
		if slot.Type != I1 && !x86OrdinaryNumericAddressSlot(slot) {
			return false
		}
	}
	for _, slot := range sig.Frame.Results {
		if !x86OrdinaryNumericAddressSlot(slot) {
			return false
		}
	}
	for _, ins := range fn.Instrs {
		if ins.Op == "CALL" || isX86RawDirective(ins) || ins.x86Encoded || ins.x86SourceRaw != nil ||
			ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
			return false
		}
	}
	return true
}

// Cost routing only: every parameter LEA still needs the complete proof,
// including narrowed addresses, Void functions and eventual unused values.
func x86OrdinaryParameterAddressNeedsProof(fn Func, sig FuncSig, arch string) bool {
	if arch != "386" && arch != "amd64" {
		return false
	}
	for _, ins := range fn.Instrs {
		if (ins.Op == "LEAW" || ins.Op == "LEAL" || ins.Op == "LEAQ") &&
			len(ins.Args) == 2 && ins.Args[0].Kind == OpFP {
			for _, slot := range sig.Frame.Params {
				width := x86FrameScalarBytes(slot.Type, arch)
				if width > 0 && slot.Offset >= 0 && slot.Offset <= 4096-width &&
					ins.Args[0].FPOffset >= slot.Offset && ins.Args[0].FPOffset < slot.Offset+width {
					return true
				}
			}
		}
	}
	return false
}
