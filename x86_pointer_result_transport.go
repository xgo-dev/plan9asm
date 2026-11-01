package plan9asm

// Preserve the existing opaque-pointer return consumer for a complete,
// straight-line native-word address transport. This is not numerical result
// initialization: code/data addresses never become NUM, caller provenance or
// permission to access their pointees. Any other effect retains its independent
// whole-source obligation. In particular, a partial or missing result cannot
// escape the numerical-family routing check merely because its type is ptr.
func x86OpaqueAddressPointerResultRole(fn Func, sig FuncSig, arch string) bool {
	if sig.Ret != Ptr || len(sig.Args) != 0 || len(sig.Frame.Params) != 0 ||
		len(sig.Frame.Results) != 1 || !x86DirectGPFPResultSourceRole(fn, sig, arch) {
		return false
	}
	word := x86ResultPointerWord(arch)
	result := sig.Frame.Results[0]
	if result.Type != Ptr || result.Offset != 0 || result.Index != 0 || result.Field != -1 ||
		len(result.Fields) != 0 || fn.ArgSize != word || len(fn.Instrs) < 3 || len(fn.Instrs) > 4096 ||
		fn.Instrs[0].Op != OpTEXT {
		return false
	}
	move := Op("MOVQ")
	if arch == "386" {
		move = "MOVL"
	}
	var defined uint16
	written := false
	for index, original := range fn.Instrs[1:] {
		if !x86ResultNamedPredicateInstruction(original) {
			return false
		}
		if original.Op == OpRET {
			return written && len(original.Args) == 0 && index == len(fn.Instrs)-2
		}
		if original.Op == "NOP" && len(original.Args) == 0 {
			continue
		}
		ins := x86SourceMoveInstruction(original, arch)
		if ins.Op != move || len(ins.Args) != 2 {
			return false
		}
		first, last := ins.Args[0], ins.Args[1]
		if _, immediate, destination, known := x86StaticAddressValueMove(original, arch); known && immediate {
			defined |= 1 << uint(destination)
			continue // The paired ordinary MOV still emits the actual symbol relocation.
		}
		value := first.Kind == OpImm && first.Imm == 0 && first.ImmRaw == "" && !first.ImmIsFloat
		if first.Kind == OpReg {
			source, _, valid := x86ResultGP(first.Reg, word, arch)
			value = valid && defined&(1<<uint(source)) != 0
		}
		if !value {
			return false
		}
		switch last.Kind {
		case OpReg:
			destination, _, valid := x86ResultGP(last.Reg, word, arch)
			if !valid {
				return false
			}
			defined |= 1 << uint(destination)
		case OpFP:
			if last.FPOffset != result.Offset {
				return false
			}
			written = true
		default:
			return false
		}
	}
	return false
}
