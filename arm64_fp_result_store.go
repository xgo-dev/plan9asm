package plan9asm

import "strings"

type arm64FPResultStoreExtent struct {
	start, end, alignedEnd int64
}

// A scalar store into the end of the ABI0 result area may cover reserved
// stack-alignment bytes. Only the bytes belonging to declared results need
// materialization in the typed LLVM frame.
func (extent arm64FPResultStoreExtent) width(offset, size int64) int64 {
	if offset >= extent.start && offset < extent.end &&
		size > extent.end-offset && size <= extent.alignedEnd-offset {
		return extent.end - offset
	}
	return size
}

func arm64ProveFPResultStoreExtent(original, normalized Func, sig FuncSig) arm64FPResultStoreExtent {
	decl := sig.arm64ABI0Declaration
	if decl == nil || len(sig.Frame.Results) == 0 || decl.argsSize&7 == 0 ||
		len(sig.ArgRegs) != 0 || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.ARMEntry != nil {
		return arm64FPResultStoreExtent{}
	}
	extent := arm64FPResultStoreExtent{
		start: sig.Frame.Results[0].Offset, end: decl.argsSize, alignedEnd: goAlignOff(decl.argsSize, 8),
	}
	for _, ins := range normalized.Instrs {
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpFP {
			continue
		}
		form, handled, err := parseARM64ScalarMemoryForm(arm64ControlOp(ins), ins)
		if !handled || err != nil || !form.store {
			continue
		}
		offset, size := form.memory.FPOffset, int64(form.bits/8)
		if extent.width(offset, size) == size {
			continue
		}
		if decl.matches(sig) && arm64ResultStorePrivate(original, decl, extent) &&
			arm64ResultStorePrivate(normalized, decl, extent) {
			return extent
		}
		break
	}
	return arm64FPResultStoreExtent{}
}

func arm64ResultStorePrivate(fn Func, decl *arm64ABI0Declaration, extent arm64FPResultStoreExtent) bool {
	name := decl.function.Name()
	symbol := strings.TrimSuffix(fn.Sym, "<ABI0>")
	if symbol != name && !strings.HasSuffix(symbol, "·"+name) {
		return false
	}
	if fn.arm64PrivateRegisterEntry || fn.arm64PrivateCallSource != nil || fn.arm64ABI0TailSource != nil ||
		fn.arm64PrivateTailSource != nil || fn.ArgSize != extent.end ||
		len(fn.Instrs) == 0 || fn.Instrs[0].Op != OpTEXT || !arm64SourceFrameFlagsKnown(fn) {
		return false
	}
	_, text := splitOpcode(fn.Instrs[0].Raw)
	fields := splitTopLevelCSV(text)
	spec, err := parseTEXTFrameSpec(fields)
	if err != nil || !spec.argsSpecified || spec.argSize != extent.end || spec.frameSize != fn.FrameSize {
		return false
	}

	for _, ins := range fn.Instrs[1:] {
		op := arm64ControlOp(ins)
		switch op {
		case OpTEXT, OpWORD, OpBYTE, "DWORD", "LONG", "QUAD", arm64RawDataOp, "CALL", "BL", "BLR", "BR",
			"DUFFCOPY", "DUFFZERO", "SVC", "HVC", "SMC", "BRK", "HLT", "DCPS1", "DCPS2", "DCPS3", "ERET", "DRPS", "MRS", "MSR":
			return false
		case OpRET:
			if len(ins.Args) != 0 {
				return false
			}
		}
		if op == "B" || op == "JMP" || arm64IsConditionalBranch(op) {
			if len(ins.Args) == 0 {
				return false
			}
			target := ins.Args[len(ins.Args)-1]
			if target.Kind != OpIdent && target.Kind != OpLabel && !(target.Kind == OpMem && target.Mem.Base == PC) {
				return false
			}
		}
		for _, arg := range ins.Args {
			switch arg.Kind {
			case OpFP:
				form, handled, err := parseARM64ScalarMemoryForm(op, ins)
				if !handled || err != nil || form.memory.Kind != OpFP ||
					!form.store && (arg.FPOffset < 0 || arg.FPOffset > extent.end-int64(form.bits/8)) {
					return false
				}
			case OpFPAddr:
				return false
			case OpSym:
				if _, _, ok := parseSBRef(strings.TrimPrefix(arg.Sym, "$")); !ok {
					return false
				}
			}
			// Go spells some base-31 atomics with (ZR), which encodes SP.
			if arg.Kind == OpMem && arg.Mem.Base == ZR {
				return false
			}
			for _, reg := range [...]Reg{arg.Reg, arg.ShiftReg, arg.Mem.Base, arg.Mem.Index} {
				if arm64ResultStoreFrameReg(reg) {
					return false
				}
			}
			for _, reg := range arg.RegList {
				if arm64ResultStoreFrameReg(reg) {
					return false
				}
			}
		}
	}
	return true
}

func arm64ResultStoreFrameReg(reg Reg) bool {
	switch reg {
	case SP, "RSP", "R31", "R29", "R30", "FP", "LR", "R28", "g", "R26":
		return true
	}
	return false
}
