package plan9asm

import (
	"reflect"
	"strings"
)

type arm64TrailingResult struct {
	offset, width, limit int64
}

func (r arm64TrailingResult) covers(offset, width int64) bool {
	return r.width != 0 && offset == r.offset && width > r.width && width <= r.limit
}

// Use only syntax for the cost query. The typed declaration chooses the
// actual result slot and exact padding extent before anything is emitted.
func arm64TrailingResultCandidate(fn Func) bool {
	if fn.FrameSize != 0 || fn.ArgSize <= 0 || fn.ArgSize > 65536 || fn.ArgSize%8 == 0 ||
		!strings.HasPrefix(fn.Sym, "·") || strings.ContainsAny(strings.TrimPrefix(fn.Sym, "·"), "·<>") {
		return false
	}
	limit := goAlignOff(fn.ArgSize, 8)
	for _, ins := range fn.Instrs {
		bits, _ := arm64ScalarMemoryBits(arm64ControlOp(ins))
		if bits <= 8 || len(ins.Args) != 2 || ins.Args[1].Kind != OpFP {
			continue
		}
		offset, width := ins.Args[1].FPOffset, int64(bits/8)
		if offset >= 0 && offset < fn.ArgSize && width > fn.ArgSize-offset && width <= limit-offset {
			return true
		}
	}
	return false
}

// Go rounds the ABI0 stack argument/result area to RegSize (see
// cmd/compile/internal/abi ABIAnalyze). A scalar move may write the final
// integer result and its trailing alignment bytes in one instruction.
// Those bytes have no LLVM frame slot and cannot be observed by closed source
// without a physical stack reference or an escaped virtual frame address.
func arm64TrailingResultForSource(original, normalized Func, sig FuncSig) arm64TrailingResult {
	decl := sig.arm64ABI0Declaration
	results := sig.Frame.Results
	if decl == nil || decl.function == nil || decl.trailingResult == nil ||
		len(results) == 0 || len(sig.ArgRegs) != 0 ||
		sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.ARMEntry != nil {
		return arm64TrailingResult{}
	}
	last := results[len(results)-1]
	width := frameTypeSize(last.Type, 8)
	end := last.Offset + width
	limit := goAlignOff(end, 8) - last.Offset
	if last.Offset < 0 || width >= limit || end != decl.argsSize || end != original.ArgSize || original.FrameSize != 0 ||
		original.Sym != "·"+decl.function.Name() || original.arm64PrivateRegisterEntry ||
		original.arm64ABI0TailSource != nil || len(original.Instrs) == 0 || original.Instrs[0].Op != OpTEXT {
		return arm64TrailingResult{}
	}
	candidate := arm64TrailingResult{offset: last.Offset, width: width, limit: limit}
	for _, ins := range normalized.Instrs {
		bits, _ := arm64ScalarMemoryBits(arm64ControlOp(ins))
		if bits == 0 || len(ins.Args) != 2 || ins.Args[1].Kind != OpFP ||
			!candidate.covers(ins.Args[1].FPOffset, int64(bits/8)) {
			continue
		}
		source := decl.trailingResult
		if source.matches(sig) && reflect.DeepEqual(source.root, arm64PrivateTailSnapshot(original)) &&
			arm64TrailingResultTextMatches(original) &&
			arm64TrailingResultUnobserved(original) && arm64TrailingResultUnobserved(normalized) {
			return candidate
		}
		break
	}
	return arm64TrailingResult{}
}

func arm64TrailingResultTextMatches(fn Func) bool {
	_, text := splitOpcode(fn.Instrs[0].Raw)
	fields := strings.Split(text, ",")
	if len(fields) != 2 && len(fields) != 3 {
		return false
	}
	name, offset, valid := parseSBRef(strings.TrimSpace(fields[0]))
	frame, err := parseTEXTFrameSpec(fields)
	if !valid || name != fn.Sym || offset != 0 || err != nil ||
		frame.frameSize != fn.FrameSize || !frame.argsSpecified || frame.argSize != fn.ArgSize {
		return false
	}
	if len(fields) == 3 {
		_, err := nativeFlags(fields[1], "NOSPLIT", "NOFRAME", "NOPROF", "DUPOK")
		return err == nil
	}
	return true
}

func arm64TrailingResultUnobserved(fn Func) bool {
	if fn.FrameSize != 0 || arm64SourceGoFrame(fn).present || len(fn.Instrs) > 32768 {
		return false
	}
	for _, ins := range fn.Instrs {
		op := arm64ControlOp(ins)
		if arm64IsSYSOpcode(op) {
			return false
		}
		switch op {
		case OpWORD, "DWORD", "BYTE", arm64RawDataOp, "ADR", "ADRP",
			"CALL", "BL", "BLR", "BR", "DUFFCOPY", "DUFFZERO", "SVC", "HVC", "SMC",
			"MRS", "MSR":
			return false
		case OpRET:
			if len(ins.Args) != 0 {
				return false
			}
		case "B", "JMP":
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpIdent && ins.Args[0].Kind != OpLabel {
				return false
			}
		}
		for _, arg := range ins.Args {
			if arm64TrailingResultAddressOperand(arg) {
				return false
			}
		}
	}
	return true
}

func arm64TrailingResultAddressOperand(arg Operand) bool {
	switch arg.Kind {
	case OpFPAddr:
		return true
	case OpReg, OpRegShift, OpRegExtend:
		return arm64TrailingResultStackReg(arg.Reg) || arm64TrailingResultStackReg(arg.ShiftReg)
	case OpRegList:
		for _, reg := range arg.RegList {
			if arm64TrailingResultStackReg(reg) {
				return true
			}
		}
	case OpMem:
		return arg.Mem.Base == ZR || arm64TrailingResultStackReg(arg.Mem.Base) || arm64TrailingResultStackReg(arg.Mem.Index)
	case OpSym:
		symbol := strings.TrimSpace(arg.Sym)
		if strings.HasPrefix(symbol, "$") {
			if strings.Contains(symbol, "(FP)") {
				return true
			}
			if memory, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(symbol, "$"))); ok {
				return arm64TrailingResultAddressOperand(Operand{Kind: OpMem, Mem: memory})
			}
		}
	}
	return false
}

func arm64TrailingResultStackReg(reg Reg) bool {
	return arm64StackReg(reg) || reg == "R18" || reg == "R28" || reg == "R29" || reg == "R30" || reg == "G" || reg == "g"
}
