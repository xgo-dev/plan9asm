package asmsig

import (
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

// ARM64BorrowedTailFrame recognizes a declared, argument-free assembly helper
// that reads arguments from the stack frame of its tail-jumping callers. Go's
// assembler permits this pattern even though the helper's Go declaration has
// no arguments. The LLVM function needs explicit arguments because an LLVM
// call does not preserve the caller's physical frame layout.
//
// Require each local entry transfer to place every consumed word in the
// corresponding outgoing ABI0 slot immediately before the branch. Anything
// more involved needs a control-flow-aware frame model and stays unsupported.
func ARM64BorrowedTailFrame(
	file *plan9asm.File,
	target plan9asm.Func,
	declared, inferred plan9asm.FuncSig,
	resolve func(string) string,
) (plan9asm.FuncSig, bool) {
	if len(declared.Args) != 0 || declared.Ret != plan9asm.Void ||
		len(declared.Frame.Params) != 0 || len(declared.Frame.Results) != 0 ||
		len(inferred.Frame.Params) == 0 || len(inferred.Frame.Results) != 0 ||
		len(inferred.Args) != len(inferred.Frame.Params) {
		return declared, false
	}
	for i, slot := range inferred.Frame.Params {
		if slot.Offset != int64(i*8) || slot.Type != plan9asm.I64 {
			return declared, false
		}
	}

	targetName := resolve(target.Sym)
	entries := 0
	for _, caller := range file.Funcs {
		if resolve(caller.Sym) == targetName {
			continue
		}
		for i, ins := range caller.Instrs {
			if len(ins.Args) != 1 || ins.Args[0].Kind != plan9asm.OpSym {
				continue
			}
			sym, ok := directEntrySymbol(ins.Args[0].Sym)
			if !ok || resolve(sym) != targetName {
				continue
			}
			if strings.ToUpper(string(ins.Op)) != "B" ||
				!hasImmediateARM64ABI0Stores(caller.Instrs, i, inferred.Frame.Params) {
				return declared, false
			}
			entries++
		}
	}
	if entries == 0 {
		return declared, false
	}

	declared.Args = inferred.Args
	declared.Frame.Params = inferred.Frame.Params
	return declared, true
}

func hasImmediateARM64ABI0Stores(instrs []plan9asm.Instr, branch int, params []plan9asm.FrameSlot) bool {
	if branch < len(params) {
		return false
	}
	written := make(map[int64]bool, len(params))
	for _, ins := range instrs[branch-len(params) : branch] {
		if strings.ToUpper(string(ins.Op)) != "MOVD" || len(ins.Args) != 2 ||
			ins.Args[1].Kind != plan9asm.OpMem ||
			(ins.Args[1].Mem.Base != plan9asm.SP && ins.Args[1].Mem.Base != "RSP") ||
			ins.Args[1].Mem.Index != "" || ins.Args[1].Mem.Sym != "" ||
			ins.Args[1].Mem.OffRaw != "" || ins.Args[1].Mem.Segment != "" {
			return false
		}
		written[ins.Args[1].Mem.Off] = true
	}
	for _, slot := range params {
		if !written[slot.Offset+8] {
			return false
		}
	}
	return len(written) == len(params)
}

func directEntrySymbol(raw string) (string, bool) {
	sym := strings.TrimSpace(raw)
	if !strings.HasSuffix(sym, "(SB)") {
		return "", false
	}
	sym = strings.TrimSuffix(sym, "(SB)")
	if i := strings.LastIndexAny(sym, "+-"); i > 0 {
		offset, err := strconv.ParseInt(strings.TrimSpace(sym[i:]), 0, 64)
		if err == nil {
			if offset != 0 {
				return "", false
			}
			sym = strings.TrimSpace(sym[:i])
		}
	}
	return sym, sym != ""
}
