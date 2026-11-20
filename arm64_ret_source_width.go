package plan9asm

import "strings"

// Source RET is expanded by Go obj7 before encoding. Only raw AWORD RET is
// always one instruction. The source leaf/frame contract must be inspected
// before any raw AWORD BL has been rewritten into a semantic BL instruction.
func arm64SourceReturnWidth(fn Func, ins Instr) (int64, bool) {
	if ins.Op != OpRET || len(ins.Args) > 1 {
		return 0, false
	}
	if len(ins.Args) == 1 {
		target := ins.Args[0]
		switch target.Kind {
		case OpReg:
			if !isARM64GeneralOrZeroReg(target.Reg) && target.Reg != SP && target.Reg != "RSP" {
				return 0, false
			}
		case OpMem:
			if !isARM64GeneralOrZeroReg(target.Mem.Base) && target.Mem.Base != SP && target.Mem.Base != "RSP" {
				return 0, false
			}
		case OpSym:
			if !strings.HasSuffix(target.Sym, "(SB)") {
				return 0, false
			}
		default:
			return 0, false
		}
	}
	// Go's autosize is int32. Stay within its non-overflowing, aligned range;
	// invalid declarations cannot establish a raw instruction boundary.
	if fn.FrameSize < 0 && fn.FrameSize != -8 || fn.FrameSize > (1<<31)-25 || fn.FrameSize&7 != 0 {
		return 0, false
	}
	if !arm64SourceFrameFlagsKnown(fn) {
		return 0, false
	}
	frame := arm64SourceGoFrame(fn)
	if !frame.present {
		return 4, fn.FrameSize <= 0
	}
	autosize := arm64SourceFrameAutosize(fn.FrameSize)
	if autosize <= 0 || autosize >= 1<<12 {
		// Large source epilogues differ across supported Go encoders. A
		// parsed Func has no sealed original SDK identity, so neither a host
		// version nor a current obj7 expansion can establish their width.
		return 0, false
	}
	// In the common Go 1.20–1.27 small-frame domain, both the leaf and
	// nonleaf expansions are two one-word frame operations plus a one-word
	// branch. Their order and return-register semantics are not certified by
	// this width proof. It grants only a raw source-layout boundary.
	return 12, true
}

// Call only after checking the source's framed, aligned int32 Go contract.
// obj7 reserves the LR and pads the top of this native frame for the old BP.
func arm64SourceFrameAutosize(frameSize int64) int64 {
	autosize := frameSize + 8
	if autosize&15 == 8 {
		autosize += 8
	} else {
		autosize += 16
	}
	return autosize
}

func arm64SourceFrameFlagsKnown(fn Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op != OpTEXT {
			continue
		}
		_, rest := splitOpcode(ins.Raw)
		parts := strings.Split(rest, ",")
		if len(parts) == 2 {
			return true
		}
		if len(parts) != 3 {
			return false
		}
		if _, resolved := parseImmExpr(strings.TrimSpace(parts[1])); resolved {
			return true
		}
		// Canonical textflag.h names have known NOFRAME membership. An
		// unresolved user flag may contain NOFRAME and cannot fix the width.
		for _, flag := range strings.Split(parts[1], "|") {
			switch strings.TrimSpace(flag) {
			case "NOPROF", "DUPOK", "NOSPLIT", "RODATA", "NOPTR", "WRAPPER", "NEEDCTXT", "TLSBSS", "NOFRAME", "REFLECTMETHOD", "TOPFRAME", "ABIWRAPPER":
			default:
				return false
			}
		}
		return true
	}
	return false
}
