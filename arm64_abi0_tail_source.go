package plan9asm

import (
	"reflect"
	"strings"
)

type arm64ABI0TailSource struct {
	declaration *arm64ABI0TailDeclaration
	original    Func
	helpers     []Func
	prepared    Func
}

func arm64ABI0TailRoot(fn Func, sig FuncSig) error {
	d := sig.arm64ABI0TailDeclaration
	if !d.matches(sig) || !reflect.DeepEqual(arm64PrivateTailSnapshot(fn), d.root) ||
		fn.arm64PrivateRegisterEntry || fn.arm64PrivateTailSource != nil || fn.arm64ABI0TailSource != nil ||
		fn.FrameSize != 0 || arm64SourceGoFrame(fn).present || !arm64SourceFrameFlagsKnown(fn) ||
		len(fn.Instrs) < 2 || fn.Instrs[0].Op != OpTEXT || strings.Contains(fn.Sym, "<ABI") ||
		len(sig.ArgRegs) != 0 || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.ARMEntry != nil {
		return arm64GoABIContext("ABI0 private tail lacks its declaration-bound zero physical frame")
	}
	_, rest := splitOpcode(fn.Instrs[0].Raw)
	parts := strings.Split(rest, ",")
	if len(parts) < 2 || len(parts) > 3 || strings.LastIndex(strings.TrimSpace(parts[len(parts)-1]), "-") <= 1 {
		return arm64GoABIContext("ABI0 private tail needs complete original TEXT/args")
	}
	name, off, ok := parseSBRef(strings.TrimSpace(parts[0]))
	frame, args, err := parseTEXTFrame(parts)
	if !ok || off != 0 || name != fn.Sym || err != nil || frame != 0 || args != fn.ArgSize || args != d.declaration.argsSize {
		return arm64GoABIContext("ABI0 private tail changed its actual TEXT/layout identity")
	}
	for _, ins := range fn.Instrs[1:] {
		if ins.Op == "CALL" || ins.Op == "BL" || ins.Op == "BLR" || ins.Op == OpTEXT {
			return arm64GoABIContext("ABI0 private tail is not a complete call-free source")
		}
		for _, arg := range ins.Args {
			if arg.Kind == OpFP || arg.Kind == OpFPAddr {
				continue // Exact parameter/result roles are checked by the CFG proof.
			}
			registers := []Reg{arg.Reg, arg.ShiftReg, arg.Mem.Base, arg.Mem.Index}
			if arg.Kind == OpSym && strings.HasPrefix(arg.Sym, "$") {
				if memory, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$"))); ok {
					registers = append(registers, memory.Base, memory.Index)
				}
			}
			for _, reg := range registers {
				if reg != "" && !arm64PrivateTailDataRegister(reg) && reg != ZR {
					return arm64GoABIContext("ABI0 private tail touches stack/hidden/reserved state")
				}
			}
			for _, reg := range arg.RegList {
				if !arm64PrivateTailDataRegister(reg) && reg != ZR {
					return arm64GoABIContext("ABI0 private tail touches a hidden/reserved register list")
				}
			}
		}
	}
	return nil
}

func validateARM64ABI0TailSource(fn Func, sig FuncSig) error {
	p := fn.arm64ABI0TailSource
	if p == nil {
		return nil
	}
	if p.declaration != sig.arm64ABI0TailDeclaration {
		return arm64GoABIContext("ABI0 continuation lost its declaration object")
	}
	if !p.declaration.matches(sig) {
		return arm64GoABIContext("ABI0 continuation changed its original selected declaration/source")
	}
	if !reflect.DeepEqual(arm64PrivateTailSnapshot(fn), p.prepared) {
		return arm64GoABIContext("ABI0 continuation changed its prepared source")
	}
	if err := arm64ABI0TailRoot(p.original, sig); err != nil {
		return err
	}
	for _, helper := range p.helpers {
		if err := arm64PrivateTailBody(helper); err != nil {
			return err
		}
	}
	return arm64ABI0TailResultProof(fn, sig)
}

// PrepareGoARM64ABI0TailContinuations is declaration-backed preparation before
// KeepFunc/chunks. File-only preparation supplies no ABI0 permissions. Shared
// CALL/ABIInternal/ABI0 additions consume the same cumulative file allowance.
func PrepareGoARM64ABI0TailContinuations(file *File, sigs map[string]FuncSig, resolve func(string) string) (*File, error) {
	if file == nil {
		return nil, arm64GoABIContext("ABI0 continuation has no original assembly file")
	}
	prepared, err := coalesceARM64PrivateRegisterHelpers(file)
	if err != nil || prepared.Arch != ArchARM64 {
		return prepared, err
	}
	remaining := arm64PrivateRegisterExpansionBudget
	for _, fn := range prepared.Funcs {
		if fn.arm64PrivateSourceAdded < 0 || fn.arm64PrivateSourceAdded > remaining {
			return nil, arm64GoABIContext("ABI0 continuation exceeds the shared cumulative expansion budget")
		}
		remaining -= fn.arm64PrivateSourceAdded
	}
	return coalesceARM64PrivateTailHelpersWithABI0(prepared, &remaining, sigs, resolve)
}
