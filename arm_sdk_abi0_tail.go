package plan9asm

import (
	"go/types"
	"strings"
)

// The global helper has two entry contracts. The native object retains the
// original TEXT. Each Go caller receives a private CFG with its own FP slots.
func prepareSDKARMABI0Tails(pkg GoPackage, file *File, helpers map[string]bool, resolve func(string) string) (*File, map[string]FuncSig, error) {
	bodies := make(map[string]Func, len(helpers))
	for _, fn := range file.Funcs {
		if name, marked := strings.CutSuffix(fn.Sym, "<>"); marked && helpers[name] {
			if _, duplicate := bodies[fn.Sym]; duplicate {
				return nil, nil, sdkASMDataContext("ARM ABI0 helper %q is ambiguous", fn.Sym)
			}
			bodies[fn.Sym] = fn
		}
	}
	result := *file
	result.Funcs = make([]Func, 0, len(file.Funcs)-len(bodies))
	sigs := make(map[string]FuncSig)
	remaining := 64 << 10
	for _, fn := range file.Funcs {
		if _, helper := bodies[fn.Sym]; helper {
			continue
		}
		expanded, err := expandSDKARMABI0Tail(fn, bodies, &remaining)
		if err != nil {
			return nil, nil, err
		}
		if expanded.armSDKABI0Tail {
			name := resolve(fn.Sym)
			sig, err := sdkARMABI0TailSignature(pkg, fn, name)
			if err != nil {
				return nil, nil, err
			}
			if _, duplicate := sigs[name]; duplicate {
				return nil, nil, sdkASMDataContext("ARM ABI0 caller %q resolves ambiguously", fn.Sym)
			}
			if err := validateSDKARMABI0Instructions(expanded, sig); err != nil {
				return nil, nil, err
			}
			sigs[name] = sig
		}
		result.Funcs = append(result.Funcs, expanded)
	}
	if len(sigs) == 0 {
		return nil, nil, sdkASMDataContext("ARM SDK tail source has no original Go ABI0 callers")
	}
	return &result, sigs, nil
}

func expandSDKARMABI0Tail(fn Func, bodies map[string]Func, remaining *int) (Func, error) {
	expanded := fn
	var entries map[string]string
	var names *assemblyBlockNames
	for i, ins := range fn.Instrs {
		if !sdkABI0TailEdge(ArchARM, ins) {
			continue
		}
		name, offset, valid := parseSBRef(ins.Args[0].Sym)
		body, helper := bodies[name]
		if !valid || offset != 0 || !helper {
			continue
		}
		if entries == nil {
			if !sdkARMABI0Terminates(fn.Instrs[len(fn.Instrs)-1]) {
				return Func{}, sdkASMDataContext("ARM ABI0 caller %q falls outside its original TEXT", fn.Sym)
			}
			expanded.Instrs = append([]Instr(nil), fn.Instrs...)
			entries, names = make(map[string]string), newAssemblyBlockNames(fn)
		}
		entry, reused := entries[name]
		if !reused {
			if len(body.Instrs) > *remaining || !abi0FramelessHelper(body) ||
				!sdkARMABI0Terminates(body.Instrs[len(body.Instrs)-1]) {
				return Func{}, sdkASMDataContext("ARM ABI0 helper %q is not a bounded, closed frameless body", body.Sym)
			}
			*remaining -= len(body.Instrs)
			entry = names.fresh("abi0_tail")
			entries[name] = entry
			expanded.Instrs = append(expanded.Instrs, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: entry}}})
			labels := make(map[string]string)
			for _, step := range body.Instrs[1:] {
				if step.Op == OpLABEL && len(step.Args) == 1 {
					label := step.Args[0].Sym
					labels[label] = names.fresh("abi0_tail_" + label)
				}
			}
			for _, step := range body.Instrs[1:] {
				if step.Op == OpLABEL && len(step.Args) == 1 {
					step.Args = []Operand{{Kind: OpLabel, Sym: labels[step.Args[0].Sym]}}
				} else if len(step.Args) == 1 && (step.Args[0].Kind == OpIdent || step.Args[0].Kind == OpLabel) {
					label, _ := armBranchTarget(step.Args[0])
					next, local := labels[label]
					if !local {
						return Func{}, sdkASMDataContext("ARM ABI0 helper %q leaves its own label scope at %q", body.Sym, step.Raw)
					}
					step.Args = []Operand{{Kind: OpIdent, Ident: next}}
				}
				expanded.Instrs = append(expanded.Instrs, step)
			}
		}
		ins.Op, ins.Args = "B", []Operand{{Kind: OpIdent, Ident: entry}}
		expanded.Instrs[i] = ins
	}
	expanded.armSDKABI0Tail = entries != nil
	return expanded, nil
}

func sdkARMABI0Terminates(ins Instr) bool {
	condition, tail, branch := armKernelBranchForm(ins)
	return ins.Op == OpRET || branch && tail && (condition == "" || condition == "AL")
}

func sdkARMABI0TailSignature(pkg GoPackage, fn Func, name string) (FuncSig, error) {
	goName, local := strings.CutPrefix(fn.Sym, "·")
	declaration, _ := pkg.Types.Scope().Lookup(goName).(*types.Func)
	if !local || declaration == nil || declaration.Pkg() != pkg.Types ||
		fn.FrameSize != 0 || fn.ArgSize <= 0 || name == "" {
		return FuncSig{}, sdkASMDataContext("ARM ABI0 caller %q needs its original ordinary Go declaration and zero frame", fn.Sym)
	}
	sig, err := DeriveGoFuncABI0Signature(name, declaration, "arm", pkg.SourceSelection.Sizes)
	if err != nil {
		return FuncSig{}, err
	}
	var end int64
	for _, group := range [][]FrameSlot{sig.Frame.Params, sig.Frame.Results} {
		for _, slot := range group {
			width := frameTypeSize(slot.Type, 4)
			if slot.Type != I1 && slot.Type != I8 && slot.Type != I16 && slot.Type != I32 && slot.Type != Ptr {
				return FuncSig{}, sdkASMDataContext("ARM ABI0 caller %q has no scalar frame transport for %s", fn.Sym, slot.Type)
			}
			if slotEnd := slot.Offset + width; slotEnd > end {
				end = slotEnd
			}
		}
	}
	if end != fn.ArgSize {
		return FuncSig{}, sdkASMDataContext("ARM ABI0 caller %q declares %d frame bytes, Go layout has %d", fn.Sym, fn.ArgSize, end)
	}
	return sig, nil
}

func validateSDKARMABI0Instructions(fn Func, sig FuncSig) error {
	names := newAssemblyBlockNames(fn)
	for _, ins := range fn.Instrs {
		if !sdkARMABI0Instruction(ins, sig, names.used) {
			return sdkASMDataContext("ARM ABI0 caller %q has an unbound frame, operand or control effect at %q", fn.Sym, ins.Raw)
		}
	}
	return nil
}

func sdkARMABI0Instruction(ins Instr, sig FuncSig, labels map[string]bool) bool {
	switch ins.Op {
	case OpTEXT, OpLABEL:
		return true
	case OpRET, "NOP":
		return len(ins.Args) == 0
	}
	if _, tail, branch := armKernelBranchForm(ins); branch {
		if !tail || len(ins.Args) != 1 || ins.Args[0].Kind == OpSym {
			return false
		}
		target, local := armBranchTarget(ins.Args[0])
		return local && labels[target]
	}
	op, _, _, _ := armDecodeOp(string(ins.Op))
	memory, move := armIntegerMemorySpecs[op]
	_, multiply := armBasicMultiplySpecs[op]
	if !move && !multiply {
		switch op {
		case "ADD", "ADC", "SUB", "SBC", "RSB", "RSC", "AND", "ORR", "EOR", "BIC", "MVN",
			"SLL", "SRL", "SRA", "CMP", "CMN", "TST", "TEQ":
		default:
			return false
		}
	}
	for index, operand := range ins.Args {
		if operand.Kind == OpFP {
			if !move || len(ins.Args) != 2 || !sdkARMABI0FrameSlot(sig, operand.FPOffset, index, int64(memory.bits/8)) {
				return false
			}
			continue
		}
		if !sdkARMABI0Operand(operand) {
			return false
		}
	}
	return true
}

func sdkARMABI0Operand(operand Operand) bool {
	switch operand.Kind {
	case OpImm:
		return operand.ImmRaw == ""
	case OpReg:
		return sdkARMABI0GP(operand.Reg)
	case OpRegShift:
		return sdkARMABI0GP(operand.Reg) && (operand.ShiftReg == "" || sdkARMABI0GP(operand.ShiftReg))
	case OpRegList:
		return len(operand.RegList) == 2 && sdkARMABI0GP(operand.RegList[0]) && sdkARMABI0GP(operand.RegList[1])
	case OpMem:
		m := operand.Mem
		return sdkARMABI0GP(m.Base) && (m.Index == "" || sdkARMABI0GP(m.Index)) &&
			m.OffRaw == "" && m.Sym == "" && m.Segment == ""
	default:
		return false
	}
}

func sdkARMABI0GP(reg Reg) bool {
	switch reg {
	case "R10", "R11", "R13", "R14", "R15", SP, PC:
		// R11 is Go asm5's implicit REGTMP for materializing large operands.
		return false
	default:
		return isARMGeneralReg(reg)
	}
}

func sdkARMABI0FrameSlot(sig FuncSig, offset int64, operand int, width int64) bool {
	slots := sig.Frame.Params
	if operand == 1 {
		slots = sig.Frame.Results
	}
	for _, slot := range slots {
		if slot.Offset == offset && frameTypeSize(slot.Type, 4) == width {
			return true
		}
	}
	return false
}
