package main

import (
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

// A shared ABI0 body can receive its arguments in physical registers while
// its wrappers pass a pointer to their own result slots. In that case the
// helper returns void; each wrapper reads its FP results after the call.
// Require both caller-side address setup and a helper-side memory write so
// ordinary register-return tail helpers retain their existing inference.
func inferSharedABI0ResultPointerHelper(
	file *plan9asm.File,
	resolve func(string) string,
	target string,
	callers []plan9asm.FuncSig,
	callerFuncs []plan9asm.Func,
	goarch string,
) (plan9asm.FuncSig, bool) {
	if (goarch != "amd64" && goarch != "386") || len(callers) < 2 || len(callers) != len(callerFuncs) {
		return plan9asm.FuncSig{}, false
	}

	var pointerReg plan9asm.Reg
	for i, caller := range callers {
		if len(caller.Frame.Results) < 2 || !strings.HasPrefix(string(caller.Ret), "{") {
			return plan9asm.FuncSig{}, false
		}
		reg, ok := callerABI0ResultPointerRegister(
			callerFuncs[i], caller.Frame.Results[0], target, resolve,
		)
		if !ok || pointerReg != "" && pointerReg != reg {
			return plan9asm.FuncSig{}, false
		}
		pointerReg = reg
	}

	var body *plan9asm.Func
	for i := range file.Funcs {
		if resolve(stripABISuffix(file.Funcs[i].Sym)) == target {
			body = &file.Funcs[i]
			break
		}
	}
	if body == nil || !helperWritesThroughRegister(*body, pointerReg) {
		return plan9asm.FuncSig{}, false
	}

	registers := x86HelperRegisterOperands(*body, pointerReg, goarch)
	word := plan9asm.I64
	if goarch == "386" {
		word = plan9asm.I32
	}
	args := make([]plan9asm.LLVMType, len(registers))
	for i := range args {
		args[i] = word
	}
	return plan9asm.FuncSig{
		Name:    target,
		Args:    args,
		ArgRegs: registers,
		Ret:     plan9asm.Void,
	}, true
}

func callerABI0ResultPointerRegister(
	fn plan9asm.Func,
	firstResult plan9asm.FrameSlot,
	target string,
	resolve func(string) string,
) (plan9asm.Reg, bool) {
	for i := 1; i < len(fn.Instrs); i++ {
		tail := fn.Instrs[i]
		if strings.ToUpper(string(tail.Op)) != "JMP" || len(tail.Args) != 1 || tail.Args[0].Kind != plan9asm.OpSym {
			continue
		}
		sym := strings.TrimSpace(tail.Args[0].Sym)
		if !strings.HasSuffix(sym, "(SB)") || resolve(stripABISuffix(strings.TrimSuffix(sym, "(SB)"))) != target {
			continue
		}
		address := fn.Instrs[i-1]
		if address.Op != "LEAQ" && address.Op != "LEAL" {
			continue
		}
		if len(address.Args) != 2 ||
			(address.Args[0].Kind != plan9asm.OpFP && address.Args[0].Kind != plan9asm.OpFPAddr) ||
			address.Args[1].Kind != plan9asm.OpReg {
			continue
		}
		if address.Args[0].FPOffset != firstResult.Offset || firstResult.Name != "" && address.Args[0].FPName != firstResult.Name {
			continue
		}
		return address.Args[1].Reg, true
	}
	return "", false
}

func helperWritesThroughRegister(fn plan9asm.Func, reg plan9asm.Reg) bool {
	for _, ins := range fn.Instrs {
		if !strings.HasPrefix(strings.ToUpper(string(ins.Op)), "MOV") || len(ins.Args) < 2 {
			continue
		}
		destination := ins.Args[len(ins.Args)-1]
		if destination.Kind == plan9asm.OpMem && destination.Mem.Base == reg {
			return true
		}
	}
	return false
}

func x86HelperRegisterOperands(fn plan9asm.Func, pointerReg plan9asm.Reg, goarch string) []plan9asm.Reg {
	used := map[plan9asm.Reg]bool{pointerReg: true}
	add := func(reg plan9asm.Reg) {
		if x86HelperGeneralRegister(reg, goarch) {
			used[reg] = true
		}
	}
	for _, ins := range fn.Instrs {
		for _, operand := range ins.Args {
			switch operand.Kind {
			case plan9asm.OpReg, plan9asm.OpRegExtend, plan9asm.OpRegShift:
				add(operand.Reg)
			case plan9asm.OpMem:
				add(operand.Mem.Base)
				add(operand.Mem.Index)
			}
		}
	}
	registers := make([]plan9asm.Reg, 0, len(used))
	for reg := range used {
		registers = append(registers, reg)
	}
	sort.Slice(registers, func(i, j int) bool { return registers[i] < registers[j] })
	return registers
}

func x86HelperGeneralRegister(reg plan9asm.Reg, goarch string) bool {
	switch reg {
	case plan9asm.AX, plan9asm.BX, plan9asm.CX, plan9asm.DX,
		plan9asm.SI, plan9asm.DI, plan9asm.BP:
		return true
	case "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15":
		return goarch == "amd64"
	default:
		return false
	}
}
