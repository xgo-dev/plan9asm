package plan9asm

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type wasmInferValue struct {
	typ  LLVMType
	regs map[Reg]struct{}
}

// InferWASMAssemblyFuncSig derives the native WebAssembly signature of a
// file-local helper from its operand-stack and virtual-register use. Official
// Go uses these helpers for bytealg routines such as memeqbody and memchr; they
// have no Go declaration, so their signature cannot come from go/types.
func InferWASMAssemblyFuncSig(fn Func, name string) (FuncSig, error) {
	type inferControl struct {
		wasmControlLabel
		base []wasmInferValue
	}
	var (
		stack       []wasmInferValue
		regTypes    = make(map[Reg]LLVMType)
		inputs      = make(map[Reg]bool)
		written     = make(map[Reg]bool)
		returnType  LLVMType
		controls    = []inferControl{{wasmControlLabel: wasmControlLabel{kind: "function"}}}
		dead        wasmDeadControls
		terminated  bool
		pendingName string
	)
	copyStack := func(values []wasmInferValue) []wasmInferValue {
		return append([]wasmInferValue(nil), values...)
	}
	push := func(v wasmInferValue) { stack = append(stack, v) }
	pop := func(op string) wasmInferValue {
		if len(stack) == 0 {
			return wasmInferValue{}
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return v
	}
	require := func(v wasmInferValue, typ LLVMType) error {
		if v.typ != "" && v.typ != typ {
			return fmt.Errorf("%s: conflicting stack types %s and %s", name, v.typ, typ)
		}
		for reg := range v.regs {
			if old := regTypes[reg]; old != "" && old != typ {
				return fmt.Errorf("%s: register %s has conflicting types %s and %s", name, reg, old, typ)
			}
			regTypes[reg] = typ
		}
		return nil
	}
	popTyped := func(op string, typ LLVMType) error {
		if len(stack) == 0 {
			return fmt.Errorf("%s: %s operand stack underflow", name, op)
		}
		value := pop(op)
		for reg := range value.regs {
			if !wasmRegisterCarries(reg, typ) {
				return fmt.Errorf("%s: %s register %s does not carry %s", name, op, reg, typ)
			}
		}
		return require(value, typ)
	}
	typedUnary := func(op string, in, out LLVMType) error {
		v := pop(op)
		if err := require(v, in); err != nil {
			return err
		}
		push(wasmInferValue{typ: out})
		return nil
	}
	typedBinary := func(op string, in, out LLVMType) error {
		rhs := pop(op)
		lhs := pop(op)
		if err := require(lhs, in); err != nil {
			return err
		}
		if err := require(rhs, in); err != nil {
			return err
		}
		push(wasmInferValue{typ: out})
		return nil
	}
	checkResult := func(kind string, result LLVMType, stackBase int) error {
		if result == "" {
			return nil
		}
		if len(stack) <= stackBase {
			return fmt.Errorf("%s: %s block is missing its %s result", name, kind, result)
		}
		return require(stack[len(stack)-1], result)
	}

	for _, ins := range fn.Instrs {
		op := normalizeInstructionOpcode(ins.Op)
		if err := validateWASMRawReturn(ins, op); err != nil {
			return FuncSig{}, err
		}
		if err := validateWASMStackControlOperands(ins, op); err != nil {
			return FuncSig{}, err
		}
		controlResult, err := parseWASMControlResult(ins, op)
		if err != nil {
			return FuncSig{}, err
		}
		// Validate typed source formats even when the instruction is dead,
		// matching translateFuncWASM's prepass. Retain these descriptors for
		// live stack inference instead of parsing them again.
		vector, vectorKnown, err := parseWASMV128Core(ins, op)
		if err != nil {
			return FuncSig{}, err
		}
		count, countKnown, err := parseWASMIntegerCount(ins)
		if err != nil {
			return FuncSig{}, err
		}
		floating, floatingKnown, err := parseWASMFloatBinary(ins)
		if err != nil {
			return FuncSig{}, err
		}
		floatConstant, floatConstantKnown, err := parseWASMFloatConstant(ins, op)
		if err != nil {
			return FuncSig{}, err
		}
		conversion, conversionKnown, err := parseWASMConversion(ins)
		if err != nil {
			return FuncSig{}, err
		}
		memory, memoryKnown, err := parseWASMMemory(ins, op)
		if err != nil {
			return FuncSig{}, err
		}
		memoryBuiltin, builtinKnown, err := parseWASMMemoryBuiltin(ins, op)
		if err != nil {
			return FuncSig{}, err
		}
		integerBinary, integerBinaryKnown, err := parseWASMIntegerBinary(ins, op)
		if err != nil {
			return FuncSig{}, err
		}
		comparison, comparisonKnown, err := parseWASMIntegerComparison(ins, op)
		if err != nil {
			return FuncSig{}, err
		}
		if terminated {
			skip, err := dead.skip(op, controlResult)
			if err != nil {
				return FuncSig{}, err
			}
			if skip {
				continue
			}
		}
		if integerBinaryKnown {
			for i := 0; i < 2; i++ {
				if err := popTyped(op, integerBinary.typ); err != nil {
					return FuncSig{}, err
				}
			}
			push(wasmInferValue{typ: integerBinary.typ})
			continue
		}
		if comparisonKnown {
			for i := 0; i < comparison.arity; i++ {
				if err := popTyped(op, comparison.typ); err != nil {
					return FuncSig{}, err
				}
			}
			push(wasmInferValue{typ: I32})
			continue
		}
		if memoryKnown {
			if memory.spec.consumesValue() {
				if err := popTyped(op, memory.spec.stack); err != nil {
					return FuncSig{}, err
				}
			}
			switch {
			case memory.frame:
				// A bound FP slot takes its address from the frame contract.
			case memory.base == "":
				if err := popTyped(op, I32); err != nil {
					return FuncSig{}, err
				}
			default:
				reg := memory.base
				if reg != SP && !written[reg] {
					inputs[reg] = true
				}
			}
			if !memory.spec.store {
				push(wasmInferValue{typ: memory.spec.stack})
			}
			continue
		}
		if builtinKnown {
			for range memoryBuiltin.operands {
				if err := popTyped(op, I32); err != nil {
					return FuncSig{}, err
				}
			}
			if !memoryBuiltin.isBulk() {
				push(wasmInferValue{typ: I32})
			}
			continue
		}
		if conversionKnown {
			if err := popTyped(op, conversion.source); err != nil {
				return FuncSig{}, err
			}
			push(wasmInferValue{typ: conversion.result})
			continue
		}
		if vectorKnown {
			for index := vector.Arity() - 1; index >= 0; index-- {
				if err := popTyped(op, LLVMType(vector.InputType(index))); err != nil {
					return FuncSig{}, err
				}
			}
			push(wasmInferValue{typ: LLVMType(vector.ResultType())})
			continue
		}
		if countKnown {
			spec := count
			if len(stack) == 0 {
				return FuncSig{}, fmt.Errorf("%s: %s requires one stack operand", name, op)
			}
			for reg := range stack[len(stack)-1].regs {
				typ := wasmDefaultRegisterType(reg)
				if typ != I32 && typ != I64 {
					return FuncSig{}, fmt.Errorf("%s: %s register %s is not an integer", name, op, reg)
				}
			}
			if err := typedUnary(op, spec.typ, spec.typ); err != nil {
				return FuncSig{}, err
			}
			continue
		}
		if floatingKnown {
			spec := floating
			if len(stack) < 2 {
				return FuncSig{}, fmt.Errorf("%s: %s requires two stack operands", name, op)
			}
			for _, value := range stack[len(stack)-2:] {
				for reg := range value.regs {
					if wasmDefaultRegisterType(reg) != spec.typ {
						return FuncSig{}, fmt.Errorf("%s: %s register %s does not carry %s", name, op, reg, spec.typ)
					}
				}
			}
			if err := typedBinary(op, spec.typ, spec.resultType()); err != nil {
				return FuncSig{}, err
			}
			continue
		}
		if floatConstantKnown {
			push(wasmInferValue{typ: floatConstant.typ})
			continue
		}
		switch op {
		case "TEXT", "NOP", "NO_LOCAL_POINTERS":
		case "GET":
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg || ins.Args[0].Reg == SP {
				continue
			}
			reg := ins.Args[0].Reg
			if !written[reg] {
				inputs[reg] = true
			}
			push(wasmInferValue{typ: regTypes[reg], regs: map[Reg]struct{}{reg: {}}})
		case "SET", "TEE":
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg {
				continue
			}
			v := pop(op)
			reg := ins.Args[0].Reg
			written[reg] = true
			if v.typ != "" {
				if err := require(wasmInferValue{regs: map[Reg]struct{}{reg: {}}}, v.typ); err != nil {
					return FuncSig{}, err
				}
			}
			if op == "TEE" {
				push(v)
			}
		case "I32CONST":
			push(wasmInferValue{typ: I32})
		case "I64CONST":
			push(wasmInferValue{typ: I64})
		case "SELECT":
			if err := popTyped(op, I32); err != nil {
				return FuncSig{}, err
			}
			ifFalse := pop(op)
			ifTrue := pop(op)
			if ifTrue.typ != "" && ifFalse.typ != "" && ifTrue.typ != ifFalse.typ {
				return FuncSig{}, fmt.Errorf("%s: Select type mismatch %s %v and %s %v", name, ifTrue.typ, ifTrue.regs, ifFalse.typ, ifFalse.regs)
			}
			typ := ifTrue.typ
			if typ == "" {
				typ = ifFalse.typ
			}
			if typ != "" {
				if err := require(ifTrue, typ); err != nil {
					return FuncSig{}, err
				}
				if err := require(ifFalse, typ); err != nil {
					return FuncSig{}, err
				}
			}
			push(wasmInferValue{typ: typ})
		case "LABEL":
			if len(ins.Args) != 1 {
				return FuncSig{}, fmt.Errorf("wasm label expects one name")
			}
			pendingName = strings.TrimSuffix(ins.Args[0].Sym, ":")
		case "BLOCK", "LOOP", "IF":
			if op == "IF" {
				if err := popTyped(op, I32); err != nil {
					return FuncSig{}, err
				}
			}
			controls = append(controls, inferControl{
				wasmControlLabel: wasmControlLabel{
					kind:       strings.ToLower(op),
					name:       pendingName,
					resultType: controlResult,
				},
				base: copyStack(stack),
			})
			pendingName = ""
		case "ELSE":
			control := &controls[len(controls)-1]
			if control.kind != "if" {
				return FuncSig{}, fmt.Errorf("Else without matching If")
			}
			if !terminated {
				if err := checkResult(control.kind, control.resultType, len(control.base)); err != nil {
					return FuncSig{}, err
				}
			}
			control.kind = "else"
			stack = copyStack(control.base)
			terminated = false
		case "END":
			if len(controls) <= 1 {
				return FuncSig{}, fmt.Errorf("End without active control")
			}
			control := controls[len(controls)-1]
			controls = controls[:len(controls)-1]
			if control.kind == "if" && control.resultType != "" {
				return FuncSig{}, fmt.Errorf("result-producing If requires Else")
			}
			if !terminated {
				if err := checkResult(control.kind, control.resultType, len(control.base)); err != nil {
					return FuncSig{}, err
				}
			}
			stack = copyStack(control.base)
			if control.resultType != "" {
				push(wasmInferValue{typ: control.resultType})
			}
			terminated = false
		case "BR", "BRIF":
			index, err := wasmBranchTarget(ins, op, len(controls), func(i int) string {
				return controls[i].name
			})
			if err != nil {
				return FuncSig{}, err
			}
			stackBase := len(controls[len(controls)-1].base)
			if op == "BRIF" {
				if len(stack) <= stackBase {
					return FuncSig{}, fmt.Errorf("%s: %s operand stack underflow", name, op)
				}
				if err := popTyped(op, I32); err != nil {
					return FuncSig{}, err
				}
			}
			target := controls[index]
			if err := checkResult(target.kind, target.branchResult(), stackBase); err != nil {
				return FuncSig{}, err
			}
			if op == "BR" {
				terminated = true
				stack = nil
			}
		case "DROP":
			_ = pop(op)
		case "UNDEF", "UNREACHABLE", "JMP":
			terminated = true
			stack = nil
		case "CALL", "CALLNORESUME", "WASMCALL":
			// The callee signature is not encoded in the instruction. Values
			// pushed for it have already constrained the input registers; reset
			// the stack and leave an unknown result for its consumer to type.
			stack = nil
			push(wasmInferValue{})
		case "WASMRETURN", "RET", "RETUNWIND":
			terminated = true
			if len(stack) != 0 {
				v := pop(op)
				if v.typ != "" {
					if returnType != "" && returnType != v.typ {
						return FuncSig{}, fmt.Errorf("%s: conflicting return types %s and %s", name, returnType, v.typ)
					}
					returnType = v.typ
				}
			}
			stack = nil
		}
	}

	if open := len(controls) - 1 + len(dead); open != 0 {
		return FuncSig{}, fmt.Errorf("%d unterminated wasm control blocks", open)
	}
	regs := make([]Reg, 0, len(inputs))
	for reg := range inputs {
		regs = append(regs, reg)
	}
	sort.Slice(regs, func(i, j int) bool { return wasmRegOrder(regs[i]) < wasmRegOrder(regs[j]) })
	args := make([]LLVMType, len(regs))
	for i, reg := range regs {
		typ := regTypes[reg]
		if typ == "" {
			typ = wasmDefaultRegisterType(reg)
		}
		args[i] = typ
	}
	if returnType == "" {
		returnType = Void
	}
	return FuncSig{Name: name, Args: args, Ret: returnType, ArgRegs: regs}, nil
}

func wasmRegisterCarries(reg Reg, want LLVMType) bool {
	typ := wasmDefaultRegisterType(reg)
	return typ == want || typ == I64 && want == I32 || typ == I32 && want == I64
}

func wasmDefaultRegisterType(reg Reg) LLVMType {
	name := strings.ToUpper(string(reg))
	if strings.HasPrefix(name, "F") {
		n, _ := strconv.Atoi(strings.TrimPrefix(name, "F"))
		if n < 16 {
			return LLVMType("float")
		}
		return LLVMType("double")
	}
	if strings.HasPrefix(name, "V") {
		return LLVMType("<4 x i32>")
	}
	if name == "PC_B" || name == "SP" {
		return I32
	}
	return I64
}

func wasmRegOrder(reg Reg) int {
	name := strings.ToUpper(string(reg))
	for group, prefix := range []string{"R", "F", "V"} {
		if strings.HasPrefix(name, prefix) {
			n, err := strconv.Atoi(strings.TrimPrefix(name, prefix))
			if err == nil {
				return group*100 + n
			}
		}
	}
	return 1000
}
