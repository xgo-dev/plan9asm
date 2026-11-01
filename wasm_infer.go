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
		base   []wasmInferValue
		result LLVMType
	}
	var (
		stack      []wasmInferValue
		regTypes   = make(map[Reg]LLVMType)
		inputs     = make(map[Reg]bool)
		written    = make(map[Reg]bool)
		returnType LLVMType
		controls   []inferControl
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

	for _, ins := range fn.Instrs {
		op := normalizeInstructionOpcode(ins.Op)
		if spec, found, err := parseWASMIntegerCount(ins); found {
			if err != nil {
				return FuncSig{}, err
			}
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
		if spec, found, err := parseWASMFloatBinary(ins); found {
			if err != nil {
				return FuncSig{}, err
			}
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
		switch op {
		case "TEXT", "NOP", "NO_LOCAL_POINTERS", "LABEL":
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
		case "I32WRAPI64":
			if err := typedUnary(op, I64, I32); err != nil {
				return FuncSig{}, err
			}
		case "I64EXTENDI32S", "I64EXTENDI32U":
			if err := typedUnary(op, I32, I64); err != nil {
				return FuncSig{}, err
			}
		case "I32ADD", "I32SUB", "I32MUL", "I32AND", "I32OR", "I32XOR",
			"I32DIVS", "I32DIVU", "I32REMS", "I32REMU", "I32SHL", "I32SHRS", "I32SHRU":
			if err := typedBinary(op, I32, I32); err != nil {
				return FuncSig{}, err
			}
		case "I64ADD", "I64SUB", "I64MUL", "I64AND", "I64OR", "I64XOR",
			"I64DIVS", "I64DIVU", "I64REMS", "I64REMU", "I64SHL", "I64SHRS", "I64SHRU":
			if err := typedBinary(op, I64, I64); err != nil {
				return FuncSig{}, err
			}
		case "I32EQ", "I32NE", "I32LTS", "I32LTU", "I32GTS", "I32GTU", "I32LES", "I32LEU", "I32GES", "I32GEU":
			if err := typedBinary(op, I32, I32); err != nil {
				return FuncSig{}, err
			}
		case "I64EQ", "I64NE", "I64LTS", "I64LTU", "I64GTS", "I64GTU", "I64LES", "I64LEU", "I64GES", "I64GEU":
			if err := typedBinary(op, I64, I32); err != nil {
				return FuncSig{}, err
			}
		case "I32EQZ", "NOT":
			if err := typedUnary(op, I32, I32); err != nil {
				return FuncSig{}, err
			}
		case "I64EQZ":
			if err := typedUnary(op, I64, I32); err != nil {
				return FuncSig{}, err
			}
		case "I32LOAD", "I32LOAD8S", "I32LOAD8U", "I32LOAD16S", "I32LOAD16U":
			if len(ins.Args) == 1 && ins.Args[0].Kind != OpFP {
				if err := require(pop(op), I32); err != nil {
					return FuncSig{}, err
				}
			}
			push(wasmInferValue{typ: I32})
		case "I64LOAD", "I64LOAD8S", "I64LOAD8U", "I64LOAD16S", "I64LOAD16U", "I64LOAD32S", "I64LOAD32U":
			if len(ins.Args) == 1 && ins.Args[0].Kind != OpFP {
				if err := require(pop(op), I32); err != nil {
					return FuncSig{}, err
				}
			}
			push(wasmInferValue{typ: I64})
		case "I32STORE", "I32STORE8", "I32STORE16":
			if err := require(pop(op), I32); err != nil {
				return FuncSig{}, err
			}
			if len(ins.Args) == 1 && ins.Args[0].Kind != OpFP {
				if err := require(pop(op), I32); err != nil {
					return FuncSig{}, err
				}
			}
		case "I64STORE", "I64STORE8", "I64STORE16", "I64STORE32":
			if err := require(pop(op), I64); err != nil {
				return FuncSig{}, err
			}
			if len(ins.Args) == 1 && ins.Args[0].Kind != OpFP {
				if err := require(pop(op), I32); err != nil {
					return FuncSig{}, err
				}
			}
		case "SELECT":
			condition := pop(op)
			if err := require(condition, I32); err != nil {
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
		case "IF", "BRIF":
			if err := require(pop(op), I32); err != nil {
				return FuncSig{}, err
			}
			if op == "IF" {
				result := LLVMType("")
				if len(ins.Args) == 1 && ins.Args[0].Kind == OpImm {
					result = wasmBlockResultType(ins.Args[0].Imm)
				}
				controls = append(controls, inferControl{base: copyStack(stack), result: result})
			}
		case "BLOCK", "LOOP":
			result := LLVMType("")
			if len(ins.Args) == 1 && ins.Args[0].Kind == OpImm {
				result = wasmBlockResultType(ins.Args[0].Imm)
			}
			controls = append(controls, inferControl{base: copyStack(stack), result: result})
		case "ELSE":
			if len(controls) != 0 {
				control := controls[len(controls)-1]
				if control.result != "" && len(stack) > len(control.base) {
					if err := require(stack[len(stack)-1], control.result); err != nil {
						return FuncSig{}, err
					}
				}
				stack = copyStack(control.base)
			}
		case "END":
			if len(controls) != 0 {
				control := controls[len(controls)-1]
				controls = controls[:len(controls)-1]
				if control.result != "" {
					if len(stack) > len(control.base) {
						if err := require(stack[len(stack)-1], control.result); err != nil {
							return FuncSig{}, err
						}
					}
					stack = copyStack(control.base)
					push(wasmInferValue{typ: control.result})
				} else {
					stack = copyStack(control.base)
				}
			}
		case "BR":
			if len(controls) != 0 {
				control := controls[len(controls)-1]
				if control.result != "" && len(stack) > len(control.base) {
					if err := require(stack[len(stack)-1], control.result); err != nil {
						return FuncSig{}, err
					}
				}
			}
			stack = nil
		case "DROP":
			_ = pop(op)
		case "CALL", "CALLNORESUME", "WASMCALL":
			// The callee signature is not encoded in the instruction. Values
			// pushed for it have already constrained the input registers; reset
			// the stack and leave an unknown result for its consumer to type.
			stack = nil
			push(wasmInferValue{})
		case "WASMRETURN", "RET", "RETUNWIND":
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

func wasmBlockResultType(code int64) LLVMType {
	switch code {
	case 1:
		return I32
	case 2:
		return I64
	case 3:
		return LLVMType("float")
	case 4:
		return LLVMType("double")
	default:
		return ""
	}
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
