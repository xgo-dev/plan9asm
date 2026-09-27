package plan9asm

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func (c *arm64Ctx) lowerARM64ScalarFloatUnary(op Op, ins Instr) (ok bool, terminated bool, err error) {
	operations := map[Op]string{
		"FABSS": "fabs", "FABSD": "fabs",
		"FNEGS": "neg", "FNEGD": "neg",
		"FSQRTS": "sqrt", "FSQRTD": "sqrt",
		"FRINTNS": "roundeven", "FRINTND": "roundeven",
		"FRINTPS": "ceil", "FRINTPD": "ceil",
		"FRINTMS": "floor", "FRINTMD": "floor",
		"FRINTZS": "trunc", "FRINTZD": "trunc",
		"FRINTAS": "round", "FRINTAD": "round",
		"FRINTXS": "rint", "FRINTXD": "rint",
		"FRINTIS": "nearbyint", "FRINTID": "nearbyint",
	}
	operation, handled := operations[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || !isARM64FReg(ins.Args[0].Reg) ||
		ins.Args[1].Kind != OpReg || !isARM64FReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 %s expects Fsrc, Fdst and no suffix: %q", op, ins.Raw)
	}
	bits := 64
	floatType := "double"
	intrinsicSuffix := "f64"
	if strings.HasSuffix(string(op), "S") {
		bits = 32
		floatType = "float"
		intrinsicSuffix = "f32"
	}
	source, err := c.loadARM64ScalarFloatReg(ins.Args[0].Reg, bits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if operation == "neg" {
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", result, floatType, source)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", result, floatType, operation, intrinsicSuffix, floatType, source)
	}
	return true, false, c.storeARM64ScalarFloatReg(ins.Args[1].Reg, bits, "%"+result)
}

func (c *arm64Ctx) lowerFP(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerARM64ScalarFloatCompare(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64FloatConditionalCompare(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64ScalarFloatBinary(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64ScalarFloatUnary(op, ins); ok {
		return ok, terminated, err
	}
	switch op {
	case "FMOVB", "FMOVH", "FMOVS", "FMOVD":
		return c.lowerScalarFloatMove(op, ins)

	case "FCVTSD", "FCVTDS", "FCVTSH", "FCVTHS", "FCVTDH", "FCVTHD":
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
			ins.Args[0].Kind != OpReg || !isARM64FReg(ins.Args[0].Reg) ||
			ins.Args[1].Kind != OpReg || !isARM64FReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("arm64 %s expects Fsrc, Fdst and no suffix: %q", op, ins.Raw)
		}
		conversionWidths := map[Op][2]int{
			"FCVTSD": {32, 64},
			"FCVTDS": {64, 32},
			"FCVTSH": {32, 16},
			"FCVTHS": {16, 32},
			"FCVTDH": {64, 16},
			"FCVTHD": {16, 64},
		}
		sourceBits := conversionWidths[op][0]
		destinationBits := conversionWidths[op][1]
		source, err := c.loadARM64ScalarFloatReg(ins.Args[0].Reg, sourceBits)
		if err != nil {
			return true, false, err
		}
		converted := c.newTmp()
		llvmFloatType := func(bits int) string {
			switch bits {
			case 16:
				return "half"
			case 32:
				return "float"
			default:
				return "double"
			}
		}
		sourceType := llvmFloatType(sourceBits)
		destinationType := llvmFloatType(destinationBits)
		if sourceBits < destinationBits {
			fmt.Fprintf(c.b, "  %%%s = fpext %s %s to %s\n", converted, sourceType, source, destinationType)
		} else {
			fmt.Fprintf(c.b, "  %%%s = fptrunc %s %s to %s\n", converted, sourceType, source, destinationType)
		}
		return true, false, c.storeARM64ScalarFloatReg(ins.Args[1].Reg, destinationBits, "%"+converted)

	case "FCSELS", "FCSELD":
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
			return true, false, fmt.Errorf("arm64 %s expects condition, Fsrc, Fsrc, Fdst and no suffix: %q", op, ins.Raw)
		}
		condition, conditionOK := arm64ConditionOperand(ins.Args[0])
		if !conditionOK {
			return true, false, fmt.Errorf("arm64 %s expects a condition operand: %q", op, ins.Raw)
		}
		for _, operand := range ins.Args[1:] {
			if operand.Kind != OpReg || !isARM64FReg(operand.Reg) {
				return true, false, fmt.Errorf("arm64 %s accepts only scalar floating registers: %q", op, ins.Raw)
			}
		}
		bits := 32
		if op == "FCSELD" {
			bits = 64
		}
		return true, false, c.lowerARM64FloatSelectValues(
			bits,
			condition,
			ins.Args[1].Reg,
			ins.Args[2].Reg,
			ins.Args[3].Reg,
		)

	case "FMADDS", "FMADDD", "FMSUBS", "FMSUBD",
		"FNMADDS", "FNMADDD", "FNMSUBS", "FNMSUBD":
		return c.lowerFusedMultiplyAdd(op, ins)

	case "FCVTZSD", "FCVTZSDW", "FCVTZSS", "FCVTZSSW",
		"FCVTZUD", "FCVTZUDW", "FCVTZUS", "FCVTZUSW":
		// Go 1.27 exposes the complete scalar FCVT-to-integer family through
		// AFCVTZSD's single C_FREG -> C_ZREG optab row. The final W selects a
		// 32-bit integer result; S/D before it selects the floating input width.
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
			ins.Args[0].Kind != OpReg || !isARM64FReg(ins.Args[0].Reg) ||
			ins.Args[1].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("arm64 %s expects Fsrc, Rdst/ZR and no suffix: %q", op, ins.Raw)
		}
		sourceBits := 64
		sourceMnemonic := strings.TrimSuffix(string(op), "W")
		if strings.HasSuffix(sourceMnemonic, "S") {
			sourceBits = 32
		}
		destinationBits := 64
		if strings.HasSuffix(string(op), "W") {
			destinationBits = 32
		}
		err := c.lowerARM64ScalarFloatToInteger(
			ins.Args[0].Reg,
			sourceBits,
			ins.Args[1].Reg,
			destinationBits,
			strings.HasPrefix(string(op), "FCVTZU"),
			arm64FloatRoundZero,
		)
		return true, false, err

	case "SCVTFD", "SCVTFS", "SCVTFWD", "SCVTFWS", "SCVTFDD", "SCVTFSS",
		"UCVTFD", "UCVTFS", "UCVTFWD", "UCVTFWS", "UCVTFDD", "UCVTFSS":
		// The DD/SS forms take integer bits from an F register; the other
		// forms take an R/ZR register. x/arch prints all twelve scalar
		// encodings with these distinct Plan 9 names.
		vectorSource := strings.HasSuffix(string(op), "DD") || strings.HasSuffix(string(op), "SS")
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
			ins.Args[0].Kind != OpReg ||
			ins.Args[1].Kind != OpReg || !isARM64FReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("arm64 %s expects an integer source, one F destination, and no suffix: %q", op, ins.Raw)
		}
		if vectorSource && !isARM64FReg(ins.Args[0].Reg) ||
			!vectorSource && !isARM64GeneralOrZeroReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("arm64 %s has the wrong source register class: %q", op, ins.Raw)
		}
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		integerType := "i64"
		if strings.Contains(string(op), "W") || strings.HasSuffix(string(op), "SS") {
			narrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, src)
			src = "%" + narrow
			integerType = "i32"
		}
		floatType := "double"
		bits := 64
		if strings.HasSuffix(string(op), "S") {
			floatType = "float"
			bits = 32
		}
		conversion := "sitofp"
		if strings.HasPrefix(string(op), "U") {
			conversion = "uitofp"
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", converted, conversion, integerType, src, floatType)
		if bits == 64 {
			encoded := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast double %%%s to i64\n", encoded, converted)
			return true, false, c.storeReg(ins.Args[1].Reg, "%"+encoded)
		}
		encoded := c.newTmp()
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %%%s to i32\n", encoded, converted)
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, encoded)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+wide)
	}
	return false, false, nil
}

func (c *arm64Ctx) lowerFusedMultiplyAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects four F-register operands and no suffixes: %q", op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects four F-register operands: %q", op, ins.Raw)
		}
		if _, ok := arm64ParseFReg(arg.Reg); !ok {
			return true, false, fmt.Errorf("arm64 %s expects four F-register operands: %q", op, ins.Raw)
		}
	}

	floatType := "double"
	intrinsic := "@llvm.fma.f64"
	eval := c.evalF64
	store := c.storeF64
	if strings.HasSuffix(string(op), "S") {
		floatType = "float"
		intrinsic = "@llvm.fma.f32"
		eval = c.evalF32
		store = c.storeF32
	}

	// Go's Plan 9 order is Fm, Fa, Fn, Fd. The architectural operations are:
	//   FMADD:   Fn*Fm + Fa       FMSUB:  Fa - Fn*Fm
	//   FNMADD: -(Fn*Fm + Fa)     FNMSUB: Fn*Fm - Fa
	fm, err := eval(ins.Args[0])
	if err != nil {
		return true, false, err
	}
	fa, err := eval(ins.Args[1])
	if err != nil {
		return true, false, err
	}
	fn, err := eval(ins.Args[2])
	if err != nil {
		return true, false, err
	}

	if strings.HasPrefix(string(op), "FMSUB") {
		negFM := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", negFM, floatType, fm)
		fm = "%" + negFM
	} else if strings.HasPrefix(string(op), "FNMSUB") {
		negFA := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", negFA, floatType, fa)
		fa = "%" + negFA
	}

	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %s, %s %s, %s %s)\n",
		result, floatType, intrinsic, floatType, fm, floatType, fn, floatType, fa)
	value := "%" + result
	if strings.HasPrefix(string(op), "FNMADD") {
		negResult := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", negResult, floatType, value)
		value = "%" + negResult
	}
	return true, false, store(ins.Args[3], value)
}

func (c *arm64Ctx) evalFMOVDBits(op Operand) (string, error) {
	if op.Kind == OpSym && strings.HasPrefix(op.Sym, "$") {
		if fv, ok := arm64ParseDollarFloat(op.Sym); ok {
			u := math.Float64bits(fv)
			return strconv.FormatInt(int64(u), 10), nil
		}
		if iv, ok := arm64ParseDollarInt64(op.Sym); ok {
			return strconv.FormatInt(iv, 10), nil
		}
	}
	return c.eval64(op, false)
}

func (c *arm64Ctx) evalF64(op Operand) (string, error) {
	switch op.Kind {
	case OpReg:
		v64, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, v64)
		return "%" + t, nil
	case OpImm:
		return formatLLVMFloat64Literal(float64(op.Imm)), nil
	case OpSym:
		if strings.HasPrefix(op.Sym, "$") {
			if fv, ok := arm64ParseDollarFloat(op.Sym); ok {
				return formatLLVMFloat64Literal(fv), nil
			}
			if iv, ok := arm64ParseDollarInt64(op.Sym); ok {
				return formatLLVMFloat64Literal(float64(iv)), nil
			}
		}
		return "", fmt.Errorf("arm64: unsupported f64 immediate %q", op.String())
	case OpFP:
		slot, ok := c.fpParams[op.FPOffset]
		if !ok {
			return "", fmt.Errorf("arm64: unsupported FP param slot: %s", op.String())
		}
		arg, err := c.loadFPParameter(slot)
		if err != nil {
			return "", err
		}
		switch slot.Type {
		case LLVMType("double"):
			return arg, nil
		case LLVMType("float"):
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fpext float %s to double\n", t, arg)
			return "%" + t, nil
		case I64:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, arg)
			return "%" + t, nil
		case I32, I16, I8, I1:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, slot.Type, arg)
			b := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i64 %%%s to double\n", b, t)
			return "%" + b, nil
		case Ptr:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, arg)
			b := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i64 %%%s to double\n", b, t)
			return "%" + b, nil
		default:
			return "", fmt.Errorf("arm64: unsupported FP slot type %s", slot.Type)
		}
	default:
		return "", fmt.Errorf("arm64: unsupported f64 operand %s", op.String())
	}
}

func (c *arm64Ctx) evalF32(op Operand) (string, error) {
	if op.Kind != OpReg {
		return "", fmt.Errorf("arm64: unsupported f32 operand %s", op.String())
	}
	v64, err := c.loadReg(op.Reg)
	if err != nil {
		return "", err
	}
	v32 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", v32, v64)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", value, v32)
	return "%" + value, nil
}

func (c *arm64Ctx) storeF64(dst Operand, v string) error {
	switch dst.Kind {
	case OpReg:
		b := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", b, v)
		return c.storeReg(dst.Reg, "%"+b)
	case OpFP:
		b := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", b, v)
		return c.storeFPResult64(dst.FPOffset, "%"+b)
	default:
		return fmt.Errorf("arm64: unsupported f64 dst operand %s", dst.String())
	}
}

func (c *arm64Ctx) storeF32(dst Operand, v string) error {
	if dst.Kind != OpReg {
		return fmt.Errorf("arm64: unsupported f32 dst operand %s", dst.String())
	}
	bits32 := c.newTmp()
	bits64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", bits32, v)
	fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", bits64, bits32)
	return c.storeReg(dst.Reg, "%"+bits64)
}

func arm64ParseDollarFloat(sym string) (float64, bool) {
	if !strings.HasPrefix(sym, "$") {
		return 0, false
	}
	s := strings.TrimSpace(strings.TrimPrefix(sym, "$"))
	if s == "" {
		return 0, false
	}
	// Integer-looking immediates are handled by arm64ParseDollarInt64.
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return 0, false
	}
	// Heuristic: require decimal/exponent marker.
	if !strings.ContainsAny(s, ".eE") {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func arm64ParseDollarInt64(sym string) (int64, bool) {
	if !strings.HasPrefix(sym, "$") {
		return 0, false
	}
	s := strings.TrimSpace(strings.TrimPrefix(sym, "$"))
	if s == "" {
		return 0, false
	}
	if v, err := strconv.ParseInt(s, 0, 64); err == nil {
		return v, true
	}
	if uv, err := strconv.ParseUint(s, 0, 64); err == nil {
		return int64(uv), true
	}
	return 0, false
}
