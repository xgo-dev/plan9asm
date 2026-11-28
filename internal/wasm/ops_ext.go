package wasm

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// M5 extended WebAssembly instruction lowering covering all standard scalar
// bit/extend, FP32/FP64 arithmetic/unary/compare/convert, control/memory/table
// ops, and full WebAssembly SIMD128 (V128) using 100% target-independent LLVM IR.

type wasmExtState struct {
	b          *strings.Builder
	newTmp     func() string
	push       func(wasmValue)
	pop        func(string) (wasmValue, error)
	cast       func(wasmValue, asm.LLVMType, bool) (wasmValue, error)
	addressPtr func(wasmValue, int64) (wasmValue, error)
}

func (s *wasmExtState) castV128(v wasmValue, vecTy asm.LLVMType) (string, error) {
	if v.typ == vecTy {
		return v.val, nil
	}
	if isWasmV128(v.typ) {
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %s to %s\n", t, v.typ, v.val, vecTy)
		return "%" + t, nil
	}
	return "", fmt.Errorf("expected v128 vector value, got %s", v.typ)
}

// emitTrapIf keeps observable traps alive even when an instruction's value is dropped.
func emitTrapIf(b *strings.Builder, newTmp func() string, condition string) {
	trap, ok := newTmp()+"_trap", newTmp()+"_ok"
	fmt.Fprintf(b, "  br i1 %%%s, label %%%s, label %%%s\n", condition, trap, ok)
	fmt.Fprintf(b, "%s:\n  call void @llvm.trap()\n  unreachable\n%s:\n", trap, ok)
}

// Bulk memory validates every range before any write, including zero-length
// operations. Use 64-bit arithmetic for the possible 4 GiB end address.
func emitBulkBoundsCheck(b *strings.Builder, newTmp func() string, length string, addresses ...string) {
	pages, pages64, limit, size := newTmp(), newTmp(), newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = call i32 @llvm.wasm.memory.size.i32(i32 0)\n", pages)
	fmt.Fprintf(b, "  %%%s = zext i32 %%%s to i64\n", pages64, pages)
	fmt.Fprintf(b, "  %%%s = shl i64 %%%s, 16\n", limit, pages64)
	fmt.Fprintf(b, "  %%%s = zext i32 %s to i64\n", size, length)
	for _, addr := range addresses {
		start, end, bad := newTmp(), newTmp(), newTmp()
		fmt.Fprintf(b, "  %%%s = ptrtoint ptr %s to i64\n", start, addr)
		fmt.Fprintf(b, "  %%%s = add i64 %%%s, %%%s\n", end, start, size)
		fmt.Fprintf(b, "  %%%s = icmp ugt i64 %%%s, %%%s\n", bad, end, limit)
		emitTrapIf(b, newTmp, bad)
	}
}

// emitWasmCheckedFloatTrunc lowers non-saturating WebAssembly float-to-int
// truncation (i32/i64.trunc_f32/f64_s/u) with mandatory trap checks for NaN,
// infinity, and out-of-range values before fptosi/fptoui. Using @llvm.trap()
// prevents LLVM -O2 from eliminating the trap when the result is dropped.
func emitWasmCheckedFloatTrunc(b *strings.Builder, newTmp func() string, srcTy, dstTy asm.LLVMType, signed bool, val string) string {
	var loPred, loLit, hiLit string
	switch {
	case dstTy == asm.I32 && srcTy == asm.LLVMType("float") && signed:
		loPred = "ult"
		loLit = asm.FormatLLVMFloat64Literal(-2147483648.0) // -2^31 (exact f32)
		hiLit = asm.FormatLLVMFloat64Literal(2147483648.0)  // +2^31 (exact f32)
	case dstTy == asm.I32 && srcTy == asm.LLVMType("float") && !signed:
		loPred = "ule"
		loLit = asm.FormatLLVMFloat64Literal(-1.0)
		hiLit = asm.FormatLLVMFloat64Literal(4294967296.0) // 2^32 (exact f32)
	case dstTy == asm.I32 && srcTy == asm.LLVMType("double") && signed:
		loPred = "ule"
		loLit = asm.FormatLLVMFloat64Literal(-2147483649.0) // -2^31 - 1 (exact f64)
		hiLit = asm.FormatLLVMFloat64Literal(2147483648.0)  // +2^31 (exact f64)
	case dstTy == asm.I32 && srcTy == asm.LLVMType("double") && !signed:
		loPred = "ule"
		loLit = asm.FormatLLVMFloat64Literal(-1.0)
		hiLit = asm.FormatLLVMFloat64Literal(4294967296.0) // 2^32 (exact f64)
	case dstTy == asm.I64 && srcTy == asm.LLVMType("float") && signed:
		loPred = "ult"
		loLit = asm.FormatLLVMFloat64Literal(-9223372036854775808.0) // -2^63 (exact f32)
		hiLit = asm.FormatLLVMFloat64Literal(9223372036854775808.0)  // +2^63 (exact f32)
	case dstTy == asm.I64 && srcTy == asm.LLVMType("float") && !signed:
		loPred = "ule"
		loLit = asm.FormatLLVMFloat64Literal(-1.0)
		hiLit = asm.FormatLLVMFloat64Literal(18446744073709551616.0) // 2^64 (exact f32)
	case dstTy == asm.I64 && srcTy == asm.LLVMType("double") && signed:
		loPred = "ult"
		loLit = asm.FormatLLVMFloat64Literal(-9223372036854775808.0) // -2^63 (exact f64)
		hiLit = asm.FormatLLVMFloat64Literal(9223372036854775808.0)  // +2^63 (exact f64)
	default: // I64TruncF64U
		loPred = "ule"
		loLit = asm.FormatLLVMFloat64Literal(-1.0)
		hiLit = asm.FormatLLVMFloat64Literal(18446744073709551616.0) // 2^64 (exact f64)
	}
	loBad, hiBad, bad := newTmp(), newTmp(), newTmp()

	// Unordered predicates (ult/ule/uge) also evaluate to true on NaN.
	fmt.Fprintf(b, "  %%%s = fcmp %s %s %s, %s\n", loBad, loPred, srcTy, val, loLit)
	fmt.Fprintf(b, "  %%%s = fcmp uge %s %s, %s\n", hiBad, srcTy, val, hiLit)
	fmt.Fprintf(b, "  %%%s = or i1 %%%s, %%%s\n", bad, loBad, hiBad)
	emitTrapIf(b, newTmp, bad)
	conv := "fptoui"
	if signed {
		conv = "fptosi"
	}
	res := newTmp()
	fmt.Fprintf(b, "  %%%s = %s %s %s to %s\n", res, conv, srcTy, val, dstTy)
	return "%" + res
}

func wasmCastFloat(s *wasmExtState, v wasmValue, to asm.LLVMType) (wasmValue, error) {
	if v.typ == to {
		return v, nil
	}
	if to == asm.LLVMType("float") && v.typ == asm.I32 {
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = bitcast i32 %s to float\n", t, v.val)
		return wasmValue{typ: to, val: "%" + t}, nil
	}
	if to == asm.LLVMType("double") && v.typ == asm.I64 {
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = bitcast i64 %s to double\n", t, v.val)
		return wasmValue{typ: to, val: "%" + t}, nil
	}
	return wasmValue{}, fmt.Errorf("expected %s, got %s", to, v.typ)
}

func (s *wasmExtState) lowerExtOp(op string, ins asm.Instr) (bool, error) {
	// 1. Scalar integer bit-manipulation & sign-extend ops
	switch op {
	case "I32CLZ", "I64CLZ", "I32CTZ", "I64CTZ", "I32POPCNT", "I64POPCNT":
		ty := asm.I32
		if strings.HasPrefix(op, "I64") {
			ty = asm.I64
		}
		v, err := s.pop(op)
		if err != nil {
			return true, err
		}
		v, err = s.cast(v, ty, false)
		if err != nil {
			return true, err
		}
		t := s.newTmp()
		switch {
		case strings.HasSuffix(op, "CLZ"):
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.ctlz.%s(%s %s, i1 false)\n", t, ty, ty, ty, v.val)
		case strings.HasSuffix(op, "CTZ"):
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.cttz.%s(%s %s, i1 false)\n", t, ty, ty, ty, v.val)
		default:
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.ctpop.%s(%s %s)\n", t, ty, ty, ty, v.val)
		}
		s.push(wasmValue{typ: ty, val: "%" + t})
		return true, nil

	case "I32ROTL", "I32ROTR", "I64ROTL", "I64ROTR":
		ty := asm.I32
		if strings.HasPrefix(op, "I64") {
			ty = asm.I64
		}
		rhs, err := s.pop(op)
		if err != nil {
			return true, err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return true, err
		}
		lhs, err = s.cast(lhs, ty, false)
		if err != nil {
			return true, err
		}
		rhs, err = s.cast(rhs, ty, false)
		if err != nil {
			return true, err
		}
		intr := "fshl"
		if strings.HasSuffix(op, "ROTR") {
			intr = "fshr"
		}
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = call %s @llvm.%s.%s(%s %s, %s %s, %s %s)\n", t, ty, intr, ty, ty, lhs.val, ty, lhs.val, ty, rhs.val)
		s.push(wasmValue{typ: ty, val: "%" + t})
		return true, nil

	case "I32EXTEND8S", "I32EXTEND16S", "I64EXTEND8S", "I64EXTEND16S", "I64EXTEND32S":
		ty := asm.I32
		if strings.HasPrefix(op, "I64") {
			ty = asm.I64
		}
		narrow := asm.I8
		if strings.Contains(op, "16S") {
			narrow = asm.I16
		} else if strings.Contains(op, "32S") {
			narrow = asm.I32
		}
		v, err := s.pop(op)
		if err != nil {
			return true, err
		}
		v, err = s.cast(v, ty, false)
		if err != nil {
			return true, err
		}
		tr, se := s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = trunc %s %s to %s\n", tr, ty, v.val, narrow)
		fmt.Fprintf(s.b, "  %%%s = sext %s %%%s to %s\n", se, narrow, tr, ty)
		s.push(wasmValue{typ: ty, val: "%" + se})
		return true, nil

	// 2. Float32 / Float64 const, load, store, arithmetic, unary, compare, convert
	case "F32CONST":
		if len(ins.Args) != 1 {
			return true, fmt.Errorf("F32Const expects one immediate")
		}
		var bits uint32
		switch arg := ins.Args[0]; arg.Kind {
		case asm.OpImm:
			if arg.ImmRaw != "" || arg.Imm < math.MinInt32 || arg.Imm > math.MaxUint32 {
				return true, fmt.Errorf("F32Const requires a 32-bit literal")
			}
			bits = uint32(arg.Imm)
		case asm.OpSym:
			raw := strings.TrimPrefix(strings.TrimSpace(arg.Sym), "$")
			v, err := strconv.ParseFloat(raw, 32)
			if err != nil {
				return true, fmt.Errorf("F32Const expects one immediate: %w", err)
			}
			bits = math.Float32bits(float32(v))
		default:
			return true, fmt.Errorf("F32Const expects one immediate")
		}
		// Widening a signaling NaN to float64 would change its quiet bit.
		s.push(wasmValue{typ: "float", val: fmt.Sprintf("bitcast (i32 %d to float)", bits)})
		return true, nil

	case "F32LOAD", "F64LOAD":
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm {
			return false, nil
		}
		ty := asm.LLVMType("float")
		if op == "F64LOAD" {
			ty = asm.LLVMType("double")
		}
		addr, err := s.pop(op)
		if err != nil {
			return true, err
		}
		addr, err = s.addressPtr(addr, ins.Args[0].Imm)
		if err != nil {
			return true, err
		}
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = load volatile %s, ptr %s, align 1\n", t, ty, addr.val)
		s.push(wasmValue{typ: ty, val: "%" + t})
		return true, nil

	case "F32STORE", "F64STORE":
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm {
			return false, nil
		}
		ty := asm.LLVMType("float")
		if op == "F64STORE" {
			ty = asm.LLVMType("double")
		}
		val, err := s.pop(op)
		if err != nil {
			return true, err
		}
		val, err = wasmCastFloat(s, val, ty)
		if err != nil {
			return true, err
		}
		addr, err := s.pop(op)
		if err != nil {
			return true, err
		}
		addr, err = s.addressPtr(addr, ins.Args[0].Imm)
		if err != nil {
			return true, err
		}
		fmt.Fprintf(s.b, "  store volatile %s %s, ptr %s, align 1\n", ty, val.val, addr.val)
		return true, nil

	case "F32ADD", "F32SUB", "F32MUL", "F32DIV", "F32MIN", "F32MAX", "F32COPYSIGN",
		"F64ADD", "F64SUB", "F64MUL", "F64DIV", "F64MIN", "F64MAX", "F64COPYSIGN":
		ty, suf := asm.LLVMType("float"), "f32"
		if strings.HasPrefix(op, "F64") {
			ty, suf = asm.LLVMType("double"), "f64"
		}
		rhs, err := s.pop(op)
		if err != nil {
			return true, err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return true, err
		}
		lhs, err = wasmCastFloat(s, lhs, ty)
		if err != nil {
			return true, err
		}
		rhs, err = wasmCastFloat(s, rhs, ty)
		if err != nil {
			return true, err
		}
		t := s.newTmp()
		switch op[3:] {
		case "ADD":
			fmt.Fprintf(s.b, "  %%%s = fadd %s %s, %s\n", t, ty, lhs.val, rhs.val)
		case "SUB":
			fmt.Fprintf(s.b, "  %%%s = fsub %s %s, %s\n", t, ty, lhs.val, rhs.val)
		case "MUL":
			fmt.Fprintf(s.b, "  %%%s = fmul %s %s, %s\n", t, ty, lhs.val, rhs.val)
		case "DIV":
			fmt.Fprintf(s.b, "  %%%s = fdiv %s %s, %s\n", t, ty, lhs.val, rhs.val)
		case "MIN":
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.minimum.%s(%s %s, %s %s)\n", t, ty, suf, ty, lhs.val, ty, rhs.val)
		case "MAX":
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.maximum.%s(%s %s, %s %s)\n", t, ty, suf, ty, lhs.val, ty, rhs.val)
		case "COPYSIGN":
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.copysign.%s(%s %s, %s %s)\n", t, ty, suf, ty, lhs.val, ty, rhs.val)
		}
		s.push(wasmValue{typ: ty, val: "%" + t})
		return true, nil

	case "F32ABS", "F32NEG", "F32CEIL", "F32FLOOR", "F32TRUNC", "F32NEAREST", "F32SQRT",
		"F64ABS", "F64NEG", "F64NEAREST", "F64SQRT":
		ty, suf := asm.LLVMType("float"), "f32"
		if strings.HasPrefix(op, "F64") {
			ty, suf = asm.LLVMType("double"), "f64"
		}
		v, err := s.pop(op)
		if err != nil {
			return true, err
		}
		v, err = wasmCastFloat(s, v, ty)
		if err != nil {
			return true, err
		}
		t := s.newTmp()
		switch op[3:] {
		case "NEG":
			fmt.Fprintf(s.b, "  %%%s = fneg %s %s\n", t, ty, v.val)
		case "ABS":
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.fabs.%s(%s %s)\n", t, ty, suf, ty, v.val)
		case "NEAREST":
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.roundeven.%s(%s %s)\n", t, ty, suf, ty, v.val)
		default:
			intr := strings.ToLower(op[3:])
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", t, ty, intr, suf, ty, v.val)
		}
		s.push(wasmValue{typ: ty, val: "%" + t})
		return true, nil

	case "F32EQ", "F32NE", "F32LT", "F32GT", "F32LE", "F32GE", "F64EQ", "F64LE", "F64GE":
		ty := asm.LLVMType("float")
		if strings.HasPrefix(op, "F64") {
			ty = asm.LLVMType("double")
		}
		rhs, err := s.pop(op)
		if err != nil {
			return true, err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return true, err
		}
		lhs, err = wasmCastFloat(s, lhs, ty)
		if err != nil {
			return true, err
		}
		rhs, err = wasmCastFloat(s, rhs, ty)
		if err != nil {
			return true, err
		}
		pred := map[string]string{"EQ": "oeq", "NE": "une", "LT": "olt", "GT": "ogt", "LE": "ole", "GE": "oge"}[op[3:]]
		cmp, out := s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = fcmp %s %s %s, %s\n", cmp, pred, ty, lhs.val, rhs.val)
		fmt.Fprintf(s.b, "  %%%s = zext i1 %%%s to i32\n", out, cmp)
		s.push(wasmValue{typ: asm.I32, val: "%" + out})
		return true, nil

	case "I32TRUNCF32S", "I32TRUNCF32U", "I32TRUNCF64S", "I32TRUNCF64U",
		"I64TRUNCF32S", "I64TRUNCF32U",
		"I32TRUNCSATF32S", "I32TRUNCSATF32U", "I32TRUNCSATF64S", "I32TRUNCSATF64U",
		"I64TRUNCSATF32S", "I64TRUNCSATF32U", "I64TRUNCSATF64S", "I64TRUNCSATF64U":
		dstTy := asm.I32
		if strings.HasPrefix(op, "I64") {
			dstTy = asm.I64
		}
		srcTy, srcSuf := asm.LLVMType("float"), "f32"
		if strings.Contains(op, "F64") {
			srcTy, srcSuf = asm.LLVMType("double"), "f64"
		}
		signed := strings.HasSuffix(op, "S")
		sat := strings.Contains(op, "SAT")
		v, err := s.pop(op)
		if err != nil {
			return true, err
		}
		v, err = wasmCastFloat(s, v, srcTy)
		if err != nil {
			return true, err
		}
		if sat {
			t := s.newTmp()
			fn := "fptoui.sat"
			if signed {
				fn = "fptosi.sat"
			}
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.%s.%s.%s(%s %s)\n", t, dstTy, fn, dstTy, srcSuf, srcTy, v.val)
			s.push(wasmValue{typ: dstTy, val: "%" + t})
		} else {
			res := emitWasmCheckedFloatTrunc(s.b, s.newTmp, srcTy, dstTy, signed, v.val)
			s.push(wasmValue{typ: dstTy, val: res})
		}
		return true, nil

	case "F32CONVERTI32S", "F32CONVERTI32U", "F32CONVERTI64S", "F32CONVERTI64U",
		"F64CONVERTI32S", "F64CONVERTI32U", "F64CONVERTI64S", "F64CONVERTI64U":
		dstTy := asm.LLVMType("float")
		if strings.HasPrefix(op, "F64") {
			dstTy = asm.LLVMType("double")
		}
		srcTy := asm.I32
		if strings.Contains(op, "I64") {
			srcTy = asm.I64
		}
		fn := "uitofp"
		if strings.HasSuffix(op, "S") {
			fn = "sitofp"
		}
		v, err := s.pop(op)
		if err != nil {
			return true, err
		}
		v, err = s.cast(v, srcTy, false)
		if err != nil {
			return true, err
		}
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = %s %s %s to %s\n", t, fn, srcTy, v.val, dstTy)
		s.push(wasmValue{typ: dstTy, val: "%" + t})
		return true, nil

	case "F32DEMOTEF64":
		v, err := s.pop(op)
		if err != nil {
			return true, err
		}
		v, err = wasmCastFloat(s, v, asm.LLVMType("double"))
		if err != nil {
			return true, err
		}
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = fptrunc double %s to float\n", t, v.val)
		s.push(wasmValue{typ: asm.LLVMType("float"), val: "%" + t})
		return true, nil

	case "F64PROMOTEF32":
		v, err := s.pop(op)
		if err != nil {
			return true, err
		}
		v, err = wasmCastFloat(s, v, asm.LLVMType("float"))
		if err != nil {
			return true, err
		}
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = fpext float %s to double\n", t, v.val)
		s.push(wasmValue{typ: asm.LLVMType("double"), val: "%" + t})
		return true, nil

	case "I32REINTERPRETF32", "I64REINTERPRETF64", "F32REINTERPRETI32", "F64REINTERPRETI64":
		var srcTy, dstTy asm.LLVMType
		switch op {
		case "I32REINTERPRETF32":
			srcTy, dstTy = asm.LLVMType("float"), asm.I32
		case "I64REINTERPRETF64":
			srcTy, dstTy = asm.LLVMType("double"), asm.I64
		case "F32REINTERPRETI32":
			srcTy, dstTy = asm.I32, asm.LLVMType("float")
		default:
			srcTy, dstTy = asm.I64, asm.LLVMType("double")
		}
		v, err := s.pop(op)
		if err != nil {
			return true, err
		}
		if srcTy == asm.I32 || srcTy == asm.I64 {
			v, err = s.cast(v, srcTy, false)
		} else {
			v, err = wasmCastFloat(s, v, srcTy)
		}
		if err != nil {
			return true, err
		}
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %s to %s\n", t, srcTy, v.val, dstTy)
		s.push(wasmValue{typ: dstTy, val: "%" + t})
		return true, nil

	// 3. Unmodeled bulk memory passive segments, table ops, and assembler/compiler pseudo-ops
	// must fail explicitly rather than silently dropping instructions or fabricating 0/-1.
	case "DATADROP", "ELEMDROP", "MEMORYINIT", "TABLEINIT", "TABLECOPY", "TABLEFILL", "TABLESIZE", "TABLEGROW":
		return true, fmt.Errorf("wasm: %s is not supported (passive data/elem segments and tables are not modeled)", ins.Op)
	case "RESUMEPOINT", "WORD":
		return true, fmt.Errorf("wasm: %s is not supported", ins.Op)
	}

	// 4. WebAssembly SIMD128 (V128 / I8X16 / I16X8 / I32X4 / I64X2 / F32X4 / F64X2)
	if strings.HasPrefix(op, "V128") || strings.HasPrefix(op, "I8X16") || strings.HasPrefix(op, "I16X8") ||
		strings.HasPrefix(op, "I32X4") || strings.HasPrefix(op, "I64X2") ||
		strings.HasPrefix(op, "F32X4") || strings.HasPrefix(op, "F64X2") {
		return true, s.lowerSIMD128(op, ins)
	}
	return false, nil
}

func wasmVecShape(op string) (vecTy asm.LLVMType, elemTy asm.LLVMType, lanes int, isFloat bool, suf string) {
	switch {
	case strings.HasPrefix(op, "I8X16"):
		return "<16 x i8>", asm.I8, 16, false, "v16i8"
	case strings.HasPrefix(op, "I16X8"):
		return "<8 x i16>", asm.I16, 8, false, "v8i16"
	case strings.HasPrefix(op, "I32X4"):
		return "<4 x i32>", asm.I32, 4, false, "v4i32"
	case strings.HasPrefix(op, "I64X2"):
		return "<2 x i64>", asm.I64, 2, false, "v2i64"
	case strings.HasPrefix(op, "F32X4"):
		return "<4 x float>", "float", 4, true, "v4f32"
	case strings.HasPrefix(op, "F64X2"):
		return "<2 x double>", "double", 2, true, "v2f64"
	default:
		return "<16 x i8>", asm.I8, 16, false, "v16i8"
	}
}

func wasmLane(arg asm.Operand, lanes int) (int, error) {
	if arg.Kind != asm.OpImm || arg.ImmRaw != "" || arg.Imm < 0 || arg.Imm >= int64(lanes) {
		return 0, fmt.Errorf("expected lane index in [0,%d), got %s", lanes, arg)
	}
	return int(arg.Imm), nil
}

func wasmVectorOffset(args []asm.Operand) (int64, error) {
	if len(args) == 0 {
		return 0, nil
	}
	if len(args) != 1 || args[0].Kind != asm.OpImm || args[0].ImmRaw != "" {
		return 0, fmt.Errorf("expected an unsigned wasm32 memory offset")
	}
	return args[0].Imm, nil
}

func (s *wasmExtState) lowerSIMD128(op string, ins asm.Instr) error {
	v128 := asm.LLVMType("<16 x i8>")
	// V128 constants, loads, stores, bitwise
	switch op {
	case "V128CONST":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpImm || ins.Args[0].ImmRaw != "" || ins.Args[1].ImmRaw != "" {
			return fmt.Errorf("V128Const requires two integer immediates")
		}
		lo, hi := ins.Args[0].Imm, ins.Args[1].Imm
		v0, v1, bc := s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = insertelement <2 x i64> undef, i64 %d, i32 0\n", v0, lo)
		fmt.Fprintf(s.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %d, i32 1\n", v1, v0, hi)
		fmt.Fprintf(s.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, v1)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "V128LOAD", "V128LOAD32ZERO", "V128LOAD64ZERO",
		"V128LOAD8SPLAT", "V128LOAD16SPLAT", "V128LOAD32SPLAT", "V128LOAD64SPLAT",
		"V128LOAD8X8S", "V128LOAD8X8U", "V128LOAD16X4S", "V128LOAD16X4U", "V128LOAD32X2S", "V128LOAD32X2U":
		off, err := wasmVectorOffset(ins.Args)
		if err != nil {
			return err
		}
		addr, err := s.pop(op)
		if err != nil {
			return err
		}
		addr, err = s.addressPtr(addr, off)
		if err != nil {
			return err
		}
		// Check the original access width even when LLVM extracts just one
		// widened lane or legalizes the vector to multiple scalar loads.
		size := "8"
		switch op {
		case "V128LOAD":
			size = "16"
		case "V128LOAD8SPLAT":
			size = "1"
		case "V128LOAD16SPLAT":
			size = "2"
		case "V128LOAD32ZERO", "V128LOAD32SPLAT":
			size = "4"
		}
		emitBulkBoundsCheck(s.b, s.newTmp, size, addr.val)
		switch op {
		case "V128LOAD":
			t := s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = load volatile <16 x i8>, ptr %s, align 1\n", t, addr.val)
			s.push(wasmValue{typ: v128, val: "%" + t})
		case "V128LOAD32ZERO", "V128LOAD64ZERO":
			elTy, vecTy := "i32", "<4 x i32>"
			if op == "V128LOAD64ZERO" {
				elTy, vecTy = "i64", "<2 x i64>"
			}
			ld, ins0, bc := s.newTmp(), s.newTmp(), s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = load volatile %s, ptr %s, align 1\n", ld, elTy, addr.val)
			fmt.Fprintf(s.b, "  %%%s = insertelement %s zeroinitializer, %s %%%s, i32 0\n", ins0, vecTy, elTy, ld)
			fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, ins0)
			s.push(wasmValue{typ: v128, val: "%" + bc})
		case "V128LOAD8SPLAT", "V128LOAD16SPLAT", "V128LOAD32SPLAT", "V128LOAD64SPLAT":
			bits, lanes := 8, 16
			switch op {
			case "V128LOAD16SPLAT":
				bits, lanes = 16, 8
			case "V128LOAD32SPLAT":
				bits, lanes = 32, 4
			case "V128LOAD64SPLAT":
				bits, lanes = 64, 2
			}
			elTy := fmt.Sprintf("i%d", bits)
			vecTy := fmt.Sprintf("<%d x %s>", lanes, elTy)
			ld, ins0, sp, bc := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = load volatile %s, ptr %s, align 1\n", ld, elTy, addr.val)
			fmt.Fprintf(s.b, "  %%%s = insertelement %s undef, %s %%%s, i32 0\n", ins0, vecTy, elTy, ld)
			fmt.Fprintf(s.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", sp, vecTy, ins0, vecTy, lanes)
			fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, sp)
			s.push(wasmValue{typ: v128, val: "%" + bc})
		default:
			extOp := "zext"
			if strings.HasSuffix(op, "S") {
				extOp = "sext"
			}
			srcTy, dstTy := "<8 x i8>", "<8 x i16>"
			if strings.Contains(op, "16X4") {
				srcTy, dstTy = "<4 x i16>", "<4 x i32>"
			} else if strings.Contains(op, "32X2") {
				srcTy, dstTy = "<2 x i32>", "<2 x i64>"
			}
			ld, ex, bc := s.newTmp(), s.newTmp(), s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = load volatile %s, ptr %s, align 1\n", ld, srcTy, addr.val)
			fmt.Fprintf(s.b, "  %%%s = %s %s %%%s to %s\n", ex, extOp, srcTy, ld, dstTy)
			fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, dstTy, ex)
			s.push(wasmValue{typ: v128, val: "%" + bc})
		}
		return nil

	case "V128STORE":
		off, err := wasmVectorOffset(ins.Args)
		if err != nil {
			return err
		}
		val, err := s.pop(op)
		if err != nil {
			return err
		}
		vb, err := s.castV128(val, v128)
		if err != nil {
			return err
		}
		addr, err := s.pop(op)
		if err != nil {
			return err
		}
		addr, err = s.addressPtr(addr, off)
		if err != nil {
			return err
		}
		emitBulkBoundsCheck(s.b, s.newTmp, "16", addr.val)
		fmt.Fprintf(s.b, "  store volatile <16 x i8> %s, ptr %s, align 1\n", vb, addr.val)
		return nil

	case "V128LOAD8LANE", "V128LOAD16LANE", "V128LOAD32LANE", "V128LOAD64LANE",
		"V128STORE8LANE", "V128STORE16LANE", "V128STORE32LANE", "V128STORE64LANE":
		bits, lanes := 8, 16
		switch {
		case strings.Contains(op, "16"):
			bits, lanes = 16, 8
		case strings.Contains(op, "32"):
			bits, lanes = 32, 4
		case strings.Contains(op, "64"):
			bits, lanes = 64, 2
		}
		elTy := fmt.Sprintf("i%d", bits)
		vecTy := asm.LLVMType(fmt.Sprintf("<%d x %s>", lanes, elTy))
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpImm || ins.Args[0].ImmRaw != "" {
			return fmt.Errorf("%s expects an offset and a lane", op)
		}
		off := ins.Args[0].Imm
		lane, err := wasmLane(ins.Args[1], lanes)
		if err != nil {
			return err
		}
		val, err := s.pop(op)
		if err != nil {
			return err
		}
		vv, err := s.castV128(val, vecTy)
		if err != nil {
			return err
		}
		addr, err := s.pop(op)
		if err != nil {
			return err
		}
		addr, err = s.addressPtr(addr, off)
		if err != nil {
			return err
		}
		if strings.Contains(op, "LOAD") {
			ld, insE, bc := s.newTmp(), s.newTmp(), s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = load volatile %s, ptr %s, align 1\n", ld, elTy, addr.val)
			fmt.Fprintf(s.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", insE, vecTy, vv, elTy, ld, lane)
			fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, insE)
			s.push(wasmValue{typ: v128, val: "%" + bc})
		} else {
			el := s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = extractelement %s %s, i32 %d\n", el, vecTy, vv, lane)
			fmt.Fprintf(s.b, "  store volatile %s %%%s, ptr %s, align 1\n", elTy, el, addr.val)
		}
		return nil

	case "V128NOT":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		vb, err := s.castV128(v, asm.LLVMType("<2 x i64>"))
		if err != nil {
			return err
		}
		t, bc := s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = xor <2 x i64> %s, <i64 -1, i64 -1>\n", t, vb)
		fmt.Fprintf(s.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, t)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "V128AND", "V128ANDNOT", "V128OR", "V128XOR":
		rhs, err := s.pop(op)
		if err != nil {
			return err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return err
		}
		a, err := s.castV128(lhs, asm.LLVMType("<2 x i64>"))
		if err != nil {
			return err
		}
		b, err := s.castV128(rhs, asm.LLVMType("<2 x i64>"))
		if err != nil {
			return err
		}
		t, bc := s.newTmp(), s.newTmp()
		switch op {
		case "V128AND":
			fmt.Fprintf(s.b, "  %%%s = and <2 x i64> %s, %s\n", t, a, b)
		case "V128OR":
			fmt.Fprintf(s.b, "  %%%s = or <2 x i64> %s, %s\n", t, a, b)
		case "V128XOR":
			fmt.Fprintf(s.b, "  %%%s = xor <2 x i64> %s, %s\n", t, a, b)
		case "V128ANDNOT":
			nb := s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = xor <2 x i64> %s, <i64 -1, i64 -1>\n", nb, b)
			fmt.Fprintf(s.b, "  %%%s = and <2 x i64> %s, %%%s\n", t, a, nb)
		}
		fmt.Fprintf(s.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, t)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "V128BITSELECT":
		c, err := s.pop(op)
		if err != nil {
			return err
		}
		v2, err := s.pop(op)
		if err != nil {
			return err
		}
		v1, err := s.pop(op)
		if err != nil {
			return err
		}
		cv, err := s.castV128(c, asm.LLVMType("<2 x i64>"))
		if err != nil {
			return err
		}
		a, err := s.castV128(v1, asm.LLVMType("<2 x i64>"))
		if err != nil {
			return err
		}
		b, err := s.castV128(v2, asm.LLVMType("<2 x i64>"))
		if err != nil {
			return err
		}
		nc, p1, p2, res, bc := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = xor <2 x i64> %s, <i64 -1, i64 -1>\n", nc, cv)
		fmt.Fprintf(s.b, "  %%%s = and <2 x i64> %s, %s\n", p1, a, cv)
		fmt.Fprintf(s.b, "  %%%s = and <2 x i64> %s, %%%s\n", p2, b, nc)
		fmt.Fprintf(s.b, "  %%%s = or <2 x i64> %%%s, %%%s\n", res, p1, p2)
		fmt.Fprintf(s.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, res)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "V128ANYTRUE":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		vb, err := s.castV128(v, asm.LLVMType("<2 x i64>"))
		if err != nil {
			return err
		}
		e0, e1, orv, cmp, out := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = extractelement <2 x i64> %s, i32 0\n", e0, vb)
		fmt.Fprintf(s.b, "  %%%s = extractelement <2 x i64> %s, i32 1\n", e1, vb)
		fmt.Fprintf(s.b, "  %%%s = or i64 %%%s, %%%s\n", orv, e0, e1)
		fmt.Fprintf(s.b, "  %%%s = icmp ne i64 %%%s, 0\n", cmp, orv)
		fmt.Fprintf(s.b, "  %%%s = zext i1 %%%s to i32\n", out, cmp)
		s.push(wasmValue{typ: asm.I32, val: "%" + out})
		return nil
	}

	if strings.HasPrefix(op, "V128") {
		return fmt.Errorf("unsupported wasm SIMD instruction %s", op)
	}
	vecTy, elemTy, lanes, isFloat, suf := wasmVecShape(op)
	suffix := op[5:]
	if !wasmVecSupports(suffix, lanes, isFloat) {
		return fmt.Errorf("unsupported wasm SIMD instruction %s", op)
	}

	// Splat / ExtractLane / ReplaceLane
	switch suffix {
	case "SPLAT":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		if isFloat {
			v, err = wasmCastFloat(s, v, elemTy)
		} else {
			v, err = s.cast(v, elemTy, false)
		}
		if err != nil {
			return err
		}
		ins0, sp, bc := s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = insertelement %s undef, %s %s, i32 0\n", ins0, vecTy, elemTy, v.val)
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", sp, vecTy, ins0, vecTy, lanes)
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, sp)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "EXTRACTLANE", "EXTRACTLANES", "EXTRACTLANEU":
		if len(ins.Args) != 1 {
			return fmt.Errorf("%s expects one lane index", op)
		}
		lane, err := wasmLane(ins.Args[0], lanes)
		if err != nil {
			return err
		}
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		vv, err := s.castV128(v, vecTy)
		if err != nil {
			return err
		}
		el := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = extractelement %s %s, i32 %d\n", el, vecTy, vv, lane)
		out := wasmValue{typ: elemTy, val: "%" + el}
		if elemTy == asm.I8 || elemTy == asm.I16 {
			out, err = s.cast(out, asm.I32, strings.HasSuffix(suffix, "S"))
			if err != nil {
				return err
			}
		}
		s.push(out)
		return nil

	case "REPLACELANE":
		if len(ins.Args) != 1 {
			return fmt.Errorf("%s expects one lane index", op)
		}
		lane, err := wasmLane(ins.Args[0], lanes)
		if err != nil {
			return err
		}
		sv, err := s.pop(op)
		if err != nil {
			return err
		}
		vv, err := s.pop(op)
		if err != nil {
			return err
		}
		if isFloat {
			sv, err = wasmCastFloat(s, sv, elemTy)
		} else {
			sv, err = s.cast(sv, elemTy, false)
		}
		if err != nil {
			return err
		}
		vb, err := s.castV128(vv, vecTy)
		if err != nil {
			return err
		}
		insE, bc := s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = insertelement %s %s, %s %s, i32 %d\n", insE, vecTy, vb, elemTy, sv.val, lane)
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, insE)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "ALLTRUE":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		vb, err := s.castV128(v, vecTy)
		if err != nil {
			return err
		}
		cmp, rd, out := s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = icmp ne %s %s, zeroinitializer\n", cmp, vecTy, vb)
		fmt.Fprintf(s.b, "  %%%s = call i1 @llvm.vector.reduce.and.v%di1(<%d x i1> %%%s)\n", rd, lanes, lanes, cmp)
		fmt.Fprintf(s.b, "  %%%s = zext i1 %%%s to i32\n", out, rd)
		s.push(wasmValue{typ: asm.I32, val: "%" + out})
		return nil

	case "BITMASK":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		vb, err := s.castV128(v, vecTy)
		if err != nil {
			return err
		}
		cmp, bc, out := s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", cmp, vecTy, vb)
		fmt.Fprintf(s.b, "  %%%s = bitcast <%d x i1> %%%s to i%d\n", bc, lanes, cmp, lanes)
		fmt.Fprintf(s.b, "  %%%s = zext i%d %%%s to i32\n", out, lanes, bc)
		s.push(wasmValue{typ: asm.I32, val: "%" + out})
		return nil

	case "SHL", "SHRS", "SHRU":
		sh, err := s.pop(op)
		if err != nil {
			return err
		}
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		vb, err := s.castV128(v, vecTy)
		if err != nil {
			return err
		}
		sh, err = s.cast(sh, elemTy, false)
		if err != nil {
			return err
		}
		mask := (128 / lanes) - 1
		m, ins0, sp, res, bc := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
		llvmSh := map[string]string{"SHL": "shl", "SHRS": "ashr", "SHRU": "lshr"}[suffix]
		fmt.Fprintf(s.b, "  %%%s = and %s %s, %d\n", m, elemTy, sh.val, mask)
		fmt.Fprintf(s.b, "  %%%s = insertelement %s undef, %s %%%s, i32 0\n", ins0, vecTy, elemTy, m)
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", sp, vecTy, ins0, vecTy, lanes)
		fmt.Fprintf(s.b, "  %%%s = %s %s %s, %%%s\n", res, llvmSh, vecTy, vb, sp)
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, res)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "EQ", "NE", "LT", "GT", "LE", "GE", "LTS", "LTU", "GTS", "GTU", "LES", "LEU", "GES", "GEU":
		rhs, err := s.pop(op)
		if err != nil {
			return err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return err
		}
		a, err := s.castV128(lhs, vecTy)
		if err != nil {
			return err
		}
		b, err := s.castV128(rhs, vecTy)
		if err != nil {
			return err
		}
		cmp, se, bc := s.newTmp(), s.newTmp(), s.newTmp()
		intVecTy := fmt.Sprintf("<%d x i%d>", lanes, 128/lanes)
		if isFloat {
			pred := map[string]string{"EQ": "oeq", "NE": "une", "LT": "olt", "GT": "ogt", "LE": "ole", "GE": "oge"}[suffix]
			fmt.Fprintf(s.b, "  %%%s = fcmp %s %s %s, %s\n", cmp, pred, vecTy, a, b)
		} else {
			pred := map[string]string{
				"EQ": "eq", "NE": "ne", "LTS": "slt", "LTU": "ult",
				"GTS": "sgt", "GTU": "ugt", "LES": "sle", "LEU": "ule", "GES": "sge", "GEU": "uge",
			}[suffix]
			fmt.Fprintf(s.b, "  %%%s = icmp %s %s %s, %s\n", cmp, pred, vecTy, a, b)
		}
		fmt.Fprintf(s.b, "  %%%s = sext <%d x i1> %%%s to %s\n", se, lanes, cmp, intVecTy)
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, intVecTy, se)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "ADD", "SUB", "MUL", "DIV", "ADDSATS", "ADDSATU", "SUBSATS", "SUBSATU",
		"MINS", "MINU", "MAXS", "MAXU", "MIN", "MAX", "PMIN", "PMAX", "RELAXEDMIN", "RELAXEDMAX", "AVGRU":
		rhs, err := s.pop(op)
		if err != nil {
			return err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return err
		}
		a, err := s.castV128(lhs, vecTy)
		if err != nil {
			return err
		}
		b, err := s.castV128(rhs, vecTy)
		if err != nil {
			return err
		}
		res, bc := s.newTmp(), s.newTmp()
		if isFloat {
			switch suffix {
			case "ADD", "SUB", "MUL", "DIV":
				fmt.Fprintf(s.b, "  %%%s = f%s %s %s, %s\n", res, strings.ToLower(suffix), vecTy, a, b)
			case "PMIN", "PMAX":
				// Pseudo-min/max keep the first input on equality or NaN,
				// including its signed zero or unmodified NaN payload.
				pred := "olt"
				if suffix == "PMAX" {
					pred = "ogt"
				}
				takeSecond := s.newTmp()
				fmt.Fprintf(s.b, "  %%%s = fcmp %s %s %s, %s\n", takeSecond, pred, vecTy, b, a)
				fmt.Fprintf(s.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", res, lanes, takeSecond, vecTy, b, vecTy, a)
			case "MIN", "RELAXEDMIN":
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.minimum.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			default:
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.maximum.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			}
		} else {
			switch suffix {
			case "ADD", "SUB", "MUL":
				fmt.Fprintf(s.b, "  %%%s = %s %s %s, %s\n", res, strings.ToLower(suffix), vecTy, a, b)
			case "ADDSATS":
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.sadd.sat.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			case "ADDSATU":
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.uadd.sat.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			case "SUBSATS":
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.ssub.sat.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			case "SUBSATU":
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.usub.sat.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			case "MINS":
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.smin.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			case "MINU":
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.umin.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			case "MAXS":
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.smax.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			case "MAXU":
				fmt.Fprintf(s.b, "  %%%s = call %s @llvm.umax.%s(%s %s, %s %s)\n", res, vecTy, suf, vecTy, a, vecTy, b)
			case "AVGRU":
				wideTy := fmt.Sprintf("<%d x i%d>", lanes, (128/lanes)*2)
				az, bz, sm, p1, sh := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
				fmt.Fprintf(s.b, "  %%%s = zext %s %s to %s\n", az, vecTy, a, wideTy)
				fmt.Fprintf(s.b, "  %%%s = zext %s %s to %s\n", bz, vecTy, b, wideTy)
				fmt.Fprintf(s.b, "  %%%s = add %s %%%s, %%%s\n", sm, wideTy, az, bz)
				one := make([]string, lanes)
				for i := range one {
					one[i] = fmt.Sprintf("i%d 1", (128/lanes)*2)
				}
				fmt.Fprintf(s.b, "  %%%s = add %s %%%s, <%s>\n", p1, wideTy, sm, strings.Join(one, ", "))
				fmt.Fprintf(s.b, "  %%%s = lshr %s %%%s, <%s>\n", sh, wideTy, p1, strings.Join(one, ", "))
				fmt.Fprintf(s.b, "  %%%s = trunc %s %%%s to %s\n", res, wideTy, sh, vecTy)
			}
		}
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, res)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "ABS", "NEG", "POPCNT", "SQRT", "CEIL", "FLOOR", "TRUNC", "NEAREST":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		a, err := s.castV128(v, vecTy)
		if err != nil {
			return err
		}
		res, bc := s.newTmp(), s.newTmp()
		switch {
		case isFloat && suffix == "NEG":
			fmt.Fprintf(s.b, "  %%%s = fneg %s %s\n", res, vecTy, a)
		case isFloat && suffix == "ABS":
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.fabs.%s(%s %s)\n", res, vecTy, suf, vecTy, a)
		case isFloat && suffix == "NEAREST":
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.roundeven.%s(%s %s)\n", res, vecTy, suf, vecTy, a)
		case isFloat:
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", res, vecTy, strings.ToLower(suffix), suf, vecTy, a)
		case suffix == "NEG":
			fmt.Fprintf(s.b, "  %%%s = sub %s zeroinitializer, %s\n", res, vecTy, a)
		case suffix == "ABS":
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.abs.%s(%s %s, i1 false)\n", res, vecTy, suf, vecTy, a)
		default: // POPCNT
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.ctpop.%s(%s %s)\n", res, vecTy, suf, vecTy, a)
		}
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, res)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "RELAXEDMADD", "RELAXEDNMADD", "RELAXEDLANESELECT":
		c, err := s.pop(op)
		if err != nil {
			return err
		}
		b, err := s.pop(op)
		if err != nil {
			return err
		}
		a, err := s.pop(op)
		if err != nil {
			return err
		}
		av, err := s.castV128(a, vecTy)
		if err != nil {
			return err
		}
		bv, err := s.castV128(b, vecTy)
		if err != nil {
			return err
		}
		cv, err := s.castV128(c, vecTy)
		if err != nil {
			return err
		}
		res, bc := s.newTmp(), s.newTmp()
		if suffix == "RELAXEDLANESELECT" {
			cmp := s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", cmp, vecTy, cv)
			fmt.Fprintf(s.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", res, lanes, cmp, vecTy, av, vecTy, bv)
		} else {
			if suffix == "RELAXEDNMADD" {
				na := s.newTmp()
				fmt.Fprintf(s.b, "  %%%s = fneg %s %s\n", na, vecTy, av)
				av = "%" + na
			}
			fmt.Fprintf(s.b, "  %%%s = call %s @llvm.fma.%s(%s %s, %s %s, %s %s)\n", res, vecTy, suf, vecTy, av, vecTy, bv, vecTy, cv)
		}
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, res)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil
	case "SHUFFLE", "SHUFFLE16":
		if op != "I8X16SHUFFLE" && op != "I8X16SHUFFLE16" {
			return fmt.Errorf("wasm: unsupported SIMD128 instruction %s", ins.Op)
		}
		rhs, err := s.pop(op)
		if err != nil {
			return err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return err
		}
		a, err := s.castV128(lhs, v128)
		if err != nil {
			return err
		}
		b, err := s.castV128(rhs, v128)
		if err != nil {
			return err
		}
		if len(ins.Args) != 16 {
			return fmt.Errorf("%s expects 16 lane indices", op)
		}
		mask := make([]string, 16)
		for i, arg := range ins.Args {
			idx, err := wasmLane(arg, 32)
			if err != nil {
				return err
			}
			mask[i] = fmt.Sprintf("i32 %d", idx)
		}
		t := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <16 x i32> <%s>\n",
			t, a, b, strings.Join(mask, ", "))
		s.push(wasmValue{typ: v128, val: "%" + t})
		return nil

	case "SWIZZLE", "RELAXEDSWIZZLE":
		if op != "I8X16SWIZZLE" && op != "I8X16RELAXEDSWIZZLE" {
			return fmt.Errorf("wasm: unsupported SIMD128 instruction %s", ins.Op)
		}
		idxV, err := s.pop(op)
		if err != nil {
			return err
		}
		srcV, err := s.pop(op)
		if err != nil {
			return err
		}
		a, err := s.castV128(srcV, v128)
		if err != nil {
			return err
		}
		idxB, err := s.castV128(idxV, v128)
		if err != nil {
			return err
		}
		acc := "zeroinitializer"
		for i := 0; i < 16; i++ {
			ix, inR, safeIx, el, val, insE := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = extractelement <16 x i8> %s, i32 %d\n", ix, idxB, i)
			fmt.Fprintf(s.b, "  %%%s = icmp ult i8 %%%s, 16\n", inR, ix)
			fmt.Fprintf(s.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 0\n", safeIx, inR, ix)
			fmt.Fprintf(s.b, "  %%%s = extractelement <16 x i8> %s, i8 %%%s\n", el, a, safeIx)
			fmt.Fprintf(s.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 0\n", val, inR, el)
			fmt.Fprintf(s.b, "  %%%s = insertelement <16 x i8> %s, i8 %%%s, i32 %d\n", insE, acc, val, i)
			acc = "%" + insE
		}
		s.push(wasmValue{typ: v128, val: acc})
		return nil

	case "EXTENDLOWI8X16S", "EXTENDLOWI8X16U", "EXTENDHIGHI8X16S", "EXTENDHIGHI8X16U",
		"EXTENDLOWI16X8S", "EXTENDLOWI16X8U", "EXTENDHIGHI16X8S", "EXTENDHIGHI16X8U",
		"EXTENDLOWI32X4S", "EXTENDLOWI32X4U", "EXTENDHIGHI32X4S", "EXTENDHIGHI32X4U":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		srcBits := (128 / lanes) / 2
		srcLanes := lanes * 2
		srcFullTy := asm.LLVMType(fmt.Sprintf("<%d x i%d>", srcLanes, srcBits))
		srcHalfTy := fmt.Sprintf("<%d x i%d>", lanes, srcBits)
		sv, err := s.castV128(v, srcFullTy)
		if err != nil {
			return err
		}
		start := 0
		if strings.Contains(suffix, "HIGH") {
			start = lanes
		}
		mask := make([]string, lanes)
		for i := 0; i < lanes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", start+i)
		}
		extOp := "zext"
		if strings.HasSuffix(suffix, "S") {
			extOp = "sext"
		}
		half, ex, bc := s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n",
			half, srcFullTy, sv, srcFullTy, lanes, strings.Join(mask, ", "))
		fmt.Fprintf(s.b, "  %%%s = %s %s %%%s to %s\n", ex, extOp, srcHalfTy, half, vecTy)
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, ex)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "EXTMULLOWI8X16S", "EXTMULLOWI8X16U", "EXTMULHIGHI8X16S", "EXTMULHIGHI8X16U",
		"EXTMULLOWI16X8S", "EXTMULLOWI16X8U", "EXTMULHIGHI16X8S", "EXTMULHIGHI16X8U",
		"EXTMULLOWI32X4S", "EXTMULLOWI32X4U", "EXTMULHIGHI32X4S", "EXTMULHIGHI32X4U":
		rhs, err := s.pop(op)
		if err != nil {
			return err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return err
		}
		srcBits := (128 / lanes) / 2
		srcLanes := lanes * 2
		srcFullTy := asm.LLVMType(fmt.Sprintf("<%d x i%d>", srcLanes, srcBits))
		srcHalfTy := fmt.Sprintf("<%d x i%d>", lanes, srcBits)
		av, err := s.castV128(lhs, srcFullTy)
		if err != nil {
			return err
		}
		bv, err := s.castV128(rhs, srcFullTy)
		if err != nil {
			return err
		}
		start := 0
		if strings.Contains(suffix, "HIGH") {
			start = lanes
		}
		mask := make([]string, lanes)
		for i := 0; i < lanes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", start+i)
		}
		extOp := "zext"
		if strings.HasSuffix(suffix, "S") {
			extOp = "sext"
		}
		ah, bh, ae, be, mul, bc := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n",
			ah, srcFullTy, av, srcFullTy, lanes, strings.Join(mask, ", "))
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n",
			bh, srcFullTy, bv, srcFullTy, lanes, strings.Join(mask, ", "))
		fmt.Fprintf(s.b, "  %%%s = %s %s %%%s to %s\n", ae, extOp, srcHalfTy, ah, vecTy)
		fmt.Fprintf(s.b, "  %%%s = %s %s %%%s to %s\n", be, extOp, srcHalfTy, bh, vecTy)
		fmt.Fprintf(s.b, "  %%%s = mul %s %%%s, %%%s\n", mul, vecTy, ae, be)
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, mul)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "EXTADDPAIRWISEI8X16S", "EXTADDPAIRWISEI8X16U",
		"EXTADDPAIRWISEI16X8S", "EXTADDPAIRWISEI16X8U":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		srcBits := (128 / lanes) / 2
		srcLanes := lanes * 2
		srcFullTy := asm.LLVMType(fmt.Sprintf("<%d x i%d>", srcLanes, srcBits))
		srcHalfTy := fmt.Sprintf("<%d x i%d>", lanes, srcBits)
		sv, err := s.castV128(v, srcFullTy)
		if err != nil {
			return err
		}
		evenM, oddM := make([]string, lanes), make([]string, lanes)
		for i := 0; i < lanes; i++ {
			evenM[i] = fmt.Sprintf("i32 %d", 2*i)
			oddM[i] = fmt.Sprintf("i32 %d", 2*i+1)
		}
		extOp := "zext"
		if strings.HasSuffix(suffix, "S") {
			extOp = "sext"
		}
		ev, od, ee, oe, sm, bc := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n",
			ev, srcFullTy, sv, srcFullTy, lanes, strings.Join(evenM, ", "))
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n",
			od, srcFullTy, sv, srcFullTy, lanes, strings.Join(oddM, ", "))
		fmt.Fprintf(s.b, "  %%%s = %s %s %%%s to %s\n", ee, extOp, srcHalfTy, ev, vecTy)
		fmt.Fprintf(s.b, "  %%%s = %s %s %%%s to %s\n", oe, extOp, srcHalfTy, od, vecTy)
		fmt.Fprintf(s.b, "  %%%s = add %s %%%s, %%%s\n", sm, vecTy, ee, oe)
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, sm)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "NARROWI16X8S", "NARROWI16X8U", "NARROWI32X4S", "NARROWI32X4U":
		rhs, err := s.pop(op)
		if err != nil {
			return err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return err
		}
		dstBits := 128 / lanes
		srcBits := dstBits * 2
		halfLanes := lanes / 2
		srcTy := asm.LLVMType(fmt.Sprintf("<%d x i%d>", halfLanes, srcBits))
		halfDstTy := fmt.Sprintf("<%d x i%d>", halfLanes, dstBits)
		av, err := s.castV128(lhs, srcTy)
		if err != nil {
			return err
		}
		bv, err := s.castV128(rhs, srcTy)
		if err != nil {
			return err
		}
		signed := strings.HasSuffix(suffix, "S")
		var loLim, hiLim int64
		if signed {
			loLim = -(int64(1) << uint(dstBits-1))
			hiLim = (int64(1) << uint(dstBits-1)) - 1
		} else {
			loLim = 0
			hiLim = (int64(1) << uint(dstBits)) - 1
		}
		mkSplat := func(val int64) string {
			ps := make([]string, halfLanes)
			for i := range ps {
				ps[i] = fmt.Sprintf("i%d %d", srcBits, val)
			}
			return "<" + strings.Join(ps, ", ") + ">"
		}
		loSplat, hiSplat := mkSplat(loLim), mkSplat(hiLim)
		clampTrunc := func(x string) string {
			c1, s1, c2, s2, tr := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = icmp slt %s %s, %s\n", c1, srcTy, x, loSplat)
			fmt.Fprintf(s.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", s1, halfLanes, c1, srcTy, loSplat, srcTy, x)
			fmt.Fprintf(s.b, "  %%%s = icmp sgt %s %%%s, %s\n", c2, srcTy, s1, hiSplat)
			fmt.Fprintf(s.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n", s2, halfLanes, c2, srcTy, hiSplat, srcTy, s1)
			fmt.Fprintf(s.b, "  %%%s = trunc %s %%%s to %s\n", tr, srcTy, s2, halfDstTy)
			return "%" + tr
		}
		ta, tb := clampTrunc(av), clampTrunc(bv)
		catMask := make([]string, lanes)
		for i := 0; i < lanes; i++ {
			catMask[i] = fmt.Sprintf("i32 %d", i)
		}
		cat, bc := s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s %s, <%d x i32> <%s>\n",
			cat, halfDstTy, ta, halfDstTy, tb, lanes, strings.Join(catMask, ", "))
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, cat)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "DOTI16X8S", "RELAXEDDOTI8X16I7X16S":
		rhs, err := s.pop(op)
		if err != nil {
			return err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return err
		}
		srcBits := (128 / lanes) / 2
		srcLanes := lanes * 2
		srcFullTy := asm.LLVMType(fmt.Sprintf("<%d x i%d>", srcLanes, srcBits))
		srcHalfTy := fmt.Sprintf("<%d x i%d>", lanes, srcBits)
		av, err := s.castV128(lhs, srcFullTy)
		if err != nil {
			return err
		}
		bv, err := s.castV128(rhs, srcFullTy)
		if err != nil {
			return err
		}
		evenM, oddM := make([]string, lanes), make([]string, lanes)
		for i := 0; i < lanes; i++ {
			evenM[i] = fmt.Sprintf("i32 %d", 2*i)
			oddM[i] = fmt.Sprintf("i32 %d", 2*i+1)
		}
		a0, a1, b0, b1 := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
		ae0, ae1, be0, be1 := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
		p0, p1, sm, bc := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", a0, srcFullTy, av, srcFullTy, lanes, strings.Join(evenM, ", "))
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", a1, srcFullTy, av, srcFullTy, lanes, strings.Join(oddM, ", "))
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", b0, srcFullTy, bv, srcFullTy, lanes, strings.Join(evenM, ", "))
		fmt.Fprintf(s.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", b1, srcFullTy, bv, srcFullTy, lanes, strings.Join(oddM, ", "))
		fmt.Fprintf(s.b, "  %%%s = sext %s %%%s to %s\n", ae0, srcHalfTy, a0, vecTy)
		fmt.Fprintf(s.b, "  %%%s = sext %s %%%s to %s\n", ae1, srcHalfTy, a1, vecTy)
		fmt.Fprintf(s.b, "  %%%s = sext %s %%%s to %s\n", be0, srcHalfTy, b0, vecTy)
		fmt.Fprintf(s.b, "  %%%s = sext %s %%%s to %s\n", be1, srcHalfTy, b1, vecTy)
		fmt.Fprintf(s.b, "  %%%s = mul %s %%%s, %%%s\n", p0, vecTy, ae0, be0)
		fmt.Fprintf(s.b, "  %%%s = mul %s %%%s, %%%s\n", p1, vecTy, ae1, be1)
		fmt.Fprintf(s.b, "  %%%s = add %s %%%s, %%%s\n", sm, vecTy, p0, p1)
		fmt.Fprintf(s.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bc, vecTy, sm)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "RELAXEDDOTI8X16I7X16ADDS":
		accV, err := s.pop(op)
		if err != nil {
			return err
		}
		rhs, err := s.pop(op)
		if err != nil {
			return err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return err
		}
		av, err := s.castV128(lhs, v128)
		if err != nil {
			return err
		}
		bv, err := s.castV128(rhs, v128)
		if err != nil {
			return err
		}
		cv, err := s.castV128(accV, asm.LLVMType("<4 x i32>"))
		if err != nil {
			return err
		}
		cur := cv
		for k := 0; k < 4; k++ {
			m := fmt.Sprintf("<i32 %d, i32 %d, i32 %d, i32 %d>", k, 4+k, 8+k, 12+k)
			as, bs, ae, be, p, sm := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
			fmt.Fprintf(s.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> poison, <4 x i32> %s\n", as, av, m)
			fmt.Fprintf(s.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> poison, <4 x i32> %s\n", bs, bv, m)
			fmt.Fprintf(s.b, "  %%%s = sext <4 x i8> %%%s to <4 x i32>\n", ae, as)
			fmt.Fprintf(s.b, "  %%%s = sext <4 x i8> %%%s to <4 x i32>\n", be, bs)
			fmt.Fprintf(s.b, "  %%%s = mul <4 x i32> %%%s, %%%s\n", p, ae, be)
			fmt.Fprintf(s.b, "  %%%s = add <4 x i32> %s, %%%s\n", sm, cur, p)
			cur = "%" + sm
		}
		bc := s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = bitcast <4 x i32> %s to <16 x i8>\n", bc, cur)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "Q15MULRSATS", "RELAXEDQ15MULRS":
		rhs, err := s.pop(op)
		if err != nil {
			return err
		}
		lhs, err := s.pop(op)
		if err != nil {
			return err
		}
		av, err := s.castV128(lhs, asm.LLVMType("<8 x i16>"))
		if err != nil {
			return err
		}
		bv, err := s.castV128(rhs, asm.LLVMType("<8 x i16>"))
		if err != nil {
			return err
		}
		ae, be, prod, rnd, sh, cHi, clamped, tr, bc := s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = sext <8 x i16> %s to <8 x i32>\n", ae, av)
		fmt.Fprintf(s.b, "  %%%s = sext <8 x i16> %s to <8 x i32>\n", be, bv)
		fmt.Fprintf(s.b, "  %%%s = mul <8 x i32> %%%s, %%%s\n", prod, ae, be)
		fmt.Fprintf(s.b, "  %%%s = add <8 x i32> %%%s, <i32 16384, i32 16384, i32 16384, i32 16384, i32 16384, i32 16384, i32 16384, i32 16384>\n", rnd, prod)
		fmt.Fprintf(s.b, "  %%%s = ashr <8 x i32> %%%s, <i32 15, i32 15, i32 15, i32 15, i32 15, i32 15, i32 15, i32 15>\n", sh, rnd)
		fmt.Fprintf(s.b, "  %%%s = icmp sgt <8 x i32> %%%s, <i32 32767, i32 32767, i32 32767, i32 32767, i32 32767, i32 32767, i32 32767, i32 32767>\n", cHi, sh)
		fmt.Fprintf(s.b, "  %%%s = select <8 x i1> %%%s, <8 x i32> <i32 32767, i32 32767, i32 32767, i32 32767, i32 32767, i32 32767, i32 32767, i32 32767>, <8 x i32> %%%s\n", clamped, cHi, sh)
		fmt.Fprintf(s.b, "  %%%s = trunc <8 x i32> %%%s to <8 x i16>\n", tr, clamped)
		fmt.Fprintf(s.b, "  %%%s = bitcast <8 x i16> %%%s to <16 x i8>\n", bc, tr)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "CONVERTI32X4S", "CONVERTI32X4U":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		iv, err := s.castV128(v, asm.LLVMType("<4 x i32>"))
		if err != nil {
			return err
		}
		cvt := "uitofp"
		if strings.HasSuffix(suffix, "S") {
			cvt = "sitofp"
		}
		res, bc := s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = %s <4 x i32> %s to <4 x float>\n", res, cvt, iv)
		fmt.Fprintf(s.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", bc, res)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "CONVERTLOWI32X4S", "CONVERTLOWI32X4U":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		iv, err := s.castV128(v, asm.LLVMType("<4 x i32>"))
		if err != nil {
			return err
		}
		cvt := "uitofp"
		if strings.HasSuffix(suffix, "S") {
			cvt = "sitofp"
		}
		lo, res, bc := s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = shufflevector <4 x i32> %s, <4 x i32> poison, <2 x i32> <i32 0, i32 1>\n", lo, iv)
		fmt.Fprintf(s.b, "  %%%s = %s <2 x i32> %%%s to <2 x double>\n", res, cvt, lo)
		fmt.Fprintf(s.b, "  %%%s = bitcast <2 x double> %%%s to <16 x i8>\n", bc, res)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "DEMOTEF64X2ZERO":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		fv, err := s.castV128(v, asm.LLVMType("<2 x double>"))
		if err != nil {
			return err
		}
		tr, pad, bc := s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = fptrunc <2 x double> %s to <2 x float>\n", tr, fv)
		fmt.Fprintf(s.b, "  %%%s = shufflevector <2 x float> %%%s, <2 x float> zeroinitializer, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n", pad, tr)
		fmt.Fprintf(s.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", bc, pad)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "PROMOTELOWF32X4":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		fv, err := s.castV128(v, asm.LLVMType("<4 x float>"))
		if err != nil {
			return err
		}
		lo, ex, bc := s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = shufflevector <4 x float> %s, <4 x float> poison, <2 x i32> <i32 0, i32 1>\n", lo, fv)
		fmt.Fprintf(s.b, "  %%%s = fpext <2 x float> %%%s to <2 x double>\n", ex, lo)
		fmt.Fprintf(s.b, "  %%%s = bitcast <2 x double> %%%s to <16 x i8>\n", bc, ex)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "TRUNCSATF32X4S", "TRUNCSATF32X4U", "RELAXEDTRUNCF32X4S", "RELAXEDTRUNCF32X4U":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		fv, err := s.castV128(v, asm.LLVMType("<4 x float>"))
		if err != nil {
			return err
		}
		fn := "fptoui.sat"
		if strings.HasSuffix(suffix, "S") {
			fn = "fptosi.sat"
		}
		res, bc := s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = call <4 x i32> @llvm.%s.v4i32.v4f32(<4 x float> %s)\n", res, fn, fv)
		fmt.Fprintf(s.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bc, res)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil

	case "TRUNCSATF64X2SZERO", "TRUNCSATF64X2UZERO", "RELAXEDTRUNCF64X2S", "RELAXEDTRUNCF64X2U", "RELAXEDTRUNCF64X2SZERO", "RELAXEDTRUNCF64X2UZERO":
		v, err := s.pop(op)
		if err != nil {
			return err
		}
		fv, err := s.castV128(v, asm.LLVMType("<2 x double>"))
		if err != nil {
			return err
		}
		fn := "fptoui.sat"
		if strings.Contains(suffix, "64X2S") {
			fn = "fptosi.sat"
		}
		res, pad, bc := s.newTmp(), s.newTmp(), s.newTmp()
		fmt.Fprintf(s.b, "  %%%s = call <2 x i32> @llvm.%s.v2i32.v2f64(<2 x double> %s)\n", res, fn, fv)
		fmt.Fprintf(s.b, "  %%%s = shufflevector <2 x i32> %%%s, <2 x i32> zeroinitializer, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n", pad, res)
		fmt.Fprintf(s.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bc, pad)
		s.push(wasmValue{typ: v128, val: "%" + bc})
		return nil
	}

	return fmt.Errorf("wasm: unsupported SIMD128 instruction %s", ins.Op)
}
