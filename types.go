package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

type Arch string

const (
	ArchAMD64 Arch = "amd64"
	ArchARM   Arch = "arm"
	ArchARM64 Arch = "arm64"
	ArchWASM  Arch = "wasm"
)

type Reg string

const (
	AX Reg = "AX"
	BX Reg = "BX"
	CX Reg = "CX"
	DX Reg = "DX"
	SI Reg = "SI"
	DI Reg = "DI"
	SP Reg = "SP"
	BP Reg = "BP"
	PC Reg = "PC"
	ES Reg = "ES"
	CS Reg = "CS"
	SS Reg = "SS"
	DS Reg = "DS"
	FS Reg = "FS"
	GS Reg = "GS"
	// TLS is the x86 thread-local-storage pseudo-register used by the Go
	// assembler both as a loadable base and as a relocation-only memory index.
	TLS Reg = "TLS"

	AL   Reg = "AL"
	AH   Reg = "AH"
	BL   Reg = "BL"
	BH   Reg = "BH"
	CL   Reg = "CL"
	CH   Reg = "CH"
	DL   Reg = "DL"
	DH   Reg = "DH"
	BPB  Reg = "BPB"
	SIB  Reg = "SIB"
	DIB  Reg = "DIB"
	R8B  Reg = "R8B"
	R9B  Reg = "R9B"
	R10B Reg = "R10B"
	R11B Reg = "R11B"
	R12B Reg = "R12B"
	R13B Reg = "R13B"
	R14B Reg = "R14B"
	R15B Reg = "R15B"

	ZR Reg = "ZR"
)

func parseReg(s string) (Reg, bool) {
	ss := strings.ToUpper(strings.TrimSpace(s))
	switch ss {
	case "RAX":
		return AX, true
	case "RBX":
		return BX, true
	case "RCX":
		return CX, true
	case "RDX":
		return DX, true
	case "RSI":
		return SI, true
	case "RDI":
		return DI, true
	case "RSP", "ESP":
		return SP, true
	case "RBP", "EBP":
		return BP, true
	case "AX":
		return AX, true
	case "BX":
		return BX, true
	case "CX":
		return CX, true
	case "DX":
		return DX, true
	case "SI":
		return SI, true
	case "DI":
		return DI, true
	case "SP":
		return SP, true
	case "BP":
		return BP, true
	case "PC":
		return PC, true
	case "FS":
		return FS, true
	case "GS":
		return GS, true
	case "TLS":
		return TLS, true
	case "AL":
		return AL, true
	case "AH":
		return AH, true
	case "BL":
		return BL, true
	case "BH":
		return BH, true
	case "CL":
		return CL, true
	case "CH":
		return CH, true
	case "DL":
		return DL, true
	case "DH":
		return DH, true
	case "BPB":
		return BPB, true
	case "SIB":
		return SIB, true
	case "DIB":
		return DIB, true
	case "R8B":
		return R8B, true
	case "R9B":
		return R9B, true
	case "R10B":
		return R10B, true
	case "R11B":
		return R11B, true
	case "R12B":
		return R12B, true
	case "R13B":
		return R13B, true
	case "R14B":
		return R14B, true
	case "R15B":
		return R15B, true
	case "ZR":
		return ZR, true
	case "G":
		// Go arm64 asm pseudo register alias.
		return Reg("R28"), true
	case "LR":
		return Reg("R30"), true
	case "R18_PLATFORM":
		return Reg("R18"), true
	}
	if strings.HasPrefix(ss, "R") && len(ss) >= 2 {
		// AArch64 general purpose registers: R0..R31, and x86-64 integer registers R8..R15.
		if n, err := strconv.Atoi(ss[1:]); err == nil && 0 <= n && n <= 31 {
			return Reg(ss), true
		}
	}
	if strings.HasPrefix(ss, "W") && len(ss) >= 2 {
		// AArch64 32-bit aliases W0..W31 share the underlying X registers.
		if n, err := strconv.Atoi(ss[1:]); err == nil && 0 <= n && n <= 31 {
			return Reg(fmt.Sprintf("R%d", n)), true
		}
	}
	// SIMD/FP registers:
	// - x86: M0..M7, X0..X31, Y0..Y31, Z0..Z31, K0..K7
	// - arm64: V0..V31 and SVE Z0..Z31/P0..P15, with optional lane suffix
	//   (for example V0.B16, V8.D[0], Z22.B, or P10.H)
	// - arm64 FP: F0..F31
	if strings.HasPrefix(ss, "K") && len(ss) >= 2 {
		if n, err := strconv.Atoi(ss[1:]); err == nil && 0 <= n && n <= 7 {
			return Reg(ss), true
		}
	}
	if strings.HasPrefix(ss, "M") && len(ss) >= 2 {
		if n, err := strconv.Atoi(ss[1:]); err == nil && 0 <= n && n <= 7 {
			return Reg(ss), true
		}
	}
	if strings.HasPrefix(ss, "PN") && len(ss) >= 3 {
		i := 2
		for i < len(ss) && ss[i] >= '0' && ss[i] <= '9' {
			i++
		}
		if i > 2 {
			rest := ss[i:]
			if rest == "" || strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, "[") {
				return Reg(ss), true
			}
		}
	}
	if (strings.HasPrefix(ss, "X") || strings.HasPrefix(ss, "Y") || strings.HasPrefix(ss, "Z") || strings.HasPrefix(ss, "V") || strings.HasPrefix(ss, "F") || strings.HasPrefix(ss, "P")) && len(ss) >= 2 {
		i := 1
		for i < len(ss) && ss[i] >= '0' && ss[i] <= '9' {
			i++
		}
		if i > 1 {
			// Accept optional suffix for arm64 vector lanes: .B16, .D[0], etc.
			rest := ss[i:]
			if rest == "" {
				return Reg(ss), true
			}
			if strings.HasPrefix(rest, ".") || strings.HasPrefix(ss, "Z") && strings.HasPrefix(rest, "[") {
				return Reg(ss), true
			}
		}
	}
	return "", false
}

type OperandKind int

const (
	OpInvalid OperandKind = iota
	OpImm
	OpReg
	OpRegExtend
	OpRegShift
	OpFP
	OpFPAddr
	OpIdent
	OpSym
	OpLabel
	OpMem
	OpRegList
)

type ShiftOp string

const (
	ShiftLeft   ShiftOp = "<<"
	ShiftRight  ShiftOp = ">>"
	ShiftArith  ShiftOp = "->"
	ShiftRotate ShiftOp = "@>"
)

// ExtendOp is an ARM64 register-extension modifier (for example UXTB, SXTW).
// The prefix U/S selects zero- or sign-extension; the suffix B/H/W/X selects
// the source width (8/16/32/64 bits).
type ExtendOp string

const (
	ExtendUXTB ExtendOp = "UXTB"
	ExtendUXTH ExtendOp = "UXTH"
	ExtendUXTW ExtendOp = "UXTW"
	ExtendUXTX ExtendOp = "UXTX"
	ExtendSXTB ExtendOp = "SXTB"
	ExtendSXTH ExtendOp = "SXTH"
	ExtendSXTW ExtendOp = "SXTW"
	ExtendSXTX ExtendOp = "SXTX"
)

// Operand models a minimal subset of Plan 9 asm operands.
//
// Supported:
//   - Immediate: $123
//   - Register: AX, BX, ...
//   - FP slot: name+offset(FP) (used in classic Go stack ABI syntax)
type Operand struct {
	Kind OperandKind

	Imm        int64    // OpImm; floating immediates hold their float64 bit pattern
	ImmRaw     string   // OpImm unresolved symbolic placeholder, including leading '$'
	ImmIsFloat bool     // OpImm originated from a floating constant expression
	Reg        Reg      // OpReg
	Ext        ExtendOp // OpRegExtend
	// OpRegShift
	ShiftOp     ShiftOp
	ShiftAmount int64
	ShiftReg    Reg

	FPName   string // OpFP (e.g. "a", "ret")
	FPOffset int64  // OpFP

	Ident string // OpIdent (e.g. system register name in MRS)

	Sym string // OpSym / OpLabel

	// OpMem: a minimal memory addressing mode.
	// Examples:
	//   (SI)
	//   16(SI)
	//   -8(SI)(R8*1)
	//   (R0)(R6)
	Mem MemRef

	RegList      []Reg // OpRegList (e.g. (R4, R8))
	RegListRange bool  // OpRegList originated from one range (e.g. [Z4.Q-Z5.Q])
}

type MemRef struct {
	Base     Reg
	Sym      string // optional symbol-based address, including the (SB) suffix
	Off      int64
	OffRaw   string   // unresolved symbolic displacement, used by generated wasm go_asm.h offsets
	Index    Reg      // optional; empty if not present
	IndexExt ExtendOp // optional ARM64 index extension (UXTW, SXTW, UXTX, or SXTX)
	Scale    int64    // optional; defaults to 1 when Index is present
	Segment  Reg      // optional x86 segment override (FS or GS)
}

func (o Operand) String() string {
	switch o.Kind {
	case OpImm:
		if o.ImmRaw != "" {
			return o.ImmRaw
		}
		if o.ImmIsFloat {
			return "$(" + strconv.FormatFloat(math.Float64frombits(uint64(o.Imm)), 'g', -1, 64) + ")"
		}
		return fmt.Sprintf("$%d", o.Imm)
	case OpReg:
		return string(o.Reg)
	case OpRegExtend:
		suffix := ""
		if o.ShiftOp != "" {
			suffix = fmt.Sprintf("%s%d", o.ShiftOp, o.ShiftAmount)
		}
		return fmt.Sprintf("%s.%s%s", o.Reg, o.Ext, suffix)
	case OpRegShift:
		suffix := fmt.Sprintf("%d", o.ShiftAmount)
		if o.ShiftReg != "" {
			suffix = string(o.ShiftReg)
		}
		return fmt.Sprintf("%s%s%s", o.Reg, o.ShiftOp, suffix)
	case OpFP:
		return fmt.Sprintf("%s+%d(FP)", o.FPName, o.FPOffset)
	case OpFPAddr:
		return fmt.Sprintf("$%s+%d(FP)", o.FPName, o.FPOffset)
	case OpIdent:
		return o.Ident
	case OpSym:
		return o.Sym
	case OpLabel:
		return o.Sym + ":"
	case OpMem:
		// Best-effort pretty print.
		segment := ""
		if o.Mem.Segment != "" {
			segment = fmt.Sprintf("(%s)", o.Mem.Segment)
		}
		if o.Mem.Sym != "" {
			if o.Mem.Scale == 0 {
				return fmt.Sprintf("%s(%s)%s", o.Mem.Sym, o.Mem.Index, segment)
			}
			return fmt.Sprintf("%s(%s*%d)%s", o.Mem.Sym, o.Mem.Index, o.Mem.Scale, segment)
		}
		offset := fmt.Sprintf("%d", o.Mem.Off)
		if o.Mem.OffRaw != "" {
			offset = o.Mem.OffRaw
		}
		if o.Mem.Index != "" {
			if o.Mem.IndexExt != "" {
				index := fmt.Sprintf("%s.%s", o.Mem.Index, o.Mem.IndexExt)
				if o.Mem.Scale > 1 {
					index += fmt.Sprintf("<<%d", bits.TrailingZeros64(uint64(o.Mem.Scale)))
				}
				return fmt.Sprintf("%s(%s)(%s)%s", offset, o.Mem.Base, index, segment)
			}
			if o.Mem.Scale == 0 {
				return fmt.Sprintf("%s(%s)(%s)%s", offset, o.Mem.Base, o.Mem.Index, segment)
			}
			return fmt.Sprintf("%s(%s)(%s*%d)%s", offset, o.Mem.Base, o.Mem.Index, o.Mem.Scale, segment)
		}
		if o.Mem.Base == "" && o.Mem.Segment != "" {
			return fmt.Sprintf("%s%s", offset, segment)
		}
		return fmt.Sprintf("%s(%s)%s", offset, o.Mem.Base, segment)
	case OpRegList:
		parts := make([]string, 0, len(o.RegList))
		for _, r := range o.RegList {
			parts = append(parts, string(r))
		}
		return "(" + strings.Join(parts, ", ") + ")"
	default:
		return "<invalid>"
	}
}

func parseImm(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "$") {
		return 0, false
	}
	v := strings.TrimPrefix(s, "$")
	if v == "" {
		return 0, false
	}
	// Plan9 constants are typically decimal or hex. Accept 0x too.
	n, err := strconv.ParseInt(v, 0, 64)
	if err == nil {
		return n, true
	}
	// Some stdlib asm uses unsigned 64-bit immediates like 0xFFFFFFFFFFFFFFFF
	// to mean the corresponding 64-bit bit-pattern (e.g. -1). Accept those by
	// parsing as uint64 and converting to int64 (two's complement).
	u, uerr := strconv.ParseUint(v, 0, 64)
	if uerr != nil {
		// Preserve the integer meaning of constant expressions such as $64-31.
		// evalFloatExpr also accepts integer literals, so trying it first would
		// accidentally store the float64 bit pattern instead of the value 33.
		if u, ok := parseImmExpr(v); ok {
			return int64(u), true
		}
		// Floating immediates (e.g. $1.0, $6.02e23) are used by some amd64
		// scalar FP instructions. Keep parser surface small by storing raw
		// float64 bit-patterns in Imm.
		if f, ferr := strconv.ParseFloat(v, 64); ferr == nil {
			return int64(math.Float64bits(f)), true
		}
		if f, ok := parseImmFloatExpr(v); ok {
			return int64(math.Float64bits(f)), true
		}
		// Be permissive with symbolic immediates such as:
		//   $(16 + callbackArgs__size)
		// Parser/scan should accept them, but lowering must reject them
		// explicitly via Operand.ImmRaw instead of silently materializing 0.
		if isSymbolicImmPlaceholder(s) {
			return 0, true
		}
		return 0, false
	}
	return int64(u), true
}

func isSymbolicImmPlaceholder(s string) bool {
	expr := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "$"))
	if !strings.HasPrefix(expr, "(") || !strings.HasSuffix(expr, ")") {
		return false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, "("), ")"))
	return strings.ContainsAny(inner, "+-*/%<>&|^ \t")
}

func parseImmExpr(v string) (uint64, bool) {
	// Plan9 asm frequently uses C-style unary "~" for bitwise-not in immediates.
	// Go expressions use "^", so normalize before parsing.
	exprText := strings.ReplaceAll(strings.TrimSpace(v), "~", "^")
	if exprText == "" {
		return 0, false
	}
	expr, err := parser.ParseExpr(exprText)
	if err != nil {
		return 0, false
	}
	return evalImmExpr(expr)
}

func parseVectorLengthScaleExpr(v string) (int64, bool) {
	expr := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(v), " ", ""))
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	sign := int64(1)
	if strings.HasPrefix(expr, "-") {
		sign = -1
		expr = strings.TrimPrefix(expr, "-")
	} else {
		expr = strings.TrimPrefix(expr, "+")
	}
	if !strings.HasPrefix(expr, "VL*") {
		return 0, false
	}
	multiplier, err := strconv.ParseInt(strings.TrimPrefix(expr, "VL*"), 10, 64)
	if err != nil || multiplier < 0 {
		return 0, false
	}
	return sign * multiplier, true
}

func parseImmFloatExpr(v string) (float64, bool) {
	exprText := strings.TrimSpace(v)
	if exprText == "" {
		return 0, false
	}
	expr, err := parser.ParseExpr(exprText)
	if err != nil {
		return 0, false
	}
	return evalFloatExpr(expr)
}

func evalFloatExpr(e ast.Expr) (float64, bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return evalFloatExpr(x.X)
	case *ast.BasicLit:
		switch x.Kind {
		case token.FLOAT:
			f, err := strconv.ParseFloat(x.Value, 64)
			if err != nil {
				return 0, false
			}
			return f, true
		case token.INT:
			i, err := strconv.ParseInt(x.Value, 0, 64)
			if err != nil {
				return 0, false
			}
			return float64(i), true
		default:
			return 0, false
		}
	case *ast.UnaryExpr:
		v, ok := evalFloatExpr(x.X)
		if !ok {
			return 0, false
		}
		switch x.Op {
		case token.ADD:
			return v, true
		case token.SUB:
			return -v, true
		default:
			return 0, false
		}
	case *ast.BinaryExpr:
		lv, ok := evalFloatExpr(x.X)
		if !ok {
			return 0, false
		}
		rv, ok := evalFloatExpr(x.Y)
		if !ok {
			return 0, false
		}
		switch x.Op {
		case token.ADD:
			return lv + rv, true
		case token.SUB:
			return lv - rv, true
		case token.MUL:
			return lv * rv, true
		case token.QUO:
			if rv == 0 {
				return 0, false
			}
			return lv / rv, true
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func evalImmExpr(e ast.Expr) (uint64, bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return evalImmExpr(x.X)
	case *ast.BasicLit:
		if x.Kind == token.CHAR {
			if len(x.Value) < 2 || x.Value[0] != '\'' {
				return 0, false
			}
			value, _, tail, err := strconv.UnquoteChar(x.Value[1:], '\'')
			if err != nil {
				return 0, false
			}
			if tail != "'" {
				return 0, false
			}
			return uint64(value), true
		}
		if x.Kind != token.INT {
			return 0, false
		}
		if u, err := strconv.ParseUint(x.Value, 0, 64); err == nil {
			return u, true
		}
		n, err := strconv.ParseInt(x.Value, 0, 64)
		if err != nil {
			return 0, false
		}
		return uint64(n), true
	case *ast.UnaryExpr:
		v, ok := evalImmExpr(x.X)
		if !ok {
			return 0, false
		}
		switch x.Op {
		case token.ADD:
			return v, true
		case token.SUB:
			return uint64(0) - v, true
		case token.XOR:
			return ^v, true
		default:
			return 0, false
		}
	case *ast.BinaryExpr:
		lv, ok := evalImmExpr(x.X)
		if !ok {
			return 0, false
		}
		rv, ok := evalImmExpr(x.Y)
		if !ok {
			return 0, false
		}
		switch x.Op {
		case token.ADD:
			return lv + rv, true
		case token.SUB:
			return lv - rv, true
		case token.MUL:
			return lv * rv, true
		case token.QUO:
			if rv == 0 {
				return 0, false
			}
			return lv / rv, true
		case token.REM:
			if rv == 0 {
				return 0, false
			}
			return lv % rv, true
		case token.SHL:
			if rv >= 64 {
				return 0, true
			}
			return lv << rv, true
		case token.SHR:
			if rv >= 64 {
				return 0, true
			}
			return lv >> rv, true
		case token.AND:
			return lv & rv, true
		case token.OR:
			return lv | rv, true
		case token.XOR:
			return lv ^ rv, true
		case token.AND_NOT:
			return lv &^ rv, true
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func parseFP(s string) (name string, off int64, ok bool) {
	// Go accepts both name(FP) and name+off(FP) (including a negative
	// displacement). The omitted displacement is exactly zero; generated
	// assembly uses that spelling frequently for the first result slot.
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "(FP)") {
		return "", 0, false
	}
	base := strings.TrimSpace(strings.TrimSuffix(s, "(FP)"))
	if base == "" {
		return "", 0, false
	}
	name, off = splitSymPlusOff(base)
	if name == "" || strings.IndexAny(name, " \t,()") >= 0 {
		return "", 0, false
	}
	return name, off, true
}

func parseFPAddr(s string) (name string, off int64, ok bool) {
	// Minimal: $name+off(FP) (address-of FP slot).
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "$") {
		return "", 0, false
	}
	return parseFP(strings.TrimPrefix(s, "$"))
}

func parseOperand(s string) (Operand, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Operand{}, fmt.Errorf("empty operand")
	}
	// A leading '$' on a register-relative memory expression means effective
	// address, not an immediate load. Recognize this before parseImm so forms
	// such as $(-64*1024+104)(R13) are not mistaken for symbolic constants.
	if strings.HasPrefix(s, "$") {
		if _, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(s, "$"))); ok {
			return Operand{Kind: OpSym, Sym: s}, nil
		}
	}
	if imm, ok := parseImm(s); ok {
		expr := strings.TrimSpace(strings.TrimPrefix(s, "$"))
		_, integerExpression := parseImmExpr(expr)
		_, floatingExpression := parseImmFloatExpr(expr)
		op := Operand{Kind: OpImm, Imm: imm, ImmIsFloat: !integerExpression && floatingExpression}
		if isSymbolicImmPlaceholder(s) {
			expr := strings.TrimSpace(strings.TrimPrefix(s, "$"))
			if _, resolvedInt := parseImmExpr(expr); !resolvedInt {
				if _, resolvedFloat := parseImmFloatExpr(expr); !resolvedFloat {
					op.ImmRaw = s
				}
			}
		}
		return op, nil
	}
	if name, off, ok := parseFPAddr(s); ok {
		return Operand{Kind: OpFPAddr, FPName: name, FPOffset: off}, nil
	}
	if r, ext, shift, ok := parseRegExtendShift(s); ok {
		return Operand{Kind: OpRegExtend, Reg: r, Ext: ext, ShiftOp: ShiftLeft, ShiftAmount: shift}, nil
	}
	if r, ext, ok := parseRegExtend(s); ok {
		return Operand{Kind: OpRegExtend, Reg: r, Ext: ext}, nil
	}
	if base, sop, amt, shiftReg, ok := parseRegShift(s); ok {
		return Operand{Kind: OpRegShift, Reg: base, ShiftOp: sop, ShiftAmount: amt, ShiftReg: shiftReg}, nil
	}
	if r, ok := parseReg(s); ok {
		return Operand{Kind: OpReg, Reg: r}, nil
	}
	if name, off, ok := parseFP(s); ok {
		return Operand{Kind: OpFP, FPName: name, FPOffset: off}, nil
	}
	// Bracketed register list (used by some arm64 vector load/store forms):
	//   [V1.B16, V2.B16]
	//   [V0.D2, V1.D2, V2.D2, V3.D2]
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"))
		if inner == "" {
			return Operand{}, fmt.Errorf("empty reg list: %q", s)
		}
		parts := splitTopLevelCSV(inner)
		regs := make([]Reg, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			rs, ok := expandRegRange(p)
			if !ok {
				return Operand{}, fmt.Errorf("invalid reg in reg list %q: %q", s, p)
			}
			regs = append(regs, rs...)
		}
		return Operand{Kind: OpRegList, RegList: regs, RegListRange: len(parts) == 1 && strings.Contains(parts[0], "-")}, nil
	}
	// Register list: (R4, R8)
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && strings.Contains(s, ",") {
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "("), ")"))
		if inner == "" {
			return Operand{}, fmt.Errorf("empty reg list: %q", s)
		}
		parts := splitTopLevelCSV(inner)
		regs := make([]Reg, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			rs, ok := expandRegRange(p)
			if !ok {
				return Operand{}, fmt.Errorf("invalid reg in reg list %q: %q", s, p)
			}
			regs = append(regs, rs...)
		}
		return Operand{Kind: OpRegList, RegList: regs}, nil
	}
	// Memory reference: off(base)(index*scale)
	if mem, ok := parseMem(s); ok {
		return Operand{Kind: OpMem, Mem: mem}, nil
	}
	// Symbol reference: foo<>(SB), runtime·bar(SB), etc.
	if sym, ok := parseSym(s); ok {
		return Operand{Kind: OpSym, Sym: sym}, nil
	}
	// Identifier (used by some arch-specific instructions like MRS).
	if ident, ok := parseIdent(s); ok {
		return Operand{Kind: OpIdent, Ident: ident}, nil
	}
	return Operand{}, fmt.Errorf("unsupported operand: %q", s)
}

func parseRegExtend(s string) (Reg, ExtendOp, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	dot := strings.LastIndexByte(s, '.')
	if dot <= 0 || dot == len(s)-1 {
		return "", "", false
	}
	r, ok := parseReg(s[:dot])
	if !ok {
		return "", "", false
	}
	ext := ExtendOp(strings.ToUpper(strings.TrimSpace(s[dot+1:])))
	switch ext {
	case ExtendUXTB, ExtendUXTH, ExtendUXTW, ExtendUXTX,
		ExtendSXTB, ExtendSXTH, ExtendSXTW, ExtendSXTX:
		return r, ext, true
	default:
		return "", "", false
	}
}

func parseRegExtendShift(s string) (Reg, ExtendOp, int64, bool) {
	i := strings.Index(s, string(ShiftLeft))
	if i < 0 {
		return "", "", 0, false
	}
	r, ext, ok := parseRegExtend(strings.TrimSpace(s[:i]))
	if !ok {
		return "", "", 0, false
	}
	shiftText := strings.TrimSpace(s[i+len(ShiftLeft):])
	shift, err := strconv.ParseInt(shiftText, 0, 64)
	if err != nil || shift < 0 || shift > 4 {
		return "", "", 0, false
	}
	return r, ext, shift, true
}

func parseRegShift(s string) (base Reg, sop ShiftOp, amt int64, shiftReg Reg, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", 0, "", false
	}
	for _, candidate := range []ShiftOp{ShiftRotate, ShiftArith, ShiftLeft, ShiftRight} {
		i := strings.Index(s, string(candidate))
		if i < 0 {
			continue
		}
		l := strings.TrimSpace(s[:i])
		r := strings.TrimSpace(s[i+len(candidate):])
		if l == "" || r == "" {
			return "", "", 0, "", false
		}
		br, ok := parseReg(l)
		if !ok {
			return "", "", 0, "", false
		}
		if rr, ok := parseReg(r); ok {
			return br, candidate, 0, rr, true
		}
		// x/arch GoSyntax prints ARM immediate shifts with a dollar sign
		// (for example R0->$32). Accept that spelling as well as the
		// existing source form without the prefix.
		r = strings.TrimPrefix(r, "$")
		if n, err := strconv.ParseInt(r, 0, 64); err == nil {
			return br, candidate, n, "", true
		}
		if u, ok := parseImmExpr(r); ok {
			return br, candidate, int64(u), "", true
		}
		return "", "", 0, "", false
	}
	return "", "", 0, "", false
}

func expandRegRange(part string) ([]Reg, bool) {
	part = strings.TrimSpace(part)
	dash := strings.IndexByte(part, '-')
	if dash < 0 {
		r, ok := parseReg(part)
		if !ok {
			return nil, false
		}
		return []Reg{r}, true
	}
	left := strings.TrimSpace(part[:dash])
	right := strings.TrimSpace(part[dash+1:])
	lr, ok := parseReg(left)
	if !ok {
		return nil, false
	}
	rr, ok := parseReg(right)
	if !ok {
		return nil, false
	}
	lp, li, ls, ok := regRangeParts(lr)
	if !ok {
		return nil, false
	}
	rp, ri, rs, ok := regRangeParts(rr)
	if !ok || lp != rp || ls != rs {
		return nil, false
	}
	step := 1
	if li > ri {
		step = -1
	}
	out := make([]Reg, 0, absInt(li-ri)+1)
	for i := li; ; i += step {
		out = append(out, Reg(fmt.Sprintf("%s%d%s", lp, i, ls)))
		if i == ri {
			break
		}
	}
	return out, true
}

func regRangeParts(r Reg) (prefix string, idx int, suffix string, ok bool) {
	s := string(r)
	digitStart := 0
	for digitStart < len(s) && (s[digitStart] < '0' || s[digitStart] > '9') {
		digitStart++
	}
	if digitStart == 0 || digitStart == len(s) {
		return "", 0, "", false
	}
	digitEnd := digitStart
	for digitEnd < len(s) && s[digitEnd] >= '0' && s[digitEnd] <= '9' {
		digitEnd++
	}
	n, err := strconv.Atoi(s[digitStart:digitEnd])
	if err != nil {
		return "", 0, "", false
	}
	return s[:digitStart], n, s[digitEnd:], true
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

type Op string

const (
	OpTEXT   Op = "TEXT"
	OpMRS    Op = "MRS"
	OpMOVQ   Op = "MOVQ"
	OpMOVL   Op = "MOVL"
	OpADDQ   Op = "ADDQ"
	OpSUBQ   Op = "SUBQ"
	OpXORQ   Op = "XORQ"
	OpMOVD   Op = "MOVD"
	OpCPUID  Op = "CPUID"
	OpXGETBV Op = "XGETBV"
	OpBYTE   Op = "BYTE"
	OpWORD   Op = "WORD"
	OpCALL   Op = "CALL"
	OpJMP    Op = "JMP"
	OpRET    Op = "RET"
	OpLABEL  Op = "LABEL"
)

type Instr struct {
	Op   Op
	Args []Operand
	Raw  string
	// Set only by a validated machine-code decoder. Physical operands need
	// not obey textual frontend limits (e.g. Go 386's three-operand limit).
	x86Encoded bool
	// Decoded vector length, separate from register storage width. Narrowing
	// conversions can write X from either a 128- or 256-bit memory source.
	x86VectorBytes int
	// A decoder folded a same-group, unreachable RIP-relative data read. Keep
	// address-observed raw TEXT bodies on the byte-preserving path instead.
	x86RIPLiteral bool
	// A wide source-local constant is materialized as an LLVM data global by
	// normalizeX86RawFile. Retain its bytes for lowerers that can specialize
	// the constant without a memory access, after source-layout validation.
	x86RIPLiteralData []byte
	// A reachable LEA addresses an offset of a source-local raw data suffix.
	// The suffix is shared by all such LEAs in one raw directive group.
	x86RIPAddressData  []byte
	x86RIPAddressOff   int
	x86RIPAddressGroup int
}

// DataStmt models a minimal Plan 9 DATA directive:
//
//	DATA sym+off(SB)/width, $value
//
// Width is in bytes. Integer values are encoded little-endian into the
// global. String payloads are copied byte-for-byte and zero-padded to Width,
// matching cmd/asm's DATA string semantics.
type DataStmt struct {
	// Addr retains a symbol-address initializer, including its (SB) suffix.
	Addr    string
	Sym     string
	Off     int64
	Width   int64
	Value   uint64
	Payload []byte
}

// GloblStmt models a minimal Plan 9 GLOBL directive:
//
// GLOBL sym(SB), $size
// GLOBL sym(SB), flags, $size
//
// Flags are preserved as raw text for now (e.g. "RODATA").
type GloblStmt struct {
	Sym     string
	Flags   string
	Size    int64
	SizeRaw string // unresolved generated go_asm.h expression; translation rejects it
}

func parseIdent(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_' {
			continue
		}
		if i > 0 && ch >= '0' && ch <= '9' {
			continue
		}
		return "", false
	}
	return s, true
}

func parseSym(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	// Heuristic: if it's an identifier, let parseIdent handle it; sym is for
	// things containing punctuation like (SB), ·, /, <>, etc.
	if _, ok := parseIdent(s); ok {
		return "", false
	}
	// Common form: name(SB)
	if strings.HasSuffix(s, "(SB)") {
		return s, true
	}
	// Local labels used as branch targets.
	if strings.IndexAny(s, " \t,") < 0 && strings.HasSuffix(s, "<>") {
		return s, true
	}
	// If it has any non-identifier chars and no spaces, treat as sym.
	if strings.IndexAny(s, " \t,") >= 0 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 0x80:
			// Allow UTF-8 bytes as part of Plan 9 symbol names (e.g. package
			// separators like the middle dot in raw asm sources).
			continue
		case (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'):
			continue
		case ch == '_' || ch == '.' || ch == '/':
			continue
		case ch == '<' || ch == '>' || ch == '+' || ch == '-' || ch == '$':
			continue
		case ch == '(' || ch == ')' || ch == '[' || ch == ']' || ch == '*':
			continue
		default:
			return "", false
		}
	}
	return s, true
}

func parseMem(s string) (MemRef, bool) {
	// Very small subset:
	//   off(base)
	//   (base)
	//   off(base)(index*scale)
	//   off(base)(index)
	//   (base)(index)
	//   off(index*scale)   (no base; used by LEAQ idioms like -1(AX*2))
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "(") || !strings.Contains(s, ")") {
		return MemRef{}, false
	}
	// A displacement is a Go constant expression and may itself contain
	// parentheses. Split from the final base-register group before the older
	// left-to-right address parser so forms such as 0+(1*16)(BP) do not mistake
	// the expression's first parenthesis for the address base.
	if strings.HasSuffix(s, ")") {
		if open := strings.LastIndexByte(s, '('); open > 0 {
			prefix := strings.TrimSpace(s[:open])
			baseText := strings.TrimSpace(s[open+1 : len(s)-1])
			if base, ok := parseReg(baseText); ok {
				if offset, ok := parseImmExpr(prefix); ok {
					if base == FS || base == GS {
						return MemRef{Segment: base, Off: int64(offset)}, true
					}
					return MemRef{Base: base, Off: int64(offset)}, true
				}
				if base == SP {
					if offset, ok := parseNamedStackConstantOffset(prefix); ok {
						return MemRef{Base: SP, Off: offset}, true
					}
				}
			}
		}
	}

	parseIndexScale := func(inner string) (idx Reg, ext ExtendOp, scale int64, ok bool) {
		inner = strings.TrimSpace(inner)
		if inner == "" {
			return "", "", 0, false
		}
		if shift := strings.Index(inner, "<<"); shift >= 0 {
			idxStr := strings.TrimSpace(inner[:shift])
			shiftStr := strings.TrimSpace(inner[shift+2:])
			if r, e, extended := parseRegExtend(idxStr); extended {
				idx, ext, ok = r, e, true
			} else {
				idx, ok = parseReg(idxStr)
			}
			if !ok || (ext != "" && ext != ExtendUXTW && ext != ExtendSXTW && ext != ExtendUXTX && ext != ExtendSXTX) {
				return "", "", 0, false
			}
			n, err := strconv.ParseInt(shiftStr, 0, 64)
			if err != nil || n < 0 || n > 4 {
				return "", "", 0, false
			}
			return idx, ext, int64(1) << uint(n), true
		}
		if star := strings.IndexByte(inner, '*'); star >= 0 {
			idxStr := strings.TrimSpace(inner[:star])
			scaleStr := strings.TrimSpace(inner[star+1:])
			idx, ok = parseReg(idxStr)
			if !ok {
				return "", "", 0, false
			}
			n, err := strconv.ParseInt(scaleStr, 0, 64)
			if err != nil || n == 0 {
				return "", "", 0, false
			}
			return idx, "", n, true
		}
		if r, e, extended := parseRegExtend(inner); extended {
			if e != ExtendUXTW && e != ExtendSXTW && e != ExtendUXTX && e != ExtendSXTX {
				return "", "", 0, false
			}
			return r, e, 1, true
		}
		idx, ok = parseReg(inner)
		if !ok {
			return "", "", 0, false
		}
		return idx, "", 1, true
	}

	offPart := ""
	i := strings.IndexByte(s, '(')
	if i < 0 {
		return MemRef{}, false
	}
	offPart = strings.TrimSpace(s[:i])
	rest := s[i:]
	if !strings.HasPrefix(rest, "(") {
		return MemRef{}, false
	}
	depth := 0
	j := -1
	for k := 0; k < len(rest); k++ {
		switch rest[k] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				j = k
			}
		}
		if j >= 0 {
			break
		}
	}
	if j < 0 {
		return MemRef{}, false
	}
	baseStr := strings.TrimSpace(rest[1:j])
	rest = strings.TrimSpace(rest[j+1:])
	// Go's x86 assembler permits a static-base symbol followed by an index,
	// for example masks<>(SB)(BX*8). Keep the symbol as the address base and
	// let the architecture lowering add the scaled register index.
	if strings.EqualFold(baseStr, "SB") && offPart != "" && rest != "" {
		if !strings.HasPrefix(rest, "(") || !strings.HasSuffix(rest, ")") {
			return MemRef{}, false
		}
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")"))
		idx, ext, scale, ok := parseIndexScale(inner)
		if !ok {
			return MemRef{}, false
		}
		return MemRef{Sym: offPart + "(SB)", Index: idx, IndexExt: ext, Scale: scale}, true
	}
	// Go's ARM64 SVE vector-offset syntax prints the vector index before the
	// scalar base, for example (Z6.S.SXTW<<2)(R14). Normalize that spelling to
	// the MemRef Base/Index model before parseReg accepts the arranged Z name as
	// an ordinary base register.
	if offPart == "" && strings.HasPrefix(strings.ToUpper(baseStr), "Z") && strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
		base2 := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")"))
		if base, baseOK := parseReg(base2); baseOK {
			if index, ext, scale, indexOK := parseIndexScale(baseStr); indexOK {
				return MemRef{Base: base, Index: index, IndexExt: ext, Scale: scale}, true
			}
		}
	}

	var off int64
	var offRaw string
	if offPart != "" {
		if n, err := strconv.ParseInt(offPart, 0, 64); err == nil {
			off = n
		} else if u, ok := parseImmExpr(offPart); ok {
			off = int64(u)
		} else {
			// Stack slots commonly use a descriptive name before their numeric
			// displacement (for example control-4(SP)). Preserve both the source
			// spelling and displacement so architecture validators can distinguish
			// named stack slots from plain register-relative memory.
			offRaw = offPart
			_, off = splitSymPlusOff(offPart)
		}
	}

	base, ok := parseReg(baseStr)
	if !ok {
		// Newer/legacy Plan 9 forms may encode displacement expression in the
		// first parens and then provide base/index groups, e.g.:
		//   (0*8)(R8)(BX*8)
		if offPart == "" && strings.HasPrefix(rest, "(") {
			j2 := strings.IndexByte(rest, ')')
			if j2 > 1 {
				base2 := strings.TrimSpace(rest[1:j2])
				if br, ok := parseReg(base2); ok {
					mem := MemRef{Base: br, Off: 0}
					if u, ok := parseImmExpr(baseStr); ok {
						mem.Off = int64(u)
					} else if idx, ext, scale, ok := parseIndexScale(baseStr); ok {
						mem.Index = idx
						mem.IndexExt = ext
						mem.Scale = scale
					} else if _, ok := parseVectorLengthScaleExpr(baseStr); ok {
						mem.OffRaw = baseStr
					} else {
						// Unknown include-derived expressions must remain visible
						// to validation; they are never evidence for offset zero.
						mem.OffRaw = baseStr
					}
					rem := strings.TrimSpace(rest[j2+1:])
					if rem == "" {
						return mem, true
					}
					if strings.HasPrefix(rem, "(") && strings.HasSuffix(rem, ")") {
						inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rem, "("), ")"))
						idx, ext, scale, ok := parseIndexScale(inner)
						if ok {
							mem.Index = idx
							mem.IndexExt = ext
							mem.Scale = scale
							return mem, true
						}
					}
				}
			}
		}
		// Legacy Go amd64 asm syntax in older stdlib releases uses
		// "(N*4)(REG)" for word-indexed offsets.
		if offPart == "" && strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
			base2 := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")"))
			if br, ok := parseReg(base2); ok {
				if u, ok := parseImmExpr(baseStr); ok {
					return MemRef{Base: br, Off: int64(u)}, true
				}
				if idx, ext, scale, ok := parseIndexScale(baseStr); ok {
					return MemRef{Base: br, Index: idx, IndexExt: ext, Scale: scale}, true
				}
				if _, ok := parseVectorLengthScaleExpr(baseStr); ok {
					return MemRef{Base: br, OffRaw: baseStr}, true
				}
				return MemRef{Base: br, OffRaw: baseStr}, true
			}
		}
		// Accept off(index*scale) with no base, e.g. -1(AX*2).
		idx, ext, scale, ok := parseIndexScale(baseStr)
		if !ok || rest != "" {
			return MemRef{}, false
		}
		return MemRef{Base: "", Off: off, Index: idx, IndexExt: ext, Scale: scale}, true
	}

	mem := MemRef{Base: base, Off: off, OffRaw: offRaw}
	if base == FS || base == GS {
		mem.Base = ""
		mem.Segment = base
	}
	if rest == "" {
		return mem, true
	}

	// Optional (index*scale) or (index)
	if !strings.HasPrefix(rest, "(") || !strings.HasSuffix(rest, ")") {
		return MemRef{}, false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")"))
	if segment, ok := parseReg(inner); ok && (segment == FS || segment == GS) {
		if mem.Segment != "" {
			return MemRef{}, false
		}
		mem.Segment = segment
		return mem, true
	}
	idx, ext, scale, ok := parseIndexScale(inner)
	if !ok {
		return MemRef{}, false
	}
	mem.Index = idx
	mem.IndexExt = ext
	mem.Scale = scale
	return mem, true
}

// Go stack names are annotations; the numeric expression after their sign
// determines the actual SP displacement. For example tmpdig-(1*4)(SP) and
// tmpdig-4(SP) address the same slot. Only an evaluable expression is accepted
// here, so an unresolved macro cannot silently become offset zero.
func parseNamedStackConstantOffset(prefix string) (int64, bool) {
	prefix = strings.TrimSpace(prefix)
	if len(prefix) < 3 {
		return 0, false
	}
	sep := strings.IndexAny(prefix[1:], "+-") + 1
	if sep == 0 || sep >= len(prefix)-1 {
		return 0, false
	}
	if _, ok := parseIdent(prefix[:sep]); !ok {
		return 0, false
	}
	offset, ok := parseImmExpr(prefix[sep:])
	return int64(offset), ok
}

func splitTopLevelCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	par := 0
	brk := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		if quote != 0 {
			if s[i] == '\\' && quote != '`' && i+1 < len(s) {
				i++
				continue
			}
			if s[i] == quote {
				quote = 0
			}
			continue
		}
		switch s[i] {
		case '\'', '"', '`':
			quote = s[i]
		case '(':
			par++
		case ')':
			if par > 0 {
				par--
			}
		case '[':
			brk++
		case ']':
			if brk > 0 {
				brk--
			}
		case ',':
			if par == 0 && brk == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}
