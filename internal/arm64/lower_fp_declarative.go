package arm64

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

var arm64DeclarativeFPSpecs = []asm.OpSpec{
	// Binary FP (single + double missing ops)
	{Op: "FADDS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fadd"},
	{Op: "FSUBS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fsub"},
	{Op: "FMULS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmul"},
	{Op: "FDIVS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fdiv"},
	{Op: "FNMULS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fnmul"},
	{Op: "FMAXS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "maximum"},
	{Op: "FMINS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "minimum"},
	{Op: "FMAXNMS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "maxnum"},
	{Op: "FMAXNMD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "maxnum"},
	{Op: "FMINNMS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "minnum"},
	{Op: "FMINNMD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "minnum"},

	// Unary FP & rounding
	{Op: "FABSS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fabs"},
	{Op: "FNEGS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fneg"},
	{Op: "FNEGD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fneg"},
	{Op: "FSQRTS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqrt"},
	{Op: "FSQRTD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqrt"},
	{Op: "FRINTAS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "round"},
	{Op: "FRINTAD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "round"},
	{Op: "FRINTIS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "nearbyint"},
	{Op: "FRINTID", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "nearbyint"},
	{Op: "FRINTMS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "floor"},
	{Op: "FRINTNS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "roundeven"},
	{Op: "FRINTND", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "roundeven"},
	{Op: "FRINTPS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "ceil"},
	{Op: "FRINTXS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "rint"},
	{Op: "FRINTXD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "rint"},
	{Op: "FRINTZS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "trunc"},

	// 4-operand FMA
	{Op: "FMADDS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmadd"},
	{Op: "FMSUBS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmsub"},
	{Op: "FNMADDS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fnmadd"},
	{Op: "FNMADDD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fnmadd"},
	{Op: "FNMSUBS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fnmsub"},

	// Compares & conditional compares / selects
	{Op: "FCMPS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "fcmp"},
	{Op: "FCMPES", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "fcmp"},
	{Op: "FCMPED", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "fcmp"},
	{Op: "FCCMPS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsReadWrite, LLVMOp: "fccmp"},
	{Op: "FCCMPD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsReadWrite, LLVMOp: "fccmp"},
	{Op: "FCCMPES", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsReadWrite, LLVMOp: "fccmp"},
	{Op: "FCCMPED", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsReadWrite, LLVMOp: "fccmp"},
	{Op: "FCSELS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsRead, LLVMOp: "fcsel"},

	// Float <-> Int conversions
	{Op: "FCVTZSS", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2i"},
	{Op: "FCVTZSSW", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "f2i"},
	{Op: "FCVTZSDW", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "f2i"},
	{Op: "FCVTZUS", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Effect: asm.EffectWriteOnly, LLVMOp: "f2i"},
	{Op: "FCVTZUSW", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "f2i"},
	{Op: "FCVTZUD", Family: asm.FamilyFP, Width: 64, SrcWidth: 64, Effect: asm.EffectWriteOnly, LLVMOp: "f2i"},
	{Op: "FCVTZUDW", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Effect: asm.EffectWriteZeroUpper, LLVMOp: "f2i"},
	{Op: "SCVTFS", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Float: true, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f"},
	{Op: "SCVTFWS", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Float: true, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f"},
	{Op: "SCVTFWD", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Float: true, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f"},
	{Op: "UCVTFS", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f"},
	{Op: "UCVTFD", Family: asm.FamilyFP, Width: 64, SrcWidth: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f"},
	{Op: "UCVTFWS", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f"},
	{Op: "UCVTFWD", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f"},

	// Moves & pairs
	{Op: "FMOVS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmov"},
	{Op: "FLDPS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fldp"},
	{Op: "FSTPS", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, LLVMOp: "fstp"},
}

var arm64FPTable = asm.NewOpTable(arm64DeclarativeFPSpecs)

func (c *arm64Ctx) evalF32(op asm.Operand) (string, error) {
	switch op.Kind {
	case asm.OpReg:
		if strings.Contains(string(op.Reg), "[") {
			bits, err := c.arm64ExtractVecLaneI64(op.Reg, 32)
			if err != nil {
				return "", err
			}
			tr, bc := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, bits)
			fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", bc, tr)
			return "%" + bc, nil
		}
		v64, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		tr, bc := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v64)
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", bc, tr)
		return "%" + bc, nil
	case asm.OpImm:
		return asm.FormatLLVMFloat64Literal(float64(float32(op.Imm))), nil
	case asm.OpSym:
		if fv, ok := arm64ParseDollarFloatFlex(op.Sym); ok {
			return asm.FormatLLVMFloat64Literal(float64(float32(fv))), nil
		}
		if iv, ok := arm64ParseDollarInt64(op.Sym); ok {
			return asm.FormatLLVMFloat64Literal(float64(float32(iv))), nil
		}
		return "", fmt.Errorf("arm64: unsupported f32 immediate %q", op.String())
	case asm.OpFP:
		v64, err := c.evalF64(op)
		if err != nil {
			return "", err
		}
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptrunc double %s to float\n", tr, v64)
		return "%" + tr, nil
	default:
		return "", fmt.Errorf("arm64: unsupported f32 operand %s", op.String())
	}
}

func (c *arm64Ctx) storeF32(dst asm.Operand, v string) error {
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", bc, v)
	ext := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", ext, bc)
	switch dst.Kind {
	case asm.OpReg:
		return c.storeReg(dst.Reg, "%"+ext)
	case asm.OpFP:
		return c.storeFPResult64(dst.FPOffset, "%"+ext)
	default:
		return fmt.Errorf("arm64: unsupported f32 dst operand %s", dst.String())
	}
}

func arm64ParseDollarFloatFlex(sym string) (float64, bool) {
	if !strings.HasPrefix(sym, "$") {
		return 0, false
	}
	s := strings.TrimSpace(strings.TrimPrefix(sym, "$"))
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && len(s) >= 2 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	if s == "" || strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return 0, false
	}
	if !strings.ContainsAny(s, ".eE") {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func (c *arm64Ctx) evalFP(op asm.Operand, width uint16) (string, error) {
	if width == 32 {
		return c.evalF32(op)
	}
	if op.Kind == asm.OpSym {
		if fv, ok := arm64ParseDollarFloatFlex(op.Sym); ok {
			return asm.FormatLLVMFloat64Literal(fv), nil
		}
	}
	return c.evalF64(op)
}

func (c *arm64Ctx) storeFP(dst asm.Operand, v string, width uint16) error {
	if width == 32 {
		return c.storeF32(dst, v)
	}
	return c.storeF64(dst, v)
}

func (c *arm64Ctx) lowerFPDeclarative(op asm.Op, postInc bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	spec, found := arm64FPTable.Lookup(op)
	if !found {
		return false, false, nil
	}
	ty, suf := "double", "f64"
	if spec.Width == 32 {
		ty, suf = "float", "f32"
	}
	switch spec.LLVMOp {
	case "fadd", "fsub", "fmul", "fdiv", "fnmul", "maximum", "minimum", "maxnum", "minnum":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
		}
		src, err := c.evalFP(ins.Args[0], spec.Width)
		if err != nil {
			return true, false, err
		}
		var lhs string
		var dstOp asm.Operand
		if len(ins.Args) == 2 {
			dstOp = ins.Args[1]
			lhs, err = c.evalFP(dstOp, spec.Width)
		} else {
			dstOp = ins.Args[2]
			lhs, err = c.evalFP(ins.Args[1], spec.Width)
		}
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		switch spec.LLVMOp {
		case "fnmul":
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fmul %s %s, %s\n", m, ty, lhs, src)
			fmt.Fprintf(c.b, "  %%%s = fneg %s %%%s\n", out, ty, m)
		case "maximum", "minimum", "maxnum", "minnum":
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s, %s %s)\n", out, ty, spec.LLVMOp, suf, ty, lhs, ty, src)
		default:
			fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", out, spec.LLVMOp, ty, lhs, src)
		}
		return true, false, c.storeFP(dstOp, "%"+out, spec.Width)

	case "fabs", "fneg", "sqrt", "round", "nearbyint", "floor", "roundeven", "ceil", "rint", "trunc":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
		}
		src, err := c.evalFP(ins.Args[0], spec.Width)
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		if spec.LLVMOp == "fneg" {
			fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", out, ty, src)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", out, ty, spec.LLVMOp, suf, ty, src)
		}
		return true, false, c.storeFP(ins.Args[1], "%"+out, spec.Width)

	case "fmadd", "fmsub", "fnmadd", "fnmsub":
		if len(ins.Args) != 4 {
			return true, false, fmt.Errorf("arm64 %s expects 4 operands: %q", op, ins.Raw)
		}
		a, err := c.evalFP(ins.Args[0], spec.Width)
		if err != nil {
			return true, false, err
		}
		b, err := c.evalFP(ins.Args[1], spec.Width)
		if err != nil {
			return true, false, err
		}
		cv, err := c.evalFP(ins.Args[2], spec.Width)
		if err != nil {
			return true, false, err
		}
		// Plan 9 order: a, b, c, dst => b +/- a*c (or negated for fn*)
		if spec.LLVMOp == "fmsub" || spec.LLVMOp == "fnmadd" {
			na := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", na, ty, a)
			a = "%" + na
		}
		if spec.LLVMOp == "fnmadd" || spec.LLVMOp == "fnmsub" {
			nb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", nb, ty, b)
			b = "%" + nb
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.%s(%s %s, %s %s, %s %s)\n", out, ty, suf, ty, a, ty, cv, ty, b)
		return true, false, c.storeFP(ins.Args[3], "%"+out, spec.Width)

	case "fcmp":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
		}
		src, err := c.evalFP(ins.Args[0], spec.Width)
		if err != nil {
			return true, false, err
		}
		dst, err := c.evalFP(ins.Args[1], spec.Width)
		if err != nil {
			return true, false, err
		}
		eq, lt, gt, uno := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp oeq %s %s, %s\n", eq, ty, dst, src)
		fmt.Fprintf(c.b, "  %%%s = fcmp olt %s %s, %s\n", lt, ty, dst, src)
		fmt.Fprintf(c.b, "  %%%s = fcmp ogt %s %s, %s\n", gt, ty, dst, src)
		fmt.Fprintf(c.b, "  %%%s = fcmp uno %s %s, %s\n", uno, ty, dst, src)
		c01, cf := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", c01, gt, eq)
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", cf, c01, uno)
		c.storeFlag(c.flagsNSlot, "%"+lt)
		c.storeFlag(c.flagsZSlot, "%"+eq)
		c.storeFlag(c.flagsCSlot, "%"+cf)
		c.storeFlag(c.flagsVSlot, "%"+uno)
		c.flagsWritten = true
		return true, false, nil

	case "fccmp":
		if len(ins.Args) != 4 || ins.Args[3].Kind != asm.OpImm {
			return true, false, fmt.Errorf("arm64 %s expects cond, src1, src2, $nzcv: %q", op, ins.Raw)
		}
		cond, ok := arm64ConditionOperand(ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("arm64 %s invalid cond: %q", op, ins.Raw)
		}
		var pred string
		if cond == "AL" {
			pred = "true"
		} else {
			pred, err = c.condValue(cond)
			if err != nil {
				return true, false, err
			}
		}
		src, err := c.evalFP(ins.Args[1], spec.Width)
		if err != nil {
			return true, false, err
		}
		dst, err := c.evalFP(ins.Args[2], spec.Width)
		if err != nil {
			return true, false, err
		}
		nzcv := ins.Args[3].Imm
		eq, lt, gt, uno := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp oeq %s %s, %s\n", eq, ty, dst, src)
		fmt.Fprintf(c.b, "  %%%s = fcmp olt %s %s, %s\n", lt, ty, dst, src)
		fmt.Fprintf(c.b, "  %%%s = fcmp ogt %s %s, %s\n", gt, ty, dst, src)
		fmt.Fprintf(c.b, "  %%%s = fcmp uno %s %s, %s\n", uno, ty, dst, src)
		c01, cf := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", c01, gt, eq)
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", cf, c01, uno)
		selFlag := func(computed string, fb bool) string {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %t\n", t, pred, computed, fb)
			return "%" + t
		}
		c.storeFlag(c.flagsNSlot, selFlag("%"+lt, nzcv&8 != 0))
		c.storeFlag(c.flagsZSlot, selFlag("%"+eq, nzcv&4 != 0))
		c.storeFlag(c.flagsCSlot, selFlag("%"+cf, nzcv&2 != 0))
		c.storeFlag(c.flagsVSlot, selFlag("%"+uno, nzcv&1 != 0))
		c.flagsWritten = true
		return true, false, nil

	case "fcsel":
		if len(ins.Args) != 4 {
			return true, false, fmt.Errorf("arm64 %s expects cond, a, b, dst: %q", op, ins.Raw)
		}
		cond, ok := arm64ConditionOperand(ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("arm64 %s invalid cond: %q", op, ins.Raw)
		}
		a, err := c.evalFP(ins.Args[1], spec.Width)
		if err != nil {
			return true, false, err
		}
		bv, err := c.evalFP(ins.Args[2], spec.Width)
		if err != nil {
			return true, false, err
		}
		var cv string
		if cond == "AL" {
			cv = "true"
		} else {
			cv, err = c.condValue(cond)
			if err != nil {
				return true, false, err
			}
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", t, cv, ty, a, ty, bv)
		return true, false, c.storeFP(ins.Args[3], "%"+t, spec.Width)

	case "f2i":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects Fsrc, dstReg: %q", op, ins.Raw)
		}
		src, err := c.evalFP(ins.Args[0], spec.SrcWidth)
		if err != nil {
			return true, false, err
		}
		srcTy := "double"
		if spec.SrcWidth == 32 {
			srcTy = "float"
		}
		dstTy := fmt.Sprintf("i%d", spec.Width)
		conv := "fptoui"
		if spec.Signed {
			conv = "fptosi"
		}
		iv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", iv, conv, srcTy, src, dstTy)
		out := "%" + iv
		if spec.Width == 32 {
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, iv)
			out = "%" + z
		}
		return true, false, c.storeReg(ins.Args[1].Reg, out)

	case "i2f":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects srcReg, Fdst: %q", op, ins.Raw)
		}
		var iv string
		if spec.SrcWidth == 32 {
			iv, err = c.eval32(ins.Args[0])
		} else {
			iv, err = c.eval64(ins.Args[0], false)
		}
		if err != nil {
			return true, false, err
		}
		srcTy := fmt.Sprintf("i%d", spec.SrcWidth)
		conv := "uitofp"
		if spec.Signed {
			conv = "sitofp"
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", out, conv, srcTy, iv, ty)
		return true, false, c.storeFP(ins.Args[1], "%"+out, spec.Width)

	case "fmov":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 FMOVS expects 2 operands: %q", ins.Raw)
		}
		src, dst := ins.Args[0], ins.Args[1]
		var bits string
		switch src.Kind {
		case asm.OpMem:
			bits, err = c.loadMem(src.Mem, 32, postInc)
		case asm.OpSym:
			if fv, ok := arm64ParseDollarFloatFlex(src.Sym); ok {
				bits = strconv.FormatUint(uint64(math.Float32bits(float32(fv))), 10)
			} else {
				p, perr := c.ptrFromSB(src.Sym)
				if perr != nil {
					return true, false, perr
				}
				ld, z := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s\n", ld, p)
				fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, ld)
				bits = "%" + z
			}
		default:
			bits, err = c.eval64(src, false)
		}
		if err != nil {
			return true, false, err
		}
		switch dst.Kind {
		case asm.OpReg:
			tr, z := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, bits)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, tr)
			return true, false, c.storeReg(dst.Reg, "%"+z)
		case asm.OpMem:
			return true, false, c.storeMem(dst.Mem, 32, postInc, bits)
		case asm.OpSym:
			p, perr := c.ptrFromSB(dst.Sym)
			if perr != nil {
				return true, false, perr
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, bits)
			fmt.Fprintf(c.b, "  store i32 %%%s, ptr %s\n", tr, p)
			return true, false, nil
		case asm.OpFP:
			return true, false, c.storeFPResult64(dst.FPOffset, bits)
		default:
			return true, false, fmt.Errorf("arm64 FMOVS unsupported dst: %q", ins.Raw)
		}

	case "fldp", "fstp":
		preInc := strings.Contains(strings.ToUpper(string(ins.Op)), ".W")
		if spec.LLVMOp == "fldp" {
			if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpRegList || len(ins.Args[1].RegList) != 2 {
				return true, false, fmt.Errorf("arm64 FLDPS expects mem/sym, (F1, F2): %q", ins.Raw)
			}
			ptr, base, inc, update, err := c.arm64PairPtr(ins.Args[0], preInc, postInc)
			if err != nil {
				return true, false, err
			}
			for i, r := range ins.Args[1].RegList {
				p := ptr
				if i != 0 {
					gp := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 4\n", gp, ptr)
					p = "%" + gp
				}
				ld, z := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s\n", ld, p)
				fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, ld)
				if err := c.storeReg(r, "%"+z); err != nil {
					return true, false, err
				}
			}
			if update {
				return true, false, c.updatePostInc(base, inc)
			}
			return true, false, nil
		}
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpRegList || len(ins.Args[0].RegList) != 2 {
			return true, false, fmt.Errorf("arm64 FSTPS expects (F1, F2), mem/sym: %q", ins.Raw)
		}
		ptr, base, inc, update, err := c.arm64PairPtr(ins.Args[1], preInc, postInc)
		if err != nil {
			return true, false, err
		}
		for i, r := range ins.Args[0].RegList {
			p := ptr
			if i != 0 {
				gp := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 4\n", gp, ptr)
				p = "%" + gp
			}
			v, err := c.loadReg(r)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v)
			fmt.Fprintf(c.b, "  store i32 %%%s, ptr %s\n", tr, p)
		}
		if update {
			return true, false, c.updatePostInc(base, inc)
		}
		return true, false, nil
	}
	return false, false, nil
}

func (c *arm64Ctx) arm64PairPtr(op asm.Operand, preInc, postInc bool) (ptr string, base asm.Reg, inc int64, update bool, err error) {
	if op.Kind == asm.OpSym {
		p, err := c.ptrFromSB(op.Sym)
		return p, "", 0, false, err
	}
	if op.Kind != asm.OpMem {
		return "", "", 0, false, fmt.Errorf("arm64: expected mem or sym operand")
	}
	addr, base, inc, err := c.addrI64(op.Mem, postInc)
	if err != nil {
		return "", "", 0, false, err
	}
	if preInc {
		if err := c.storeReg(base, addr); err != nil {
			return "", "", 0, false, err
		}
	}
	pt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
	return "%" + pt, base, inc, postInc, nil
}
