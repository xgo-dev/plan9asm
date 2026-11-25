package arm

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// OpTable is the declarative 32-bit ARM instruction table targeting LLVM IR.
// Each family is lowered by one parameterized emitter below rather than
// per-instruction boilerplate files.
var OpTable = asm.NewOpTable(
	armScalarSpecs,
	armBitMulSpecs,
	armVFPSpecs,
)

var armScalarSpecs = []asm.OpSpec{
	{Op: "MOVW", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteOnly},
	{Op: "MOVB", Family: asm.FamilyMove, Width: 8, Signed: true, Effect: asm.EffectWriteOnly},
	{Op: "MOVBS", Family: asm.FamilyMove, Width: 8, Signed: true, Effect: asm.EffectWriteOnly},
	{Op: "MOVBU", Family: asm.FamilyMove, Width: 8, Effect: asm.EffectWriteOnly},
	{Op: "MOVH", Family: asm.FamilyMove, Width: 16, Signed: true, Effect: asm.EffectWriteOnly},
	{Op: "MOVHS", Family: asm.FamilyMove, Width: 16, Signed: true, Effect: asm.EffectWriteOnly},
	{Op: "MOVHU", Family: asm.FamilyMove, Width: 16, Effect: asm.EffectWriteOnly},
	{Op: "MOVF", Family: asm.FamilyMove, Width: 32, Float: true, Effect: asm.EffectWriteOnly},
	{Op: "MOVD", Family: asm.FamilyMove, Width: 64, Float: true, Effect: asm.EffectWriteOnly},
	{Op: "RSC", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectWriteOnly, Flags: asm.FlagsReadWrite, LLVMOp: "rsc"},
	{Op: "SLL", Family: asm.FamilyShift, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "shl"},
	{Op: "SRL", Family: asm.FamilyShift, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "lshr"},
	{Op: "SRA", Family: asm.FamilyShift, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ashr"},
	{Op: "XTAB", Family: asm.FamilyALU, Width: 32, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "xta"},
	{Op: "XTABU", Family: asm.FamilyALU, Width: 32, SrcWidth: 8, Effect: asm.EffectWriteOnly, LLVMOp: "xta"},
	{Op: "XTAH", Family: asm.FamilyALU, Width: 32, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "xta"},
	{Op: "XTAHU", Family: asm.FamilyALU, Width: 32, SrcWidth: 16, Effect: asm.EffectWriteOnly, LLVMOp: "xta"},
	{Op: "SWPW", Family: asm.FamilyAtomic, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "xchg"},
	{Op: "SWPBU", Family: asm.FamilyAtomic, Width: 8, Effect: asm.EffectWriteOnly, LLVMOp: "xchg"},
	{Op: "PLD", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "prefetch"},
	{Op: "MCR", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mcr"},
	{Op: "RFE", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly, LLVMOp: "rfe"},
	{Op: "BX", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly, LLVMOp: "bx"},
	{Op: "BXRET", Family: asm.FamilyBranch, Effect: asm.EffectReadOnly, LLVMOp: "bx"},
	{Op: "DUFFZERO", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "DUFFCOPY", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "END", Family: asm.FamilyNOP, Effect: asm.EffectNone},
}

var armBitMulSpecs = []asm.OpSpec{
	{Op: "BFC", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectReadWrite, LLVMOp: "bfc"},
	{Op: "BFI", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectReadWrite, LLVMOp: "bfi"},
	{Op: "BFX", Family: asm.FamilyBit, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "bfx"},
	{Op: "BFXU", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "bfx"},
	{Op: "RBIT", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "rbit"},
	{Op: "REV", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "rev"},
	{Op: "REV16", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "rev16"},
	{Op: "REVSH", Family: asm.FamilyBit, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "revsh"},
	{Op: "DIV", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "sdiv"},
	{Op: "DIVU", Family: asm.FamilyMulDiv, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "udiv"},
	{Op: "MOD", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "srem"},
	{Op: "MODU", Family: asm.FamilyMulDiv, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "urem"},
	{Op: "DIVHW", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "sdiv"},
	{Op: "DIVUHW", Family: asm.FamilyMulDiv, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "udiv"},
	{Op: "MULL", Family: asm.FamilyMulDiv, Width: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mull"},
	{Op: "MULS", Family: asm.FamilyMulDiv, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "muls"},
	{Op: "MMUL", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mmul"},
	{Op: "MMULA", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mmula"},
	{Op: "MMULS", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mmuls"},
	{Op: "MULBB", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulbb"},
	{Op: "MULBT", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulbt"},
	{Op: "MULTB", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "multb"},
	{Op: "MULTT", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "multt"},
	{Op: "MULWB", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulwb"},
	{Op: "MULWT", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulwt"},
	{Op: "MULABB", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulabb"},
	{Op: "MULABT", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulabt"},
	{Op: "MULATB", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulatb"},
	{Op: "MULATT", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulatt"},
	{Op: "MULAWB", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulawb"},
	{Op: "MULAWT", Family: asm.FamilyMulDiv, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "mulawt"},
}

var armVFPSpecs = []asm.OpSpec{
	// Binary arithmetic (2-op or 3-op)
	{Op: "ADDF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fadd"},
	{Op: "ADDD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fadd"},
	{Op: "SUBF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fsub"},
	{Op: "SUBD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fsub"},
	{Op: "MULF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmul"},
	{Op: "MULD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmul"},
	{Op: "DIVF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fdiv"},
	{Op: "DIVD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fdiv"},
	{Op: "NMULF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fnmul"},
	{Op: "NMULD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fnmul"},

	// Unary FP
	{Op: "ABSF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fabs"},
	{Op: "ABSD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fabs"},
	{Op: "NEGF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fneg"},
	{Op: "NEGD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fneg"},
	{Op: "SQRTF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fsqrt"},
	{Op: "SQRTD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fsqrt"},

	// FP Compare (1-op vs 0.0 or 2-op)
	{Op: "CMPF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "fcmp"},
	{Op: "CMPD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "fcmp"},

	// FP Conversions
	{Op: "MOVDF", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2f"},
	{Op: "MOVFD", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2f"},
	{Op: "MOVDW", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2i"},
	{Op: "MOVFW", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2i"},
	{Op: "MOVWD", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Float: true, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f"},
	{Op: "MOVWF", Family: asm.FamilyFP, Width: 32, SrcWidth: 32, Float: true, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f"},

	// VFP Multiply-Accumulate / Fused Multiply-Accumulate (3-op: a, b, dst)
	{Op: "MULAF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "mula"},
	{Op: "MULAD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "mula"},
	{Op: "MULSF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "muls"},
	{Op: "MULSD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "muls"},
	{Op: "NMULAF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "nmula"},
	{Op: "NMULAD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "nmula"},
	{Op: "NMULSF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "nmuls"},
	{Op: "NMULSD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "nmuls"},
	{Op: "FMULAF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmula"},
	{Op: "FMULAD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmula"},
	{Op: "FMULSF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmuls"},
	{Op: "FMULSD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fmuls"},
	{Op: "FNMULAF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fnmula"},
	{Op: "FNMULAD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fnmula"},
	{Op: "FNMULSF", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fnmuls"},
	{Op: "FNMULSD", Family: asm.FamilyFP, Width: 64, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fnmuls"},
}

// lowerDeclarative lowers any instruction registered in arm OpTable using
// parameterized family emitters.
func (c *armCtx) lowerDeclarative(op, cond string, postInc, setFlags bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	spec, found := OpTable.Lookup(asm.Op(op))
	if !found {
		return false, false, nil
	}
	switch spec.Family {
	case asm.FamilyNOP:
		return true, false, nil
	case asm.FamilySystem:
		switch spec.LLVMOp {
		case "prefetch":
			if len(ins.Args) != 1 || (ins.Args[0].Kind != asm.OpMem && ins.Args[0].Kind != asm.OpSym) {
				return true, false, fmt.Errorf("arm %s expects memory operand: %q", op, ins.Raw)
			}
			return true, false, nil
		case "mcr":
			if len(ins.Args) != 6 || ins.Args[2].Kind != asm.OpReg {
				return true, false, fmt.Errorf("arm MCR expects coproc, opc1, src, CRn, CRm, opc2: %q", ins.Raw)
			}
			src, err := c.loadReg(ins.Args[2].Reg)
			if err != nil {
				return true, false, err
			}
			part := func(o asm.Operand) string {
				return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(o.String())), "$")
			}
			asmStr := fmt.Sprintf("mcr p%s, %s, $0, %s, %s, %s", part(ins.Args[0]), part(ins.Args[1]), part(ins.Args[3]), part(ins.Args[4]), part(ins.Args[5]))
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", asmStr, "r,~{memory}", src)
			return true, false, nil
		}
	case asm.FamilyBranch:
		switch spec.LLVMOp {
		case "bx":
			return c.lowerARMBX(cond, ins)
		case "rfe":
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", "rfeia sp!", "~{memory}")
			c.lowerRetZero()
			return true, true, nil
		}
	case asm.FamilyAtomic:
		if spec.LLVMOp == "xchg" {
			return true, false, c.lowerARMSWP(spec, cond, ins)
		}
	case asm.FamilyShift:
		return true, false, c.lowerARMShiftOp(spec, cond, setFlags, ins)
	case asm.FamilyALU:
		switch spec.LLVMOp {
		case "rsc":
			return true, false, c.lowerARMRSC(cond, setFlags, ins)
		case "xta":
			return true, false, c.lowerARMXTA(spec, cond, ins)
		}
	case asm.FamilyBit:
		return true, false, c.lowerARMDeclarativeBit(spec, cond, ins)
	case asm.FamilyMulDiv:
		return true, false, c.lowerARMDeclarativeMulDiv(spec, cond, ins)
	case asm.FamilyFP:
		return true, false, c.lowerARMDeclarativeFP(spec, cond, ins)
	}
	return false, false, nil
}

func (c *armCtx) lowerARMBX(cond string, ins asm.Instr) (bool, bool, error) {
	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("arm BX expects 1 operand: %q", ins.Raw)
	}
	var addr string
	var err error
	switch ins.Args[0].Kind {
	case asm.OpReg:
		addr, err = c.loadReg(ins.Args[0].Reg)
	case asm.OpMem:
		addr, _, _, err = c.addrI32(ins.Args[0].Mem, false)
	default:
		return true, false, fmt.Errorf("arm BX expects reg or (reg): %q", ins.Raw)
	}
	if err != nil {
		return true, false, err
	}
	emitBX := func() error {
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "bx $0", "r,~{memory}", addr)
		return nil
	}
	if cond != "" {
		return true, false, c.emitConditionalEffect(cond, emitBX)
	}
	if err := emitBX(); err != nil {
		return true, false, err
	}
	c.lowerRetZero()
	return true, true, nil
}

func (c *armCtx) lowerARMSWP(spec asm.OpSpec, cond string, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm %s expects srcReg, (ptr), dstReg: %q", spec.Op, ins.Raw)
	}
	srcArg, memArg := ins.Args[0], ins.Args[1]
	if srcArg.Kind == asm.OpMem && memArg.Kind == asm.OpReg {
		srcArg, memArg = memArg, srcArg
	}
	if srcArg.Kind != asm.OpReg || memArg.Kind != asm.OpMem {
		return fmt.Errorf("arm %s expects srcReg, (ptr), dstReg: %q", spec.Op, ins.Raw)
	}
	emit := func() error {
		src, err := c.loadReg(srcArg.Reg)
		if err != nil {
			return err
		}
		addr, _, _, err := c.addrI32(memArg.Mem, false)
		if err != nil {
			return err
		}
		pt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pt, addr)
		if spec.Width == 8 {
			s8 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i8\n", s8, src)
			old := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = atomicrmw xchg ptr %%%s, i8 %%%s seq_cst\n", old, pt, s8)
			ext := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i32\n", ext, old)
			return c.storeReg(ins.Args[2].Reg, "%"+ext)
		}
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw xchg ptr %%%s, i32 %s seq_cst\n", old, pt, src)
		return c.storeReg(ins.Args[2].Reg, "%"+old)
	}
	return c.emitConditionalEffect(cond, emit)
}

func (c *armCtx) lowerARMRSC(cond string, setFlags bool, ins asm.Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm RSC expects 2 or 3 operands: %q", ins.Raw)
	}
	var src, lhs string
	var dst asm.Operand
	var err error
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm RSC dst must be reg: %q", ins.Raw)
		}
		src, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		lhs, err = c.loadReg(dst.Reg)
		if err != nil {
			return err
		}
	} else {
		dst = ins.Args[2]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm RSC dst must be reg: %q", ins.Raw)
		}
		src, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		lhs, err = c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
	}
	cf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", cf, c.flagsCSlot)
	ncf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", ncf, cf)
	borrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", borrow, ncf)
	t0 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", t0, src, lhs)
	res := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, %%%s\n", res, t0, borrow)
	if err := c.selectRegWrite(dst.Reg, cond, "%"+res); err != nil {
		return err
	}
	if setFlags {
		s64 := c.zextI32ToI64(src)
		l64 := c.zextI32ToI64(lhs)
		b64 := c.zextI32ToI64("%" + borrow)
		subtr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", subtr, l64, b64)
		hasBorrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %%%s\n", hasBorrow, s64, subtr)
		if err := c.setFlagsSub(cond, src, lhs, "%"+res); err != nil {
			return err
		}
		nb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", nb, hasBorrow)
		if err := c.storeFlagCond(cond, c.flagsCSlot, "%"+nb); err != nil {
			return err
		}
	}
	return nil
}

func (c *armCtx) lowerARMShiftOp(spec asm.OpSpec, cond string, setFlags bool, ins asm.Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects 2 or 3 operands: %q", spec.Op, ins.Raw)
	}
	amt, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	var src string
	var dst asm.Operand
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", spec.Op, ins.Raw)
		}
		src, err = c.loadReg(dst.Reg)
	} else {
		dst = ins.Args[2]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", spec.Op, ins.Raw)
		}
		src, err = c.eval32(ins.Args[1], false)
	}
	if err != nil {
		return err
	}
	// ARM register/imm shift clamps counts >= 32 (masking byte count first).
	amt8 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %s, 255\n", amt8, amt)
	big := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp uge i32 %%%s, 32\n", big, amt8)
	clamped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 31, i32 %%%s\n", clamped, big, amt8)
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %%%s\n", shifted, spec.LLVMOp, src, clamped)
	var out string
	if spec.LLVMOp == "ashr" {
		sign := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, 31\n", sign, src)
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 %%%s\n", sel, big, sign, shifted)
		out = "%" + sel
	} else {
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 0, i32 %%%s\n", sel, big, shifted)
		out = "%" + sel
	}
	if err := c.selectRegWrite(dst.Reg, cond, out); err != nil {
		return err
	}
	if setFlags {
		return c.setFlagsLogic(cond, out)
	}
	return nil
}

func (c *armCtx) lowerARMXTA(spec asm.OpSpec, cond string, ins asm.Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects 2 or 3 operands: %q", spec.Op, ins.Raw)
	}
	src, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	var acc string
	var dst asm.Operand
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", spec.Op, ins.Raw)
		}
		acc, err = c.loadReg(dst.Reg)
	} else {
		dst = ins.Args[2]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", spec.Op, ins.Raw)
		}
		acc, err = c.eval32(ins.Args[1], false)
	}
	if err != nil {
		return err
	}
	srcTy := fmt.Sprintf("i%d", spec.SrcWidth)
	tr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to %s\n", tr, src, srcTy)
	ext := c.newTmp()
	if spec.Signed {
		fmt.Fprintf(c.b, "  %%%s = sext %s %%%s to i32\n", ext, srcTy, tr)
	} else {
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i32\n", ext, srcTy, tr)
	}
	sum := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i32 %s, %%%s\n", sum, acc, ext)
	return c.selectRegWrite(dst.Reg, cond, "%"+sum)
}

func (c *armCtx) lowerARMDeclarativeBit(spec asm.OpSpec, cond string, ins asm.Instr) error {
	switch spec.LLVMOp {
	case "rbit", "rev", "rev16", "revsh":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm %s expects src, dst: %q", spec.Op, ins.Raw)
		}
		src, err := c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		var out string
		switch spec.LLVMOp {
		case "rbit":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bitreverse.i32(i32 %s)\n", t, src)
			out = "%" + t
		case "rev":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bswap.i32(i32 %s)\n", t, src)
			out = "%" + t
		case "rev16":
			lo := c.newTmp()
			hi := c.newTmp()
			loSh := c.newTmp()
			hiSh := c.newTmp()
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %s, 16711935\n", lo, src)
			fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, 8\n", loSh, lo)
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, 8\n", hiSh, src)
			fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 16711935\n", hi, hiSh)
			fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", res, loSh, hi)
			out = "%" + res
		case "revsh":
			tr := c.newTmp()
			sw := c.newTmp()
			se := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", tr, src)
			fmt.Fprintf(c.b, "  %%%s = call i16 @llvm.bswap.i16(i16 %%%s)\n", sw, tr)
			fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i32\n", se, sw)
			out = "%" + se
		}
		return c.selectRegWrite(ins.Args[1].Reg, cond, out)

	case "bfc", "bfi", "bfx":
		if len(ins.Args) < 2 || len(ins.Args) > 4 || (spec.LLVMOp == "bfc" && len(ins.Args) == 4) {
			return fmt.Errorf("arm %s unexpected operand count: %q", spec.Op, ins.Raw)
		}
		var width, lsb int64
		var srcOp, dstOp asm.Operand
		if len(ins.Args) == 2 {
			// Compact encoder form: $imm, Rd (width=imm&31, lsb=0)
			if ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg {
				return fmt.Errorf("arm %s expects $width, dst: %q", spec.Op, ins.Raw)
			}
			width = ins.Args[0].Imm & 31
			if width == 0 {
				width = 1
			}
			lsb = 0
			srcOp = ins.Args[1]
			dstOp = ins.Args[1]
		} else if len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpImm && ins.Args[1].Kind == asm.OpReg {
			// Compact encoder 3-op form: $imm, Rn, Rd
			width = ins.Args[0].Imm & 31
			if width == 0 {
				width = 1
			}
			lsb = 0
			srcOp = ins.Args[1]
			dstOp = ins.Args[2]
		} else {
			if ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpImm {
				return fmt.Errorf("arm %s expects $width, $lsb: %q", spec.Op, ins.Raw)
			}
			width = ins.Args[0].Imm
			lsb = ins.Args[1].Imm
			dstOp = ins.Args[len(ins.Args)-1]
			srcOp = dstOp
			if len(ins.Args) == 4 {
				srcOp = ins.Args[2]
			}
		}
		if width <= 0 || lsb < 0 || lsb+width > 32 {
			return fmt.Errorf("arm %s invalid width=%d lsb=%d: %q", spec.Op, width, lsb, ins.Raw)
		}
		if dstOp.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", spec.Op, ins.Raw)
		}
		mask := uint32(0xffffffff)
		if width < 32 {
			mask = (uint32(1) << uint(width)) - 1
		}
		switch spec.LLVMOp {
		case "bfc":
			dstV, err := c.loadReg(dstOp.Reg)
			if err != nil {
				return err
			}
			clearMask := ^(mask << uint(lsb))
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", res, dstV, int32(clearMask))
			return c.selectRegWrite(dstOp.Reg, cond, "%"+res)
		case "bfi":
			srcV, err := c.eval32(srcOp, false)
			if err != nil {
				return err
			}
			dstV, err := c.loadReg(dstOp.Reg)
			if err != nil {
				return err
			}
			clearMask := ^(mask << uint(lsb))
			cleared := c.newTmp()
			masked := c.newTmp()
			shifted := c.newTmp()
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", cleared, dstV, int32(clearMask))
			fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", masked, srcV, int32(mask))
			fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %d\n", shifted, masked, lsb)
			fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", res, cleared, shifted)
			return c.selectRegWrite(dstOp.Reg, cond, "%"+res)
		case "bfx":
			srcV, err := c.eval32(srcOp, false)
			if err != nil {
				return err
			}
			if spec.Signed {
				topShift := 32 - (lsb + width)
				lsh := srcV
				if topShift > 0 {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %d\n", t, srcV, topShift)
					lsh = "%" + t
				}
				rsh := 32 - width
				out := lsh
				if rsh > 0 {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, %d\n", t, lsh, rsh)
					out = "%" + t
				}
				return c.selectRegWrite(dstOp.Reg, cond, out)
			}
			shifted := srcV
			if lsb > 0 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %d\n", t, srcV, lsb)
				shifted = "%" + t
			}
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", res, shifted, int32(mask))
			return c.selectRegWrite(dstOp.Reg, cond, "%"+res)
		}
	}
	return fmt.Errorf("arm: unhandled declarative bit op %s", spec.Op)
}

func (c *armCtx) lowerARMDeclarativeMulDiv(spec asm.OpSpec, cond string, ins asm.Instr) error {
	switch spec.LLVMOp {
	case "sdiv", "udiv", "srem", "urem":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return fmt.Errorf("arm %s expects 2 or 3 operands: %q", spec.Op, ins.Raw)
		}
		divisor, err := c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		var numer string
		var dst asm.Operand
		if len(ins.Args) == 2 {
			dst = ins.Args[1]
			if dst.Kind != asm.OpReg {
				return fmt.Errorf("arm %s dst must be reg: %q", spec.Op, ins.Raw)
			}
			numer, err = c.loadReg(dst.Reg)
		} else {
			dst = ins.Args[2]
			if dst.Kind != asm.OpReg {
				return fmt.Errorf("arm %s dst must be reg: %q", spec.Op, ins.Raw)
			}
			numer, err = c.eval32(ins.Args[1], false)
		}
		if err != nil {
			return err
		}
		zero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", zero, divisor)
		safeDiv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 1, i32 %s\n", safeDiv, zero, divisor)
		if spec.LLVMOp == "sdiv" || spec.LLVMOp == "srem" {
			// Guard INT32_MIN / -1 UB in LLVM sdiv/srem.
			isMin := c.newTmp()
			isNeg1 := c.newTmp()
			ov := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, -2147483648\n", isMin, numer)
			fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, -1\n", isNeg1, safeDiv)
			fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", ov, isMin, isNeg1)
			safeDiv2 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 1, i32 %%%s\n", safeDiv2, ov, safeDiv)
			q := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %%%s\n", q, spec.LLVMOp, numer, safeDiv2)
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 0, i32 %%%s\n", sel, zero, q)
			return c.selectRegWrite(dst.Reg, cond, "%"+sel)
		}
		q := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %%%s\n", q, spec.LLVMOp, numer, safeDiv)
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 0, i32 %%%s\n", sel, zero, q)
		return c.selectRegWrite(dst.Reg, cond, "%"+sel)

	case "mull":
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpRegList || len(ins.Args[2].RegList) != 2 {
			return fmt.Errorf("arm MULL expects a, b, (hi,lo): %q", ins.Raw)
		}
		a, err := c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		b, err := c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
		a64, b64 := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", a64, a)
		fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", b64, b)
		prod := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", prod, a64, b64)
		lo, hiSh, hi := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo, prod)
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hiSh, prod)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, hiSh)
		return c.selectRegPairWrite(ins.Args[2].RegList[0], ins.Args[2].RegList[1], cond, "%"+hi, "%"+lo)

	case "muls":
		if len(ins.Args) != 4 || ins.Args[3].Kind != asm.OpReg {
			return fmt.Errorf("arm MULS expects a, b, acc, dst: %q", ins.Raw)
		}
		a, err := c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		b, err := c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
		acc, err := c.eval32(ins.Args[2], false)
		if err != nil {
			return err
		}
		prod, res := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", prod, a, b)
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %%%s\n", res, acc, prod)
		return c.selectRegWrite(ins.Args[3].Reg, cond, "%"+res)

	case "mmul", "mmula", "mmuls":
		want := 3
		if spec.LLVMOp != "mmul" {
			want = 4
		}
		if len(ins.Args) != want || ins.Args[want-1].Kind != asm.OpReg {
			return fmt.Errorf("arm %s expects %d operands: %q", spec.Op, want, ins.Raw)
		}
		a, err := c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		b, err := c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
		a64, b64, prod, hiSh, hi := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", a64, a)
		fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", b64, b)
		fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", prod, a64, b64)
		fmt.Fprintf(c.b, "  %%%s = ashr i64 %%%s, 32\n", hiSh, prod)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, hiSh)
		out := "%" + hi
		if spec.LLVMOp != "mmul" {
			acc, err := c.eval32(ins.Args[2], false)
			if err != nil {
				return err
			}
			res := c.newTmp()
			if spec.LLVMOp == "mmula" {
				fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", res, acc, out)
			} else {
				fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", res, acc, out)
			}
			out = "%" + res
		}
		return c.selectRegWrite(ins.Args[want-1].Reg, cond, out)

	default:
		// Halfword multiply family: MUL{,A}{B,T,W}{B,T}
		key := spec.LLVMOp
		hasAcc := strings.HasPrefix(key, "mula")
		suffix := strings.TrimPrefix(strings.TrimPrefix(key, "mula"), "mul")
		if len(suffix) != 2 {
			return fmt.Errorf("arm: unsupported multiply op %s", spec.Op)
		}
		want := 3
		if hasAcc {
			want = 4
		}
		if len(ins.Args) != want || ins.Args[want-1].Kind != asm.OpReg {
			return fmt.Errorf("arm %s expects %d operands: %q", spec.Op, want, ins.Raw)
		}
		a, err := c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		b, err := c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
		extractHalf := func(v string, sel byte) string {
			s := v
			if sel == 't' {
				sh := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, 16\n", sh, v)
				s = "%" + sh
			}
			tr := c.newTmp()
			se := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", tr, s)
			fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i32\n", se, tr)
			return "%" + se
		}
		var out string
		if suffix[0] == 'w' {
			// SMULW{B,T}: (sext64(a) * sext64(half(b))) >> 16
			bh := extractHalf(b, suffix[1])
			a64, b64, prod, sh, tr := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", a64, a)
			fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", b64, bh)
			fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", prod, a64, b64)
			fmt.Fprintf(c.b, "  %%%s = ashr i64 %%%s, 16\n", sh, prod)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", tr, sh)
			out = "%" + tr
		} else {
			ah := extractHalf(a, suffix[0])
			bh := extractHalf(b, suffix[1])
			prod := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", prod, ah, bh)
			out = "%" + prod
		}
		if hasAcc {
			acc, err := c.eval32(ins.Args[2], false)
			if err != nil {
				return err
			}
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", sum, out, acc)
			out = "%" + sum
		}
		return c.selectRegWrite(ins.Args[want-1].Reg, cond, out)
	}
}

func (c *armCtx) armLoadFloat(op asm.Operand, bits uint16) (string, error) {
	if bits == 64 {
		switch op.Kind {
		case asm.OpReg:
			raw, err := c.loadFReg(op.Reg)
			if err != nil {
				return "", err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, raw)
			return "%" + t, nil
		case asm.OpImm:
			return asm.FormatLLVMFloat64Literal(float64(op.Imm)), nil
		case asm.OpSym:
			if fv, ok := parseARMFloatDollar(op.Sym); ok {
				return asm.FormatLLVMFloat64Literal(fv), nil
			}
		}
		return "", fmt.Errorf("arm: unsupported f64 operand %s", op.String())
	}
	switch op.Kind {
	case asm.OpReg:
		raw, err := c.loadFReg(op.Reg)
		if err != nil {
			return "", err
		}
		tr, bc := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, raw)
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", bc, tr)
		return "%" + bc, nil
	case asm.OpImm:
		return asm.FormatLLVMFloat64Literal(float64(float32(op.Imm))), nil
	case asm.OpSym:
		if fv, ok := parseARMFloatDollar(op.Sym); ok {
			return asm.FormatLLVMFloat64Literal(float64(float32(fv))), nil
		}
	}
	return "", fmt.Errorf("arm: unsupported f32 operand %s", op.String())
}

func (c *armCtx) armStoreFloat(dst asm.Reg, cond string, val string, bits uint16) error {
	var raw64 string
	if bits == 64 {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", bc, val)
		raw64 = "%" + bc
	} else {
		bc, ext := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", bc, val)
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", ext, bc)
		raw64 = "%" + ext
	}
	if cond == "" || strings.EqualFold(cond, "AL") {
		return c.storeFReg(dst, raw64)
	}
	cv, err := c.condValue(cond)
	if err != nil {
		return err
	}
	oldV, err := c.loadFReg(dst)
	if err != nil {
		return err
	}
	sel := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", sel, cv, raw64, oldV)
	return c.storeFReg(dst, "%"+sel)
}

func parseARMFloatDollar(sym string) (float64, bool) {
	if !strings.HasPrefix(sym, "$") {
		return 0, false
	}
	s := strings.TrimSpace(strings.TrimPrefix(sym, "$"))
	if fv, err := strconv.ParseFloat(s, 64); err == nil {
		return fv, true
	}
	return 0, false
}

func (c *armCtx) lowerARMDeclarativeFP(spec asm.OpSpec, cond string, ins asm.Instr) error {
	ty := "float"
	suf := "f32"
	if spec.Width == 64 {
		ty = "double"
		suf = "f64"
	}
	switch spec.LLVMOp {
	case "fadd", "fsub", "fmul", "fdiv", "fnmul":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return fmt.Errorf("arm %s expects 2 or 3 operands: %q", spec.Op, ins.Raw)
		}
		dst := ins.Args[len(ins.Args)-1]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be Freg: %q", spec.Op, ins.Raw)
		}
		src, err := c.armLoadFloat(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		var lhs string
		if len(ins.Args) == 2 {
			lhs, err = c.armLoadFloat(dst, spec.Width)
		} else {
			lhs, err = c.armLoadFloat(ins.Args[1], spec.Width)
		}
		if err != nil {
			return err
		}
		if spec.LLVMOp == "fnmul" {
			m, neg := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fmul %s %s, %s\n", m, ty, lhs, src)
			fmt.Fprintf(c.b, "  %%%s = fneg %s %%%s\n", neg, ty, m)
			return c.armStoreFloat(dst.Reg, cond, "%"+neg, spec.Width)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", out, spec.LLVMOp, ty, lhs, src)
		return c.armStoreFloat(dst.Reg, cond, "%"+out, spec.Width)

	case "fabs", "fneg", "fsqrt":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm %s expects src, dst: %q", spec.Op, ins.Raw)
		}
		src, err := c.armLoadFloat(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		out := c.newTmp()
		switch spec.LLVMOp {
		case "fneg":
			fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", out, ty, src)
		case "fabs":
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %s)\n", out, ty, suf, ty, src)
		case "fsqrt":
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.%s(%s %s)\n", out, ty, suf, ty, src)
		}
		return c.armStoreFloat(ins.Args[1].Reg, cond, "%"+out, spec.Width)

	case "fcmp":
		if len(ins.Args) != 1 && len(ins.Args) != 2 {
			return fmt.Errorf("arm %s expects 1 or 2 operands: %q", spec.Op, ins.Raw)
		}
		lhs, err := c.armLoadFloat(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		rhs := "0.0"
		if len(ins.Args) == 2 {
			rhs, err = c.armLoadFloat(ins.Args[1], spec.Width)
			if err != nil {
				return err
			}
		}
		eq, lt, gt, uno := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp oeq %s %s, %s\n", eq, ty, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = fcmp olt %s %s, %s\n", lt, ty, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = fcmp ogt %s %s, %s\n", gt, ty, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = fcmp uno %s %s, %s\n", uno, ty, lhs, rhs)
		c01, cf := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", c01, gt, eq)
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", cf, c01, uno)
		c.flagsWritten = true
		if err := c.storeFlagCond(cond, c.flagsNSlot, "%"+lt); err != nil {
			return err
		}
		if err := c.storeFlagCond(cond, c.flagsZSlot, "%"+eq); err != nil {
			return err
		}
		if err := c.storeFlagCond(cond, c.flagsCSlot, "%"+cf); err != nil {
			return err
		}
		return c.storeFlagCond(cond, c.flagsVSlot, "%"+uno)

	case "f2f":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm %s expects Fsrc, Fdst: %q", spec.Op, ins.Raw)
		}
		src, err := c.armLoadFloat(ins.Args[0], spec.SrcWidth)
		if err != nil {
			return err
		}
		out := c.newTmp()
		if spec.Width == 32 {
			fmt.Fprintf(c.b, "  %%%s = fptrunc double %s to float\n", out, src)
		} else {
			fmt.Fprintf(c.b, "  %%%s = fpext float %s to double\n", out, src)
		}
		return c.armStoreFloat(ins.Args[1].Reg, cond, "%"+out, spec.Width)

	case "f2i":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm %s expects Fsrc, dst: %q", spec.Op, ins.Raw)
		}
		src, err := c.armLoadFloat(ins.Args[0], spec.SrcWidth)
		if err != nil {
			return err
		}
		srcTy := "float"
		if spec.SrcWidth == 64 {
			srcTy = "double"
		}
		iv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptosi %s %s to i32\n", iv, srcTy, src)
		if strings.HasPrefix(string(ins.Args[1].Reg), "F") {
			ext := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", ext, iv)
			if cond == "" || strings.EqualFold(cond, "AL") {
				return c.storeFReg(ins.Args[1].Reg, "%"+ext)
			}
			cv, err := c.condValue(cond)
			if err != nil {
				return err
			}
			oldV, err := c.loadFReg(ins.Args[1].Reg)
			if err != nil {
				return err
			}
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %%%s, i64 %s\n", sel, cv, ext, oldV)
			return c.storeFReg(ins.Args[1].Reg, "%"+sel)
		}
		return c.selectRegWrite(ins.Args[1].Reg, cond, "%"+iv)

	case "i2f":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm %s expects src, Fdst: %q", spec.Op, ins.Raw)
		}
		var iv string
		if ins.Args[0].Kind == asm.OpReg && strings.HasPrefix(string(ins.Args[0].Reg), "F") {
			raw, err := c.loadFReg(ins.Args[0].Reg)
			if err != nil {
				return err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, raw)
			iv = "%" + tr
		} else {
			var err error
			iv, err = c.eval32(ins.Args[0], false)
			if err != nil {
				return err
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sitofp i32 %s to %s\n", out, iv, ty)
		return c.armStoreFloat(ins.Args[1].Reg, cond, "%"+out, spec.Width)

	case "mula", "muls", "nmula", "nmuls", "fmula", "fmuls", "fnmula", "fnmuls":
		if (len(ins.Args) != 2 && len(ins.Args) != 3) || ins.Args[len(ins.Args)-1].Kind != asm.OpReg {
			return fmt.Errorf("arm %s expects [Fa,] Fb, Fdst: %q", spec.Op, ins.Raw)
		}
		dstOp := ins.Args[len(ins.Args)-1]
		a, err := c.armLoadFloat(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		var b string
		if len(ins.Args) == 3 {
			b, err = c.armLoadFloat(ins.Args[1], spec.Width)
		} else {
			b, err = c.armLoadFloat(dstOp, spec.Width)
		}
		if err != nil {
			return err
		}
		acc, err := c.armLoadFloat(dstOp, spec.Width)
		if err != nil {
			return err
		}
		fused := strings.HasPrefix(spec.LLVMOp, "f")
		base := strings.TrimPrefix(spec.LLVMOp, "f")
		negAcc := strings.HasPrefix(base, "n")
		isSub := strings.HasSuffix(base, "s")
		if fused {
			if isSub != negAcc {
				na := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", na, ty, a)
				a = "%" + na
			}
			if negAcc {
				nc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", nc, ty, acc)
				acc = "%" + nc
			}
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.%s(%s %s, %s %s, %s %s)\n", res, ty, suf, ty, a, ty, b, ty, acc)
			return c.armStoreFloat(dstOp.Reg, cond, "%"+res, spec.Width)
		}
		prod := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fmul %s %s, %s\n", prod, ty, a, b)
		if isSub {
			res := c.newTmp()
			if negAcc {
				fmt.Fprintf(c.b, "  %%%s = fsub %s %%%s, %s\n", res, ty, prod, acc)
			} else {
				fmt.Fprintf(c.b, "  %%%s = fsub %s %s, %%%s\n", res, ty, acc, prod)
			}
			return c.armStoreFloat(dstOp.Reg, cond, "%"+res, spec.Width)
		}
		sum := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fadd %s %s, %%%s\n", sum, ty, acc, prod)
		out := "%" + sum
		if negAcc {
			neg := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg %s %%%s\n", neg, ty, sum)
			out = "%" + neg
		}
		return c.armStoreFloat(dstOp.Reg, cond, out, spec.Width)
	}
	return fmt.Errorf("arm: unhandled declarative FP op %s", spec.Op)
}

func (c *armCtx) lowerARMMOVFOrD(op, cond string, postInc bool, ins asm.Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("arm %s expects 2 operands: %q", op, ins.Raw)
	}
	bits := 64
	if op == "MOVF" {
		bits = 32
	}
	src, dst := ins.Args[0], ins.Args[1]
	if cond != "" && (dst.Kind == asm.OpMem || dst.Kind == asm.OpSym || dst.Kind == asm.OpFP) {
		return c.emitConditionalEffect(cond, func() error {
			return c.lowerARMMOVFOrD(op, "", postInc, ins)
		})
	}
	isF := func(o asm.Operand) bool {
		return o.Kind == asm.OpReg && strings.HasPrefix(string(o.Reg), "F")
	}
	loadRaw := func(o asm.Operand) (string, error) {
		switch {
		case isF(o):
			raw, err := c.loadFReg(o.Reg)
			if err != nil {
				return "", err
			}
			if bits == 32 {
				tr := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, raw)
				return "%" + tr, nil
			}
			return raw, nil
		case o.Kind == asm.OpMem:
			return c.loadMem(o.Mem, bits, postInc, false)
		case o.Kind == asm.OpFP:
			if bits == 32 {
				return c.evalFPValue32(o)
			}
			return c.evalFPValue64(o)
		case o.Kind == asm.OpSym:
			if fv, ok := parseARMFloatDollar(o.Sym); ok {
				if bits == 32 {
					return strconv.FormatInt(int64(int32(math.Float32bits(float32(fv)))), 10), nil
				}
				return strconv.FormatInt(int64(math.Float64bits(fv)), 10), nil
			}
			p, err := c.ptrFromSB(o.Sym)
			if err != nil {
				return "", err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s\n", t, bits, p)
			return "%" + t, nil
		case o.Kind == asm.OpImm:
			if bits == 32 {
				return strconv.FormatInt(int64(int32(math.Float32bits(float32(o.Imm)))), 10), nil
			}
			return strconv.FormatInt(int64(math.Float64bits(float64(o.Imm))), 10), nil
		default:
			return "", fmt.Errorf("arm %s unsupported src: %q", op, ins.Raw)
		}
	}
	val, err := loadRaw(src)
	if err != nil {
		return err
	}
	switch {
	case isF(dst):
		v64 := val
		if bits == 32 {
			ext := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", ext, val)
			v64 = "%" + ext
		}
		if cond == "" || strings.EqualFold(cond, "AL") {
			return c.storeFReg(dst.Reg, v64)
		}
		cv, err := c.condValue(cond)
		if err != nil {
			return err
		}
		oldV, err := c.loadFReg(dst.Reg)
		if err != nil {
			return err
		}
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", sel, cv, v64, oldV)
		return c.storeFReg(dst.Reg, "%"+sel)
	case dst.Kind == asm.OpMem:
		return c.storeMem(dst.Mem, bits, postInc, val)
	case dst.Kind == asm.OpFP:
		if bits == 32 {
			return c.storeFP32(dst.FPOffset, val)
		}
		return c.storeFP64(dst.FPOffset, val)
	case dst.Kind == asm.OpSym:
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i%d %s, ptr %s\n", bits, val, p)
		return nil
	default:
		return fmt.Errorf("arm %s unsupported dst: %q", op, ins.Raw)
	}
}
