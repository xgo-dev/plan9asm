package arm64

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

var arm64ExtraScalarSpecs = []asm.OpSpec{
	// 32/64-bit ALU & flag-setting variants missing from lower_arith.go
	{Op: "ADDSW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "add"},
	{Op: "ADCW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsRead, LLVMOp: "adc"},
	{Op: "ADCSW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsReadWrite, LLVMOp: "adc"},
	{Op: "SBCW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsRead, LLVMOp: "sbc"},
	{Op: "SBCSW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsReadWrite, LLVMOp: "sbc"},
	{Op: "BICS", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "bic"},
	{Op: "BICSW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "bic"},
	{Op: "EON", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "eon"},
	{Op: "EONW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "eon"},
	{Op: "ORN", Family: asm.FamilyALU, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "orn"},
	{Op: "ORNW", Family: asm.FamilyALU, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "orn"},
	{Op: "CMNW", Family: asm.FamilyCompare, Width: 32, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "cmn"},
	{Op: "NEGS", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "neg"},
	{Op: "NEGSW", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "neg"},
	{Op: "NGC", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsRead, LLVMOp: "ngc"},
	{Op: "NGCW", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsRead, LLVMOp: "ngc"},
	{Op: "NGCS", Family: asm.FamilyALU, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsReadWrite, LLVMOp: "ngc"},
	{Op: "NGCSW", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsReadWrite, LLVMOp: "ngc"},

	// Sign/Zero extend
	{Op: "SXTB", Family: asm.FamilyMove, Width: 64, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ext"},
	{Op: "SXTBW", Family: asm.FamilyMove, Width: 32, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ext"},
	{Op: "SXTH", Family: asm.FamilyMove, Width: 64, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ext"},
	{Op: "SXTHW", Family: asm.FamilyMove, Width: 32, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ext"},
	{Op: "SXTW", Family: asm.FamilyMove, Width: 64, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ext"},
	{Op: "UXTBW", Family: asm.FamilyMove, Width: 32, SrcWidth: 8, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ext"},
	{Op: "UXTHW", Family: asm.FamilyMove, Width: 32, SrcWidth: 16, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ext"},
	{Op: "MOVK", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectReadWrite, LLVMOp: "movk"},
	{Op: "LDPSW", Family: asm.FamilyMove, Width: 64, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ldpsw"},

	// Bit ops
	{Op: "CLZW", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "clz"},
	{Op: "CLS", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "cls"},
	{Op: "CLSW", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "cls"},
	{Op: "RBITW", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "rbit"},
	{Op: "EXTRW", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "extr"},

	// Mul / Div
	{Op: "SDIV", Family: asm.FamilyMulDiv, Width: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sdiv"},
	{Op: "SDIVW", Family: asm.FamilyMulDiv, Width: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sdiv"},
	{Op: "UDIV", Family: asm.FamilyMulDiv, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "udiv"},
	{Op: "UDIVW", Family: asm.FamilyMulDiv, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "udiv"},
	{Op: "MNEG", Family: asm.FamilyMulDiv, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mneg"},
	{Op: "MNEGW", Family: asm.FamilyMulDiv, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "mneg"},
	{Op: "SMULL", Family: asm.FamilyMulDiv, Width: 64, SrcWidth: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mull"},
	{Op: "UMULL", Family: asm.FamilyMulDiv, Width: 64, SrcWidth: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mull"},
	{Op: "SMADDL", Family: asm.FamilyMulDiv, Width: 64, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "maddl"},
	{Op: "UMADDL", Family: asm.FamilyMulDiv, Width: 64, SrcWidth: 32, Effect: asm.EffectWriteOnly, LLVMOp: "maddl"},
	{Op: "SMSUBL", Family: asm.FamilyMulDiv, Width: 64, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "msubl"},
	{Op: "UMSUBL", Family: asm.FamilyMulDiv, Width: 64, SrcWidth: 32, Effect: asm.EffectWriteOnly, LLVMOp: "msubl"},
	{Op: "SMNEGL", Family: asm.FamilyMulDiv, Width: 64, SrcWidth: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mnegl"},
	{Op: "UMNEGL", Family: asm.FamilyMulDiv, Width: 64, SrcWidth: 32, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mnegl"},
	{Op: "SMULH", Family: asm.FamilyMulDiv, Width: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "smulh"},

	// PAC / BTI / System / Hints
	{Op: "PACIASP", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "hint #25"},
	{Op: "PACIBSP", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "hint #27"},
	{Op: "AUTIASP", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "hint #29"},
	{Op: "AUTIBSP", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "hint #31"},
	{Op: "AUTIA1716", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "hint #12"},
	{Op: "AUTIB1716", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "hint #14"},
	{Op: "BTI", Family: asm.FamilySystem, Effect: asm.EffectNone, LLVMOp: "nop"},
	{Op: "HINT", Family: asm.FamilySystem, Effect: asm.EffectNone, LLVMOp: "nop"},
	{Op: "NOOP", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "END", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "WFE", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "wfe"},
	{Op: "WFI", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "wfi"},
	{Op: "SEV", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "sev"},
	{Op: "SEVL", Family: asm.FamilySystem, Effect: asm.EffectNone, InlineAsm: "sevl"},
	{Op: "CLREX", Family: asm.FamilySystem, Effect: asm.EffectNone, LLVMOp: "clrex"},
	{Op: "RPRFM", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "nop"},
}

var arm64ExtraScalarTable = asm.NewOpTable(arm64ExtraScalarSpecs)

func (c *arm64Ctx) lowerScalarDeclarative(op asm.Op, postInc bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	spec, found := arm64ExtraScalarTable.Lookup(op)
	if !found {
		return false, false, nil
	}
	switch spec.Family {
	case asm.FamilyNOP:
		return true, false, nil
	case asm.FamilySystem:
		if spec.LLVMOp == "clrex" {
			if !c.nativeAArch64 {
				return true, false, fmt.Errorf("%w: CLREX needs an AArch64 target", asm.ErrProbeNeedsContext)
			}
			c.b.WriteString("  call void asm sideeffect \"clrex\", \"~{memory}\"()\n")
			return true, false, nil
		}
		if spec.InlineAsm != "" {
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", spec.InlineAsm, "~{memory}")
		}
		return true, false, nil
	case asm.FamilyCompare:
		if spec.LLVMOp == "cmn" {
			if len(ins.Args) != 2 {
				return true, false, fmt.Errorf("arm64 CMNW expects 2 operands: %q", ins.Raw)
			}
			src, err := c.eval32(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			dst, err := c.eval32(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", sum, dst, src)
			c.setFlagsAdd32(dst, src, "%"+sum)
			return true, false, nil
		}
	case asm.FamilyMove:
		return true, false, c.lowerARM64ExtraMove(spec, postInc, ins)
	case asm.FamilyALU:
		return true, false, c.lowerARM64ExtraALU(spec, ins)
	case asm.FamilyBit:
		return true, false, c.lowerARM64ExtraBit(spec, ins)
	case asm.FamilyMulDiv:
		return true, false, c.lowerARM64ExtraMulDiv(spec, ins)
	}
	return false, false, nil
}

func (c *arm64Ctx) storeWidth(dst asm.Reg, val string, width uint16) error {
	if width == 32 {
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, val)
		val = "%" + z
	}
	return c.storeReg(dst, val)
}

func (c *arm64Ctx) evalWidth(op asm.Operand, width uint16) (string, error) {
	if width == 32 {
		return c.eval32(op)
	}
	return c.eval64(op, false)
}

func (c *arm64Ctx) lowerARM64ExtraMove(spec asm.OpSpec, postInc bool, ins asm.Instr) error {
	switch spec.LLVMOp {
	case "ext":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects src, dstReg: %q", spec.Op, ins.Raw)
		}
		v64, err := c.eval64(ins.Args[0], false)
		if err != nil {
			return err
		}
		srcTy := fmt.Sprintf("i%d", spec.SrcWidth)
		dstTy := fmt.Sprintf("i%d", spec.Width)
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v64, srcTy)
		ext := c.newTmp()
		if spec.Signed {
			fmt.Fprintf(c.b, "  %%%s = sext %s %%%s to %s\n", ext, srcTy, tr, dstTy)
		} else {
			fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to %s\n", ext, srcTy, tr, dstTy)
		}
		return c.storeWidth(ins.Args[1].Reg, "%"+ext, spec.Width)

	case "movk":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 MOVK expects $imm, dstReg: %q", ins.Raw)
		}
		imm := uint64(ins.Args[0].Imm)
		shift := uint(0)
		for s := uint(0); s < 64; s += 16 {
			if (imm & ^(uint64(0xffff) << s)) == 0 {
				shift = s
				break
			}
		}
		keepMask := ^(uint64(0xffff) << shift)
		old, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return err
		}
		kept, merged := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", kept, old, int64(keepMask))
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %d\n", merged, kept, int64(imm))
		return c.storeReg(ins.Args[1].Reg, "%"+merged)

	case "ldpsw":
		var regs []asm.Reg
		if len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpRegList && len(ins.Args[1].RegList) == 2 {
			regs = ins.Args[1].RegList
		} else if len(ins.Args) == 3 && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpReg {
			regs = []asm.Reg{ins.Args[1].Reg, ins.Args[2].Reg}
		} else {
			return fmt.Errorf("arm64 LDPSW expects mem/sym, (r1, r2): %q", ins.Raw)
		}
		preInc := strings.Contains(strings.ToUpper(string(ins.Op)), ".W")
		ptr, base, inc, update, err := c.arm64PairPtr(ins.Args[0], preInc, postInc)
		if err != nil {
			return err
		}
		for i, r := range regs {
			p := ptr
			if i != 0 {
				gp := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 4\n", gp, ptr)
				p = "%" + gp
			}
			ld, se := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s\n", ld, p)
			fmt.Fprintf(c.b, "  %%%s = sext i32 %%%s to i64\n", se, ld)
			if err := c.storeReg(r, "%"+se); err != nil {
				return err
			}
		}
		if update {
			return c.updatePostInc(base, inc)
		}
		return nil
	}
	return fmt.Errorf("arm64: unhandled move %s", spec.Op)
}

func (c *arm64Ctx) lowerARM64ExtraALU(spec asm.OpSpec, ins asm.Instr) error {
	ty := fmt.Sprintf("i%d", spec.Width)
	switch spec.LLVMOp {
	case "neg", "ngc":
		if (len(ins.Args) != 1 && len(ins.Args) != 2) || ins.Args[len(ins.Args)-1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects [src,] dstReg: %q", spec.Op, ins.Raw)
		}
		dstReg := ins.Args[len(ins.Args)-1].Reg
		src, err := c.evalWidth(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		var res string
		var cf string
		if spec.LLVMOp == "neg" {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", t, ty, src)
			res = "%" + t
		} else {
			cf = c.newTmp()
			if err := c.requireFlags(string(spec.Op)); err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", cf, c.flagsCSlot)
			ncf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", ncf, cf)
			borrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to %s\n", borrow, ncf, ty)
			t0, t1 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", t0, ty, src)
			fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", t1, ty, t0, borrow)
			res = "%" + t1
		}
		if err := c.storeWidth(dstReg, res, spec.Width); err != nil {
			return err
		}
		if spec.Flags == asm.FlagsWrite || spec.Flags == asm.FlagsReadWrite {
			if spec.LLVMOp == "ngc" {
				nsrc := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", nsrc, ty, src)
				c.setFlagsAddWithCarry(spec.Width, "0", "%"+nsrc, "%"+cf, res)
			} else if spec.Width == 32 {
				c.setFlagsSub32("0", src, res)
			} else {
				c.setFlagsSub("0", src, res)
			}
		}
		return nil

	default:
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", spec.Op, ins.Raw)
		}
		dstOp := ins.Args[len(ins.Args)-1]
		if dstOp.Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s dst must be reg: %q", spec.Op, ins.Raw)
		}
		src, err := c.evalWidth(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		var lhs string
		if len(ins.Args) == 2 {
			lhs, err = c.evalWidth(dstOp, spec.Width)
		} else {
			lhs, err = c.evalWidth(ins.Args[1], spec.Width)
		}
		if err != nil {
			return err
		}
		var res string
		switch spec.LLVMOp {
		case "add":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", t, ty, lhs, src)
			res = "%" + t
			if err := c.storeWidth(dstOp.Reg, res, spec.Width); err != nil {
				return err
			}
			if spec.Flags == asm.FlagsWrite {
				if spec.Width == 32 {
					c.setFlagsAdd32(lhs, src, res)
				} else {
					c.setFlagsAdd(lhs, src, res)
				}
			}
			return nil
		case "adc", "sbc":
			cf := c.newTmp()
			if err := c.requireFlags(string(spec.Op)); err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", cf, c.flagsCSlot)
			cin := c.newTmp()
			if spec.LLVMOp == "sbc" {
				ncf := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", ncf, cf)
				fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to %s\n", cin, ncf, ty)
			} else {
				fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to %s\n", cin, cf, ty)
			}
			t0, t1 := c.newTmp(), c.newTmp()
			if spec.LLVMOp == "sbc" {
				fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", t0, ty, lhs, src)
				fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", t1, ty, t0, cin)
			} else {
				fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", t0, ty, lhs, src)
				fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", t1, ty, t0, cin)
			}
			res = "%" + t1
			if err := c.storeWidth(dstOp.Reg, res, spec.Width); err != nil {
				return err
			}
			if spec.Flags == asm.FlagsReadWrite {
				if spec.LLVMOp == "adc" {
					c.setFlagsAddWithCarry(spec.Width, lhs, src, "%"+cf, res)
				} else {
					nsrc := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", nsrc, ty, src)
					c.setFlagsAddWithCarry(spec.Width, lhs, "%"+nsrc, "%"+cf, res)
				}
			}
			return nil
		case "bic", "eon", "orn":
			inv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inv, ty, src)
			llvmBin := map[string]string{"bic": "and", "eon": "xor", "orn": "or"}[spec.LLVMOp]
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", t, llvmBin, ty, lhs, inv)
			res = "%" + t
			if err := c.storeWidth(dstOp.Reg, res, spec.Width); err != nil {
				return err
			}
			if spec.Flags == asm.FlagsWrite {
				if spec.Width == 32 {
					c.setFlagsLogic32(res)
				} else {
					c.setFlagsLogic(res)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("arm64: unhandled ALU %s", spec.Op)
}

func (c *arm64Ctx) lowerARM64ExtraBit(spec asm.OpSpec, ins asm.Instr) error {
	ty := fmt.Sprintf("i%d", spec.Width)
	switch spec.LLVMOp {
	case "clz":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects src, dstReg: %q", spec.Op, ins.Raw)
		}
		src, err := c.evalWidth(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.%s(%s %s, i1 false)\n", t, ty, ty, ty, src)
		return c.storeWidth(ins.Args[1].Reg, "%"+t, spec.Width)

	case "cls":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects src, dstReg: %q", spec.Op, ins.Raw)
		}
		src, err := c.evalWidth(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		// Count leading sign bits = ctlz((x << 1) ^ (x ashr (W-1))) - ... actually ctlz(x ^ (x ashr 1)) - 1?
		// Exact AArch64 CLS(x): sign = ashr x, W-1; diff = xor x, sign; cls = ctlz(diff, false) - 1 (clamped at W-1 for 0/-1).
		sign, diff, lz, isZero, sub1, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %d\n", sign, ty, src, spec.Width-1)
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", diff, ty, src, sign)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.%s(%s %%%s, i1 false)\n", lz, ty, ty, ty, diff)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", isZero, ty, diff)
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, 1\n", sub1, ty, lz)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %d, %s %%%s\n", out, isZero, ty, spec.Width-1, ty, sub1)
		return c.storeWidth(ins.Args[1].Reg, "%"+out, spec.Width)

	case "rbit":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects src, dstReg: %q", spec.Op, ins.Raw)
		}
		src, err := c.evalWidth(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.bitreverse.%s(%s %s)\n", t, ty, ty, ty, src)
		return c.storeWidth(ins.Args[1].Reg, "%"+t, spec.Width)

	case "extr":
		if len(ins.Args) != 4 || ins.Args[0].Kind != asm.OpImm || ins.Args[3].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects $lsb, rm, rn, dstReg: %q", spec.Op, ins.Raw)
		}
		lsb := ins.Args[0].Imm & 31
		rm, err := c.eval32(ins.Args[1])
		if err != nil {
			return err
		}
		rn, err := c.eval32(ins.Args[2])
		if err != nil {
			return err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.fshr.i32(i32 %s, i32 %s, i32 %d)\n", t, rn, rm, lsb)
		return c.storeWidth(ins.Args[3].Reg, "%"+t, 32)
	}
	return fmt.Errorf("arm64: unhandled bit op %s", spec.Op)
}

func (c *arm64Ctx) lowerARM64ExtraMulDiv(spec asm.OpSpec, ins asm.Instr) error {
	ty := fmt.Sprintf("i%d", spec.Width)
	switch spec.LLVMOp {
	case "sdiv", "udiv", "srem", "urem":
		if (len(ins.Args) != 2 && len(ins.Args) != 3) || ins.Args[len(ins.Args)-1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects divisor, [numer,] dstReg: %q", spec.Op, ins.Raw)
		}
		dstReg := ins.Args[len(ins.Args)-1].Reg
		divisor, err := c.evalWidth(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		numer, err := c.evalWidth(ins.Args[1], spec.Width)
		if err != nil {
			return err
		}
		zero, safeDiv := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zero, ty, divisor)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 1, %s %s\n", safeDiv, zero, ty, ty, divisor)
		divIn := "%" + safeDiv
		if spec.Signed {
			minLit := "-9223372036854775808"
			if spec.Width == 32 {
				minLit = "-2147483648"
			}
			isMin, isNeg1, ov, safeDiv2 := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", isMin, ty, numer, minLit)
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, -1\n", isNeg1, ty, divIn)
			fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", ov, isMin, isNeg1)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 1, %s %s\n", safeDiv2, ov, ty, ty, divIn)
			divIn = "%" + safeDiv2
		}
		q, sel := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", q, spec.LLVMOp, ty, numer, divIn)
		zeroResult := "0"
		if spec.LLVMOp == "srem" || spec.LLVMOp == "urem" {
			// Go expands REM to DIV and MSUB: n - (n / d) * d.
			zeroResult = numer
		}
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %%%s\n", sel, zero, ty, zeroResult, ty, q)
		return c.storeWidth(dstReg, "%"+sel, spec.Width)

	case "mneg":
		if (len(ins.Args) != 2 && len(ins.Args) != 3) || ins.Args[len(ins.Args)-1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects a, [b,] dstReg: %q", spec.Op, ins.Raw)
		}
		dstReg := ins.Args[len(ins.Args)-1].Reg
		a, err := c.evalWidth(ins.Args[0], spec.Width)
		if err != nil {
			return err
		}
		b, err := c.evalWidth(ins.Args[1], spec.Width)
		if err != nil {
			return err
		}
		m, n := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", m, ty, a, b)
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %%%s\n", n, ty, m)
		return c.storeWidth(dstReg, "%"+n, spec.Width)

	case "mull", "mnegl", "maddl", "msubl":
		isAcc := spec.LLVMOp == "maddl" || spec.LLVMOp == "msubl"
		minArgs, maxArgs := 2, 3
		if isAcc {
			minArgs, maxArgs = 4, 4
		}
		if len(ins.Args) < minArgs || len(ins.Args) > maxArgs || ins.Args[len(ins.Args)-1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects %d operands: %q", spec.Op, maxArgs, ins.Raw)
		}
		dstReg := ins.Args[len(ins.Args)-1].Reg
		// Plan 9 ARM64 4-op order: OP Rm, Ra, Rn, Rd => Rd = Ra +/- ext(Rm)*ext(Rn).
		// 2/3-op order: OP Rm, [Rn,] Rd => Rd = +/- ext(Rm)*ext(Rn).
		mulIdxB := 1
		if isAcc {
			mulIdxB = 2
		}
		a32, err := c.eval32(ins.Args[0])
		if err != nil {
			return err
		}
		b32, err := c.eval32(ins.Args[mulIdxB])
		if err != nil {
			return err
		}
		extOp := "zext"
		if spec.Signed {
			extOp = "sext"
		}
		a64, b64, prod := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s to i64\n", a64, extOp, a32)
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s to i64\n", b64, extOp, b32)
		fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", prod, a64, b64)
		out := "%" + prod
		switch spec.LLVMOp {
		case "mnegl":
			n := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i64 0, %s\n", n, out)
			out = "%" + n
		case "maddl":
			acc, err := c.eval64(ins.Args[1], false)
			if err != nil {
				return err
			}
			s := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", s, acc, out)
			out = "%" + s
		case "msubl":
			acc, err := c.eval64(ins.Args[1], false)
			if err != nil {
				return err
			}
			s := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", s, acc, out)
			out = "%" + s
		}
		return c.storeReg(dstReg, out)

	case "smulh":
		if (len(ins.Args) != 2 && len(ins.Args) != 3) || ins.Args[len(ins.Args)-1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 SMULH expects a, [b,] dstReg: %q", ins.Raw)
		}
		dstReg := ins.Args[len(ins.Args)-1].Reg
		a, err := c.eval64(ins.Args[0], false)
		if err != nil {
			return err
		}
		b, err := c.eval64(ins.Args[1], false)
		if err != nil {
			return err
		}
		a128, b128, prod, sh, hi := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i64 %s to i128\n", a128, a)
		fmt.Fprintf(c.b, "  %%%s = sext i64 %s to i128\n", b128, b)
		fmt.Fprintf(c.b, "  %%%s = mul i128 %%%s, %%%s\n", prod, a128, b128)
		fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", sh, prod)
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", hi, sh)
		return c.storeReg(dstReg, "%"+hi)
	}
	return fmt.Errorf("arm64: unhandled mul/div %s", spec.Op)
}
