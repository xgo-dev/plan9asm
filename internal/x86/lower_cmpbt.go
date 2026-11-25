package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *amd64Ctx) lowerCmpBt(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "CMPB", "CMPW", "CMPL", "CMPQ":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 CMPQ expects 2 operands: %q", ins.Raw)
		}
		ty := asm.I64
		switch op {
		case "CMPB":
			ty = asm.I8
		case "CMPW":
			ty = asm.I16
		case "CMPL":
			ty = asm.I32
		case "CMPQ":
			ty = asm.I64
		}
		a, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return true, false, err
		}
		b, err := c.evalIntSized(ins.Args[1], ty)
		if err != nil {
			return true, false, err
		}
		c.setCmpFlagsSized(ty, a, b)
		return true, false, nil

	case "TESTB", "TESTW", "TESTL", "TESTQ":
		// TEST* a,b sets flags based on (a & b) without storing the result.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects 2 operands: %q", op, ins.Raw)
		}
		ty := asm.I64
		switch op {
		case "TESTB":
			ty = asm.I8
		case "TESTW":
			ty = asm.I16
		case "TESTL":
			ty = asm.I32
		case "TESTQ":
			ty = asm.I64
		}
		a, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return true, false, err
		}
		b, err := c.evalIntSized(ins.Args[1], ty)
		if err != nil {
			return true, false, err
		}
		c.setTestFlagsSized(ty, a, b)
		return true, false, nil

	case "BTQ":
		// BTQ bit(imm|reg), dst(reg|mem): sets CF to selected bit.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 BTQ expects bit, dst: %q", ins.Raw)
		}
		return true, false, c.lowerX86ExtraBit(asm.OpSpec{Op: "BTQ", Width: 64, LLVMOp: "bt"}, ins)

	case "BTSQ", "BTRQ":
		// BTSQ/BTRQ src, dstReg|dstMem: CF = old bit, then set or
		// clear the selected destination bit.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		var amt string
		var registerIndex string
		switch ins.Args[0].Kind {
		case asm.OpImm:
			amt = fmt.Sprintf("%d", ins.Args[0].Imm&63)
		case asm.OpReg:
			av, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", m, av)
			amt = "%" + m
			registerIndex = av
		default:
			return true, false, fmt.Errorf("amd64 %s expects imm/reg bit index: %q", op, ins.Raw)
		}

		var dst string
		var storeDst func(string) error
		switch ins.Args[1].Kind {
		case asm.OpReg:
			dv, err := c.loadReg(ins.Args[1].Reg)
			if err != nil {
				return true, false, err
			}
			dst = dv
			storeDst = func(v string) error { return c.storeReg(ins.Args[1].Reg, v) }
		case asm.OpMem, asm.OpSym:
			addr, err := c.resolveMemAddrI64(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			// A register bit index on a memory operand selects a bit in an
			// unbounded bit string, not merely within the first qword. Adjust
			// the address by floor(index/64)*8 and retain index&63 within it.
			if registerIndex != "" {
				word := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, 6\n", word, registerIndex)
				byteOff := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 3\n", byteOff, word)
				adjusted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", adjusted, addr, byteOff)
				addr = "%" + adjusted
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", ld, p)
			dst = "%" + ld
			storeDst = func(v string) error {
				fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", v, p)
				return nil
			}
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
		}

		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %s\n", sh, dst, amt)
		and := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 1\n", and, sh)
		cf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", cf, and)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		one := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 1, %s\n", one, amt)
		out := c.newTmp()
		if op == "BTSQ" {
			fmt.Fprintf(c.b, "  %%%s = or i64 %s, %%%s\n", out, dst, one)
		} else {
			mask := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %%%s, -1\n", mask, one)
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %%%s\n", out, dst, mask)
		}
		if err := storeDst("%" + out); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	return false, false, nil
}

func (c *amd64Ctx) setCmpFlagsSized(ty asm.LLVMType, a, b string) {
	// Unlike most Plan 9 x86 instructions, CMP spells its operands in
	// comparison order: CMP a,b sets flags for a-b.
	zt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", zt, ty, a, b)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zt, c.flagsZSlot)
	slt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, %s\n", slt, ty, a, b)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", slt, c.flagsSltSlot)
	ult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %s\n", ult, ty, a, b)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", ult, c.flagsCFSlot)
}

func (c *amd64Ctx) setTestFlagsSized(ty asm.LLVMType, a, b string) {
	// Z from (a&b)==0, signed-lt from (a&b)<0, CF cleared.
	and := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", and, ty, a, b)
	zt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zt, ty, and)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zt, c.flagsZSlot)
	slt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", slt, ty, and)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", slt, c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
}

func (c *amd64Ctx) evalIntSized(op asm.Operand, ty asm.LLVMType) (string, error) {
	switch op.Kind {
	case asm.OpImm:
		// LLVM will interpret the literal in the destination integer width.
		return fmt.Sprintf("%d", op.Imm), nil
	case asm.OpReg:
		v64, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		if ty == asm.I64 {
			return v64, nil
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	case asm.OpFP:
		v64, err := c.evalFPToI64(op.FPOffset)
		if err != nil {
			return "", err
		}
		if ty == asm.I64 {
			return v64, nil
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	case asm.OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", t, ty, ptrType, p)
		return "%" + t, nil
	case asm.OpSym:
		s := strings.TrimSpace(op.Sym)
		if strings.HasPrefix(s, "$") {
			address := strings.TrimSpace(strings.TrimPrefix(s, "$"))
			if strings.HasSuffix(address, "(SB)") {
				p, err := c.ptrFromSB(address)
				if err != nil {
					return "", err
				}
				wide := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", wide, p)
				if ty == asm.I64 {
					return "%" + wide, nil
				}
				value := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", value, wide, ty)
				return "%" + value, nil
			}
			// Macro-style symbolic immediates (e.g. $const_avxSupported) may
			// survive preprocessing when include constants are unavailable.
			// Keep translation progressing with a conservative zero value.
			return "0", nil
		}
		if strings.HasSuffix(s, "(SB)") {
			p, err := c.ptrFromSB(s)
			if err != nil {
				return "", err
			}
			t := c.newTmp()
			loadKW := "load"
			if c.isVolatileSB(s) {
				loadKW = "load volatile"
			}
			fmt.Fprintf(c.b, "  %%%s = %s %s, ptr %s, align 1\n", t, loadKW, ty, p)
			return "%" + t, nil
		}
		return "", fmt.Errorf("amd64: unsupported sym int operand: %s", op.String())
	case asm.OpIdent:
		if isX86SystemOrSegIdent(op.Ident) {
			return "0", nil
		}
		return "", fmt.Errorf("amd64: unsupported int operand: %s", op.String())
	default:
		return "", fmt.Errorf("amd64: unsupported int operand: %s", op.String())
	}
}
