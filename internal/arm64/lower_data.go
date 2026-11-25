package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *arm64Ctx) lowerData(op asm.Op, postInc bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "MOVKW":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 MOVKW expects $imm16[<<16], dstReg: %q", ins.Raw)
		}
		if ins.Args[0].Imm < 0 || uint64(ins.Args[0].Imm) > uint64(^uint32(0)) {
			return true, false, fmt.Errorf("arm64 MOVKW immediate is outside 32 bits: %q", ins.Raw)
		}
		imm := uint32(ins.Args[0].Imm)
		var keepMask uint32
		switch {
		case imm <= 0xffff:
			keepMask = 0xffff0000
		case imm&0xffff == 0:
			keepMask = 0x0000ffff
		default:
			return true, false, fmt.Errorf("arm64 MOVKW immediate is not an imm16 or imm16<<16: %q", ins.Raw)
		}
		old, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		old32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", old32, old)
		kept := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %d\n", kept, old32, keepMask)
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %d\n", merged, kept, imm)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, merged)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+wide)

	case "MOVD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 MOVD expects 2 operands: %q", ins.Raw)
		}
		src, dst := ins.Args[0], ins.Args[1]
		v, err := c.eval64(src, postInc)
		if err != nil {
			return true, false, err
		}
		switch dst.Kind {
		case asm.OpReg:
			return true, false, c.storeReg(dst.Reg, v)
		case asm.OpMem:
			return true, false, c.storeMem(dst.Mem, 64, false, v)
		case asm.OpFP:
			return true, false, c.storeFPResult64(dst.FPOffset, v)
		case asm.OpSym:
			return true, false, nil
		default:
			return true, false, nil
		}

	case "MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU":
		bits := 8
		if op == "MOVH" || op == "MOVHU" {
			bits = 16
		} else if op == "MOVW" || op == "MOVWU" {
			bits = 32
		}
		signed := op == "MOVB" || op == "MOVH" || op == "MOVW"
		return true, false, c.lowerNarrowMove(op, ins, bits, signed, postInc)

	case "LDP":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpRegList || len(ins.Args[1].RegList) != 2 {
			return true, false, fmt.Errorf("arm64 LDP expects src, (reg,reg): %q", ins.Raw)
		}
		var v0, v1 string
		if ins.Args[0].Kind == asm.OpMem {
			mem := ins.Args[0].Mem
			addr, base, inc, err := c.addrI64(mem, postInc)
			if err != nil {
				return true, false, err
			}
			p0t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p0t, addr)
			v0t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %%%s\n", v0t, p0t)
			v0 = "%" + v0t
			addr2t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, 8\n", addr2t, addr)
			p1t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", p1t, addr2t)
			v1t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %%%s\n", v1t, p1t)
			v1 = "%" + v1t
			if err := c.storeReg(ins.Args[1].RegList[0], v0); err != nil {
				return true, false, err
			}
			if err := c.storeReg(ins.Args[1].RegList[1], v1); err != nil {
				return true, false, err
			}
			if err := c.updatePostInc(base, inc); err != nil {
				return true, false, err
			}
			return true, false, nil
		}
		if ins.Args[0].Kind == asm.OpFP {
			val, err := c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			if err := c.storeReg(ins.Args[1].RegList[0], val); err != nil {
				return true, false, err
			}
			if err := c.storeReg(ins.Args[1].RegList[1], "0"); err != nil {
				return true, false, err
			}
			return true, false, nil
		}
		if ins.Args[0].Kind == asm.OpSym {
			p, err := c.ptrFromSB(ins.Args[0].Sym)
			if err != nil {
				return true, false, err
			}
			v0t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", v0t, p)
			p1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 8\n", p1, p)
			v1t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %%%s\n", v1t, p1)
			if err := c.storeReg(ins.Args[1].RegList[0], "%"+v0t); err != nil {
				return true, false, err
			}
			if err := c.storeReg(ins.Args[1].RegList[1], "%"+v1t); err != nil {
				return true, false, err
			}
			return true, false, nil
		}
		return true, false, fmt.Errorf("arm64 LDP unsupported src: %q", ins.Raw)

	case "LDPW":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpMem || ins.Args[1].Kind != asm.OpRegList || len(ins.Args[1].RegList) != 2 {
			return true, false, fmt.Errorf("arm64 LDPW expects mem, (reg,reg): %q", ins.Raw)
		}
		mem := ins.Args[0].Mem
		addr, base, inc, err := c.addrI64(mem, postInc)
		if err != nil {
			return true, false, err
		}
		p0t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p0t, addr)
		v0t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i32, ptr %%%s\n", v0t, p0t)
		z0t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z0t, v0t)
		addr2t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 4\n", addr2t, addr)
		p1t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", p1t, addr2t)
		v1t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i32, ptr %%%s\n", v1t, p1t)
		z1t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z1t, v1t)
		if err := c.storeReg(ins.Args[1].RegList[0], "%"+z0t); err != nil {
			return true, false, err
		}
		if err := c.storeReg(ins.Args[1].RegList[1], "%"+z1t); err != nil {
			return true, false, err
		}
		if err := c.updatePostInc(base, inc); err != nil {
			return true, false, err
		}
		return true, false, nil

	case "STPW":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpRegList || len(ins.Args[0].RegList) != 2 || ins.Args[1].Kind != asm.OpMem {
			return true, false, fmt.Errorf("arm64 STPW expects (reg,reg), mem: %q", ins.Raw)
		}
		mem := ins.Args[1].Mem
		addr, base, inc, err := c.addrI64(mem, postInc)
		if err != nil {
			return true, false, err
		}
		v0, err := c.loadReg(ins.Args[0].RegList[0])
		if err != nil {
			return true, false, err
		}
		t0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t0, v0)
		p0t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p0t, addr)
		fmt.Fprintf(c.b, "  store i32 %%%s, ptr %%%s\n", t0, p0t)

		addr2t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 4\n", addr2t, addr)
		v1, err := c.loadReg(ins.Args[0].RegList[1])
		if err != nil {
			return true, false, err
		}
		t1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t1, v1)
		p1t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", p1t, addr2t)
		fmt.Fprintf(c.b, "  store i32 %%%s, ptr %%%s\n", t1, p1t)
		if err := c.updatePostInc(base, inc); err != nil {
			return true, false, err
		}
		return true, false, nil

	case "STP":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpRegList || len(ins.Args[0].RegList) != 2 || ins.Args[1].Kind != asm.OpMem {
			return true, false, fmt.Errorf("arm64 STP expects (reg,reg), mem: %q", ins.Raw)
		}
		mem := ins.Args[1].Mem
		addr, base, inc, err := c.addrI64(mem, postInc)
		if err != nil {
			return true, false, err
		}
		v0, err := c.loadReg(ins.Args[0].RegList[0])
		if err != nil {
			return true, false, err
		}
		p0t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p0t, addr)
		fmt.Fprintf(c.b, "  store i64 %s, ptr %%%s\n", v0, p0t)

		addr2t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 8\n", addr2t, addr)
		v1, err := c.loadReg(ins.Args[0].RegList[1])
		if err != nil {
			return true, false, err
		}
		p1t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", p1t, addr2t)
		fmt.Fprintf(c.b, "  store i64 %s, ptr %%%s\n", v1, p1t)
		if err := c.updatePostInc(base, inc); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	return false, false, nil
}

func (c *arm64Ctx) lowerNarrowMove(op asm.Op, ins asm.Instr, bits int, signed, postInc bool) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
	}
	src, dst := ins.Args[0], ins.Args[1]
	var value string
	var err error
	switch src.Kind {
	case asm.OpMem:
		value, err = c.loadMem(src.Mem, bits, postInc)
	case asm.OpSym:
		if strings.HasPrefix(strings.TrimSpace(src.Sym), "$") {
			return fmt.Errorf("arm64 %s does not accept an address source: %q", op, ins.Raw)
		}
		var ptr string
		ptr, err = c.ptrFromSB(src.Sym)
		if err == nil {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s\n", t, bits, ptr)
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, bits, t)
			value = "%" + z
		}
	default:
		value, err = c.eval64(src, false)
	}
	if err != nil {
		return err
	}

	switch dst.Kind {
	case asm.OpReg:
		// A MOVW immediate is materialized through the 32-bit register view,
		// which clears the upper half even though register and memory sources
		// for MOVW are sign-extended.
		value = c.arm64ExtendNarrow(value, bits, signed && src.Kind != asm.OpImm)
		return c.storeReg(dst.Reg, value)
	case asm.OpMem:
		return c.storeMem(dst.Mem, bits, postInc, value)
	case asm.OpSym:
		ptr, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", t, value, bits)
		fmt.Fprintf(c.b, "  store i%d %%%s, ptr %s\n", bits, t, ptr)
		return nil
	case asm.OpFP:
		value = c.arm64ExtendNarrow(value, bits, signed)
		return c.storeFPResult64(dst.FPOffset, value)
	default:
		return fmt.Errorf("arm64 %s unsupported destination: %q", op, ins.Raw)
	}
}

func (c *arm64Ctx) arm64ExtendNarrow(value string, bits int, signed bool) string {
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, value, bits)
	extended := c.newTmp()
	extendOp := "zext"
	if signed {
		extendOp = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s i%d %%%s to i64\n", extended, extendOp, bits, narrow)
	return "%" + extended
}
