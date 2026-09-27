package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerArith(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerARM64DivideRemainder(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerNegate(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64ScalarMultiply(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64BitReverse(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64CountLeading(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64InvertedLogical(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64BitClear(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64AddFlags(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64AddSubCarry(op, ins); ok {
		return ok, terminated, err
	}
	switch op {
	case "MRS_TPIDR_R0":
		// Pseudo-op used in runtime tls stubs.
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 asm sideeffect %q, %q()\n", t, "mrs $0, TPIDR_EL0", "=r,~{memory}")
		return true, false, c.storeReg(Reg("R0"), "%"+t)

	case "MRS":
		// MRS <sysreg>, Rn
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpIdent || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 MRS expects ident, reg: %q", ins.Raw)
		}
		sysreg := arm64CanonicalSysReg(ins.Args[0].Ident)
		dst := ins.Args[1].Reg
		if v, ok := arm64CompileSafeMRSValue(sysreg); ok {
			return true, false, c.storeReg(dst, v)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 asm sideeffect %q, %q()\n", t, "mrs $0, "+sysreg, "=r,~{memory}")
		return true, false, c.storeReg(dst, "%"+t)

	case "MSR":
		// MSR src, <sysreg>
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpIdent {
			return true, false, fmt.Errorf("arm64 MSR expects src, ident: %q", ins.Raw)
		}
		name := ins.Args[1].Ident
		sysreg := arm64CanonicalSysReg(name)
		switch ins.Args[0].Kind {
		case OpImm:
			imm := ins.Args[0].Imm
			field := ""
			switch strings.ToUpper(name) {
			case "SPSEL":
				field = "SPSel"
			case "DAIFSET":
				field = "DAIFSet"
			case "DAIFCLR":
				field = "DAIFClr"
			case "DIT":
				field = "DIT"
			}
			if imm == 0 && field != "DAIFSet" && field != "DAIFClr" {
				// Go encodes $0 as the zero register for system-register
				// writes, including SPSel and DIT, not as a PSTATE immediate.
				if field != "" {
					sysreg = field
				}
				fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", "msr "+sysreg+", xzr", "~{memory}")
				return true, false, nil
			}
			if field == "" || imm < 1 || imm > 15 {
				return true, false, fmt.Errorf("arm64 MSR immediate is not a Go PSTATE field form: %q", ins.Raw)
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", fmt.Sprintf("msr %s, #%d", field, imm), "~{memory}")
			return true, false, nil
		case OpReg:
			if strings.EqualFold(name, "DAIFSet") || strings.EqualFold(name, "DAIFClr") {
				return true, false, fmt.Errorf("arm64 MSR register source is not a Go PSTATE field form: %q", ins.Raw)
			}
			v, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "msr "+sysreg+", $0", "r,~{memory}", v)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("arm64 MSR unsupported src operand: %q", ins.Raw)
		}

	case "BFI", "BFIW", "BFXIL", "BFXILW",
		"SBFIZ", "SBFIZW", "SBFX", "SBFXW",
		"UBFIZ", "UBFIZW", "UBFX", "UBFXW":
		return true, false, c.lowerBitfield(op, ins)

	case "ADD", "SUB", "ADDS":
		if handled, dynamicErr := c.lowerDynamicStack(ins); handled {
			return true, false, dynamicErr
		}
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
		}
		var a, bval string
		var dst Reg
		if len(ins.Args) == 2 {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s dst must be reg: %q", op, ins.Raw)
			}
			dst = ins.Args[1].Reg
			bval, err = c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
		} else {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			bval, err = c.eval64(ins.Args[1], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s dst must be reg: %q", op, ins.Raw)
			}
			dst = ins.Args[2].Reg
		}
		t := c.newTmp()
		if op == "ADD" || op == "ADDS" {
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", t, bval, a)
		} else {
			fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", t, bval, a)
		}
		if err := c.storeReg(dst, "%"+t); err != nil {
			return true, false, err
		}
		if op == "ADDS" {
			c.setFlagsAdd(bval, a, "%"+t)
		}
		return true, false, nil

	case "ADDW":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 ADDW expects 2 or 3 operands: %q", ins.Raw)
		}
		var a, bval string
		var dst Reg
		if len(ins.Args) == 2 {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 ADDW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[1].Reg
			bval, err = c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
		} else {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			bval, err = c.eval64(ins.Args[1], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 ADDW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[2].Reg
		}
		ta := c.newTmp()
		tb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", ta, a)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tb, bval)
		sum := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", sum, tb, ta)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, sum)
		return true, false, c.storeReg(dst, "%"+z)

	case "SUBW":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 SUBW expects 2 or 3 operands: %q", ins.Raw)
		}
		var a, bval string
		var dst Reg
		if len(ins.Args) == 2 {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 SUBW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[1].Reg
			bval, err = c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
		} else {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			bval, err = c.eval64(ins.Args[1], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 SUBW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[2].Reg
		}
		ta := c.newTmp()
		tb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", ta, a)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tb, bval)
		diff := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, %%%s\n", diff, tb, ta)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, diff)
		return true, false, c.storeReg(dst, "%"+z)

	case "AND", "ANDS", "EOR", "ORR", "ANDW", "EORW", "ORRW":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
		}
		var a, bval string
		var dst Reg
		if len(ins.Args) == 2 {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s dst must be reg: %q", op, ins.Raw)
			}
			dst = ins.Args[1].Reg
			bval, err = c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
		} else {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			bval, err = c.eval64(ins.Args[1], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s dst must be reg: %q", op, ins.Raw)
			}
			dst = ins.Args[2].Reg
		}
		isWord := op == "ANDW" || op == "EORW" || op == "ORRW"
		t := c.newTmp()
		if isWord {
			aw := c.newTmp()
			bw := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", aw, a)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", bw, bval)
			switch op {
			case "ANDW":
				fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", t, bw, aw)
			case "EORW":
				fmt.Fprintf(c.b, "  %%%s = xor i32 %%%s, %%%s\n", t, bw, aw)
			case "ORRW":
				fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", t, bw, aw)
			}
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
			if err := c.storeReg(dst, "%"+z); err != nil {
				return true, false, err
			}
			return true, false, nil
		}
		switch op {
		case "AND", "ANDS":
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", t, bval, a)
		case "EOR":
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", t, bval, a)
		case "ORR":
			fmt.Fprintf(c.b, "  %%%s = or i64 %s, %s\n", t, bval, a)
		}
		if err := c.storeReg(dst, "%"+t); err != nil {
			return true, false, err
		}
		if op == "ANDS" {
			c.setFlagsLogic("%" + t)
		}
		return true, false, nil

	case "TST", "TSTW":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
		}
		word := op == "TSTW"
		var a, bval string
		var err error
		if word {
			a, err = c.eval32(ins.Args[0])
		} else {
			a, err = c.eval64(ins.Args[0], false)
		}
		if err != nil {
			return true, false, err
		}
		if word {
			bval, err = c.eval32(ins.Args[1])
		} else {
			bval, err = c.eval64(ins.Args[1], false)
		}
		if err != nil {
			return true, false, err
		}
		res := c.newTmp()
		if word {
			fmt.Fprintf(c.b, "  %%%s = and i32 %s, %s\n", res, bval, a)
			c.setFlagsLogic32("%" + res)
		} else {
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", res, bval, a)
			c.setFlagsLogic("%" + res)
		}
		return true, false, nil

	case "ANDSW":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 ANDSW expects 2 or 3 operands: %q", ins.Raw)
		}
		var a, bval string
		var dst Reg
		if len(ins.Args) == 2 {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 ANDSW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[1].Reg
			bval, err = c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
		} else {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			bval, err = c.eval64(ins.Args[1], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 ANDSW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[2].Reg
		}
		aw := c.newTmp()
		bw := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", aw, a)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", bw, bval)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", t, bw, aw)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
		if err := c.storeReg(dst, "%"+z); err != nil {
			return true, false, err
		}
		c.setFlagsLogic32("%" + t)
		return true, false, nil

	case "SUBS":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 SUBS expects 2 or 3 operands: %q", ins.Raw)
		}
		var a, bval string
		var dst Reg
		if len(ins.Args) == 2 {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 SUBS dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[1].Reg
			bval, err = c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
		} else {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			bval, err = c.eval64(ins.Args[1], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 SUBS dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[2].Reg
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", t, bval, a)
		if err := c.storeReg(dst, "%"+t); err != nil {
			return true, false, err
		}
		c.setFlagsSub(bval, a, "%"+t)
		return true, false, nil

	case "SUBSW":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 SUBSW expects 2 or 3 operands: %q", ins.Raw)
		}
		var a, bval string
		var dst Reg
		if len(ins.Args) == 2 {
			a, err = c.eval32(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 SUBSW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[1].Reg
			bval, err = c.eval32(ins.Args[1])
		} else {
			a, err = c.eval32(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			bval, err = c.eval32(ins.Args[1])
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 SUBSW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[2].Reg
		}
		if err != nil {
			return true, false, err
		}
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", res, bval, a)
		c.setFlagsSub32(bval, a, "%"+res)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, res)
		return true, false, c.storeReg(dst, "%"+z)

	case "MVN":
		// MVN src, dst => dst = ~src
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 MVN expects src, dstReg: %q", ins.Raw)
		}
		src, err := c.eval64(ins.Args[0], false)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i64 %s, -1\n", t, src)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+t)

	case "MVNW":
		// MVNW src, dst => dst = ~src (32-bit, zero-extended)
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 MVNW expects src, dstReg: %q", ins.Raw)
		}
		src, err := c.eval64(ins.Args[0], false)
		if err != nil {
			return true, false, err
		}
		sw := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", sw, src)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i32 %%%s, -1\n", t, sw)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+z)

	case "CRC32B", "CRC32H", "CRC32W", "CRC32X", "CRC32CB", "CRC32CH", "CRC32CW", "CRC32CX":
		// CRC32{C}{B,H,W,X} src, crc, dst, with the two-operand form
		// taking the incoming CRC from dst.
		if strings.ToUpper(string(ins.Op)) != string(op) {
			return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
		}
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects 2 or 3 registers: %q", op, ins.Raw)
		}
		for _, operand := range ins.Args {
			if operand.Kind != OpReg || !isARM64GeneralOrZeroReg(operand.Reg) {
				return true, false, fmt.Errorf("arm64 %s operands must be general registers: %q", op, ins.Raw)
			}
		}
		src64, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		dstReg := ins.Args[len(ins.Args)-1].Reg
		crcReg := dstReg
		if len(ins.Args) == 3 {
			crcReg = ins.Args[1].Reg
		}
		crc64, err := c.loadReg(crcReg)
		if err != nil {
			return true, false, err
		}
		crc32t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", crc32t, crc64)

		intr := ""
		dataTy := ""
		dataVal := ""
		switch op {
		case "CRC32B":
			intr = "llvm.aarch64.crc32b"
			tb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", tb, src64)
			zb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i32\n", zb, tb)
			dataTy, dataVal = "i32", "%"+zb
		case "CRC32H":
			intr = "llvm.aarch64.crc32h"
			th := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", th, src64)
			zh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i16 %%%s to i32\n", zh, th)
			dataTy, dataVal = "i32", "%"+zh
		case "CRC32W":
			intr = "llvm.aarch64.crc32w"
			tw := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tw, src64)
			dataTy, dataVal = "i32", "%"+tw
		case "CRC32X":
			intr = "llvm.aarch64.crc32x"
			dataTy, dataVal = "i64", src64
		case "CRC32CB":
			intr = "llvm.aarch64.crc32cb"
			tb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", tb, src64)
			zb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i32\n", zb, tb)
			dataTy, dataVal = "i32", "%"+zb
		case "CRC32CH":
			intr = "llvm.aarch64.crc32ch"
			th := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", th, src64)
			zh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i16 %%%s to i32\n", zh, th)
			dataTy, dataVal = "i32", "%"+zh
		case "CRC32CW":
			intr = "llvm.aarch64.crc32cw"
			tw := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tw, src64)
			dataTy, dataVal = "i32", "%"+tw
		case "CRC32CX":
			intr = "llvm.aarch64.crc32cx"
			dataTy, dataVal = "i64", src64
		}
		if intr == "" || dataTy == "" || dataVal == "" {
			return true, false, fmt.Errorf("arm64 %s: missing intrinsic mapping", op)
		}
		rt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @%s(i32 %%%s, %s %s)\n", rt, intr, crc32t, dataTy, dataVal)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, rt)
		return true, false, c.storeReg(dstReg, "%"+z)

	case "CMP", "CMPW":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
		}
		if op == "CMPW" {
			src, err := c.eval32(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			dst, err := c.eval32(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", res, dst, src)
			c.setFlagsSub32(dst, src, "%"+res)
			return true, false, nil
		}
		src, err := c.eval64(ins.Args[0], false)
		if err != nil {
			return true, false, err
		}
		dst, err := c.eval64(ins.Args[1], false)
		if err != nil {
			return true, false, err
		}
		rt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", rt, dst, src)
		c.setFlagsSub(dst, src, "%"+rt)
		return true, false, nil

	case "CCMP", "CCMPW", "CCMN", "CCMNW":
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 ||
			ins.Args[3].Kind != OpImm || ins.Args[3].ImmRaw != "" {
			return true, false, fmt.Errorf("arm64 %s expects condition, lhs, rhs, $nzcv: %q", op, ins.Raw)
		}
		condition := ""
		switch ins.Args[0].Kind {
		case OpIdent:
			condition = ins.Args[0].Ident
		case OpReg:
			// AL is also a register spelling in the Plan 9 parser, but in
			// this operand position Go's optab classifies it as C_COND.
			condition = string(ins.Args[0].Reg)
		default:
			return true, false, fmt.Errorf("arm64 %s first operand must be a condition: %q", op, ins.Raw)
		}
		if ins.Args[3].Imm < 0 || ins.Args[3].Imm > 15 {
			return true, false, fmt.Errorf("arm64 %s NZCV immediate is outside 0..15: %q", op, ins.Raw)
		}
		if ins.Args[1].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("arm64 %s lhs must be a general register: %q", op, ins.Raw)
		}
		switch ins.Args[2].Kind {
		case OpReg:
			if !isARM64GeneralOrZeroReg(ins.Args[2].Reg) {
				return true, false, fmt.Errorf("arm64 %s rhs must be a general register: %q", op, ins.Raw)
			}
		case OpImm:
			if ins.Args[2].ImmRaw != "" || ins.Args[2].Imm < 0 || ins.Args[2].Imm > 31 {
				return true, false, fmt.Errorf("arm64 %s rhs immediate is outside 0..31: %q", op, ins.Raw)
			}
		default:
			return true, false, fmt.Errorf("arm64 %s rhs must be a register or immediate: %q", op, ins.Raw)
		}
		word := op == "CCMPW" || op == "CCMNW"
		add := op == "CCMN" || op == "CCMNW"
		var lhs, rhs string
		var err error
		if word {
			lhs, err = c.eval32(ins.Args[1])
			if err == nil {
				rhs, err = c.eval32(ins.Args[2])
			}
		} else {
			lhs, err = c.eval64(ins.Args[1], false)
			if err == nil {
				rhs, err = c.eval64(ins.Args[2], false)
			}
		}
		if err != nil {
			return true, false, err
		}
		return true, false, c.setConditionalCompareFlags(condition, lhs, rhs, ins.Args[3].Imm, word, add)

	case "CMN", "CMNW":
		if strings.ToUpper(string(ins.Op)) != string(op) {
			return true, false, fmt.Errorf("arm64 %s does not accept instruction suffixes: %q", op, ins.Raw)
		}
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
		}
		word := op == "CMNW"
		if err := validateARM64CompareNegativeOperands(ins.Args[0], ins.Args[1], word); err != nil {
			return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
		}
		if word {
			src, err := c.eval32(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			dst, err := c.eval32(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			result := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", result, dst, src)
			c.setFlagsAdd32(dst, src, "%"+result)
			return true, false, nil
		}
		src, err := c.eval64(ins.Args[0], false)
		if err != nil {
			return true, false, err
		}
		dst, err := c.eval64(ins.Args[1], false)
		if err != nil {
			return true, false, err
		}
		rt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", rt, dst, src)
		c.setFlagsAdd(dst, src, "%"+rt)
		return true, false, nil

	case "NEG":
		// NEG src, dst => dst = -src
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 NEG expects src, dstReg: %q", ins.Raw)
		}
		src, err := c.eval64(ins.Args[0], false)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 0, %s\n", t, src)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+t)

	case "MULW":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 MULW expects 2 or 3 operands: %q", ins.Raw)
		}
		a, err := c.eval32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		var bval string
		var dst Reg
		if len(ins.Args) == 2 {
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 MULW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[1].Reg
			bval, err = c.eval32(ins.Args[1])
		} else {
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 MULW dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[2].Reg
			bval, err = c.eval32(ins.Args[1])
		}
		if err != nil {
			return true, false, err
		}
		product := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", product, bval, a)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, product)
		return true, false, c.storeReg(dst, "%"+wide)

	case "MUL":
		// MUL a, dst or MUL a, b, dst
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 MUL expects 2 or 3 operands: %q", ins.Raw)
		}
		var a, bval string
		var dst Reg
		if len(ins.Args) == 2 {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 MUL dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[1].Reg
			bval, err = c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
		} else {
			a, err = c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			bval, err = c.eval64(ins.Args[1], false)
			if err != nil {
				return true, false, err
			}
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 MUL dst must be reg: %q", ins.Raw)
			}
			dst = ins.Args[2].Reg
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", t, bval, a)
		return true, false, c.storeReg(dst, "%"+t)

	case "LSL", "LSR":
		// LSL/LSR $imm|reg, srcReg, dstReg
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
		}
		var srcReg Reg
		var dstReg Reg
		if len(ins.Args) == 2 {
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s expects shift, dstReg: %q", op, ins.Raw)
			}
			srcReg, dstReg = ins.Args[1].Reg, ins.Args[1].Reg
		} else {
			if ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s expects shift, srcReg, dstReg: %q", op, ins.Raw)
			}
			srcReg, dstReg = ins.Args[1].Reg, ins.Args[2].Reg
		}
		src, err := c.loadReg(srcReg)
		if err != nil {
			return true, false, err
		}
		shv := ""
		switch ins.Args[0].Kind {
		case OpImm:
			if ins.Args[0].Imm < 0 || ins.Args[0].Imm > 63 {
				return true, false, fmt.Errorf("arm64 %s immediate shift out of range: %q", op, ins.Raw)
			}
			shv = c.imm64(ins.Args[0].Imm)
		case OpReg:
			shv, err = c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			// AArch64 masks register shift amounts; LLVM shifts are poison for >= bitwidth.
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", m, shv)
			shv = "%" + m
		default:
			return true, false, fmt.Errorf("arm64 %s unsupported shift operand: %q", op, ins.Raw)
		}
		t := c.newTmp()
		if op == "LSL" {
			fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %s\n", t, src, shv)
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %s\n", t, src, shv)
		}
		return true, false, c.storeReg(dstReg, "%"+t)

	case "LSLW", "LSRW":
		// LSLW/LSRW shift, dstReg  or  LSLW/LSRW shift, srcReg, dstReg
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
		}
		var srcReg Reg
		var dstReg Reg
		var sh Operand
		if len(ins.Args) == 2 {
			sh = ins.Args[0]
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s expects shift, dstReg: %q", op, ins.Raw)
			}
			srcReg, dstReg = ins.Args[1].Reg, ins.Args[1].Reg
		} else {
			sh = ins.Args[0]
			if ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s expects shift, srcReg, dstReg: %q", op, ins.Raw)
			}
			srcReg, dstReg = ins.Args[1].Reg, ins.Args[2].Reg
		}
		src64, err := c.loadReg(srcReg)
		if err != nil {
			return true, false, err
		}
		src32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", src32, src64)
		var sh32 string
		switch sh.Kind {
		case OpImm:
			if sh.Imm < 0 || sh.Imm > 31 {
				return true, false, fmt.Errorf("arm64 %s immediate shift out of range: %q", op, ins.Raw)
			}
			sh32 = fmt.Sprintf("%d", sh.Imm)
		case OpReg:
			sv, err := c.loadReg(sh.Reg)
			if err != nil {
				return true, false, err
			}
			st := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", st, sv)
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", m, st)
			sh32 = "%" + m
		default:
			return true, false, fmt.Errorf("arm64 %s unsupported shift operand: %q", op, ins.Raw)
		}
		t := c.newTmp()
		if op == "LSLW" {
			fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %s\n", t, src32, sh32)
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, %s\n", t, src32, sh32)
		}
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
		return true, false, c.storeReg(dstReg, "%"+z)

	case "ASR", "ASRW":
		// ASR shift, dstReg  or  ASR shift, srcReg, dstReg
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
		}
		var srcReg Reg
		var dstReg Reg
		if len(ins.Args) == 2 {
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s expects shift, dstReg: %q", op, ins.Raw)
			}
			srcReg, dstReg = ins.Args[1].Reg, ins.Args[1].Reg
		} else {
			if ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s expects shift, srcReg, dstReg: %q", op, ins.Raw)
			}
			srcReg, dstReg = ins.Args[1].Reg, ins.Args[2].Reg
		}
		src, err := c.loadReg(srcReg)
		if err != nil {
			return true, false, err
		}
		if op == "ASRW" {
			src32 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", src32, src)
			shv := ""
			switch ins.Args[0].Kind {
			case OpImm:
				if ins.Args[0].Imm < 0 || ins.Args[0].Imm > 31 {
					return true, false, fmt.Errorf("arm64 ASRW immediate shift out of range: %q", ins.Raw)
				}
				shv = fmt.Sprintf("%d", ins.Args[0].Imm)
			case OpReg:
				sv, err := c.loadReg(ins.Args[0].Reg)
				if err != nil {
					return true, false, err
				}
				st := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", st, sv)
				masked := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", masked, st)
				shv = "%" + masked
			default:
				return true, false, fmt.Errorf("arm64 ASRW unsupported shift operand: %q", ins.Raw)
			}
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %%%s, %s\n", out, src32, shv)
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, out)
			return true, false, c.storeReg(dstReg, "%"+z)
		}
		shv := ""
		switch ins.Args[0].Kind {
		case OpImm:
			if ins.Args[0].Imm < 0 || ins.Args[0].Imm > 63 {
				return true, false, fmt.Errorf("arm64 ASR immediate shift out of range: %q", ins.Raw)
			}
			shv = c.imm64(ins.Args[0].Imm)
		case OpReg:
			shv, err = c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", m, shv)
			shv = "%" + m
		default:
			return true, false, fmt.Errorf("arm64 ASR unsupported shift operand: %q", ins.Raw)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, %s\n", t, src, shv)
		return true, false, c.storeReg(dstReg, "%"+t)

	case "EXTR", "EXTRW":
		// EXTR shift, hi, lo, dst
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 ||
			ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
			return true, false, fmt.Errorf("arm64 %s expects $shift, hi, lo, dstReg: %q", op, ins.Raw)
		}
		for _, operand := range ins.Args[1:] {
			if operand.Kind != OpReg || !isARM64GeneralOrZeroReg(operand.Reg) {
				return true, false, fmt.Errorf("arm64 %s operands must be general registers: %q", op, ins.Raw)
			}
		}
		width := int64(64)
		if op == "EXTRW" {
			width = 32
		}
		shift := ins.Args[0].Imm
		if shift < 0 || shift >= width {
			return true, false, fmt.Errorf("arm64 %s shift must be in [0,%d): %q", op, width, ins.Raw)
		}
		if op == "EXTRW" {
			hi, err := c.eval32(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			lo, err := c.eval32(ins.Args[2])
			if err != nil {
				return true, false, err
			}
			result := lo
			if shift != 0 {
				loPart := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %d\n", loPart, lo, shift)
				hiPart := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %d\n", hiPart, hi, width-shift)
				combined := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", combined, loPart, hiPart)
				result = "%" + combined
			}
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, result)
			return true, false, c.storeReg(ins.Args[3].Reg, "%"+wide)
		}
		hi, err := c.eval64(ins.Args[1], false)
		if err != nil {
			return true, false, err
		}
		lo, err := c.eval64(ins.Args[2], false)
		if err != nil {
			return true, false, err
		}
		result := lo
		if shift != 0 {
			loPart := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", loPart, lo, shift)
			hiPart := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", hiPart, hi, width-shift)
			combined := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", combined, loPart, hiPart)
			result = "%" + combined
		}
		return true, false, c.storeReg(ins.Args[3].Reg, result)

	case "RORW":
		// RORW shift, dstReg  or  RORW shift, srcReg, dstReg
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 RORW expects 2 or 3 operands: %q", ins.Raw)
		}
		var srcReg Reg
		var dstReg Reg
		var sh Operand
		if len(ins.Args) == 2 {
			sh = ins.Args[0]
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 RORW expects shift, dstReg: %q", ins.Raw)
			}
			srcReg = ins.Args[1].Reg
			dstReg = ins.Args[1].Reg
		} else {
			sh = ins.Args[0]
			if ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 RORW expects shift, srcReg, dstReg: %q", ins.Raw)
			}
			srcReg = ins.Args[1].Reg
			dstReg = ins.Args[2].Reg
		}
		src64, err := c.loadReg(srcReg)
		if err != nil {
			return true, false, err
		}
		src32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", src32, src64)
		sh32 := ""
		switch sh.Kind {
		case OpImm:
			if sh.Imm < 0 || sh.Imm > 31 {
				return true, false, fmt.Errorf("arm64 RORW immediate shift out of range: %q", ins.Raw)
			}
			sh32 = fmt.Sprintf("%d", sh.Imm)
		case OpReg:
			sv, err := c.loadReg(sh.Reg)
			if err != nil {
				return true, false, err
			}
			st := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", st, sv)
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", m, st)
			sh32 = "%" + m
		default:
			return true, false, fmt.Errorf("arm64 RORW unsupported shift operand: %q", ins.Raw)
		}
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 32, %s\n", neg, sh32)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", nm, neg)
		r := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, %s\n", r, src32, sh32)
		l := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %%%s\n", l, src32, nm)
		o := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", o, r, l)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, o)
		return true, false, c.storeReg(dstReg, "%"+z)

	case "ROR":
		// ROR shift, dstReg or ROR shift, srcReg, dstReg.
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 ROR expects 2 or 3 operands: %q", ins.Raw)
		}
		var srcReg, dstReg Reg
		shift := ins.Args[0]
		if len(ins.Args) == 2 {
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 ROR expects shift, dstReg: %q", ins.Raw)
			}
			srcReg, dstReg = ins.Args[1].Reg, ins.Args[1].Reg
		} else {
			if ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("arm64 ROR expects shift, srcReg, dstReg: %q", ins.Raw)
			}
			srcReg, dstReg = ins.Args[1].Reg, ins.Args[2].Reg
		}
		src, err := c.loadReg(srcReg)
		if err != nil {
			return true, false, err
		}
		shv := ""
		switch shift.Kind {
		case OpImm:
			if shift.Imm < 0 || shift.Imm > 63 {
				return true, false, fmt.Errorf("arm64 ROR immediate shift out of range: %q", ins.Raw)
			}
			shv = fmt.Sprintf("%d", shift.Imm)
		case OpReg:
			sv, err := c.loadReg(shift.Reg)
			if err != nil {
				return true, false, err
			}
			masked := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", masked, sv)
			shv = "%" + masked
		default:
			return true, false, fmt.Errorf("arm64 ROR unsupported shift operand: %q", ins.Raw)
		}
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 64, %s\n", neg, shv)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", nm, neg)
		right := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %s\n", right, src, shv)
		left := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %%%s\n", left, src, nm)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", out, right, left)
		return true, false, c.storeReg(dstReg, "%"+out)

	case "REV":
		// REV src, dst (bswap)
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 REV expects reg, reg: %q", ins.Raw)
		}
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.bswap.i64(i64 %s)\n", t, src)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+t)

	case "REVW":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 REVW expects reg, reg: %q", ins.Raw)
		}
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		word := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", word, src)
		reversed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bswap.i32(i32 %%%s)\n", reversed, word)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, reversed)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+z)

	case "REV16", "REV16W":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects reg, reg: %q", op, ins.Raw)
		}
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		typeName := "i64"
		lowMask, highMask := int64(0x00ff00ff00ff00ff), int64(-71777214294589696)
		if op == "REV16W" {
			typeName = "i32"
			word := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", word, src)
			src = "%" + word
			lowMask, highMask = 0x00ff00ff, -16711936
		}
		low := c.newTmp()
		high := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", low, typeName, src, lowMask)
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", high, typeName, src, highMask)
		lowShift := c.newTmp()
		highShift := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, 8\n", lowShift, typeName, low)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, 8\n", highShift, typeName, high)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", out, typeName, lowShift, highShift)
		value := "%" + out
		if op == "REV16W" {
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, value)
			value = "%" + z
		}
		return true, false, c.storeReg(ins.Args[1].Reg, value)

	case "REV32":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 REV32 expects reg, reg: %q", ins.Raw)
		}
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		reversed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.bswap.i64(i64 %s)\n", reversed, src)
		out := c.rotateInt("%"+reversed, "i64", 64, "32")
		return true, false, c.storeReg(ins.Args[1].Reg, out)
	}
	return false, false, nil
}

func (c *arm64Ctx) lowerBitfield(op Op, ins Instr) error {
	if len(ins.Args) != 4 ||
		ins.Args[0].Kind != OpImm ||
		ins.Args[1].Kind != OpReg ||
		ins.Args[2].Kind != OpImm ||
		ins.Args[3].Kind != OpReg {
		return fmt.Errorf("arm64 %s expects $lsb, srcReg, $width, dstReg: %q", op, ins.Raw)
	}
	bits := int64(64)
	if strings.HasSuffix(string(op), "W") {
		bits = 32
	}
	lsb, width := ins.Args[0].Imm, ins.Args[2].Imm
	if lsb < 0 || width <= 0 || lsb >= bits || lsb+width > bits {
		return fmt.Errorf("arm64 %s invalid range lsb=%d width=%d for %d-bit form: %q", op, lsb, width, bits, ins.Raw)
	}

	src64, err := c.loadReg(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	dst64, err := c.loadReg(ins.Args[3].Reg)
	if err != nil {
		return err
	}
	typeName := "i64"
	src, dst := src64, dst64
	if bits == 32 {
		typeName = "i32"
		srcTmp := c.newTmp()
		dstTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", srcTmp, src64)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", dstTmp, dst64)
		src, dst = "%"+srcTmp, "%"+dstTmp
	}

	mask := ^uint64(0)
	if width < 64 {
		mask = (uint64(1) << uint(width)) - 1
	}
	if bits == 32 {
		mask &= uint64(^uint32(0))
	}

	value := src
	switch {
	case strings.HasPrefix(string(op), "BFI"):
		value, err = c.arm64InsertBits(typeName, bits, src, dst, lsb, width, 0)
	case strings.HasPrefix(string(op), "BFXIL"):
		value, err = c.arm64InsertBits(typeName, bits, src, dst, 0, width, lsb)
	case strings.HasPrefix(string(op), "UBFX"):
		value = c.arm64ExtractBits(typeName, src, lsb, mask, false, width)
	case strings.HasPrefix(string(op), "SBFX"):
		value = c.arm64ExtractBits(typeName, src, lsb, mask, true, width)
	case strings.HasPrefix(string(op), "UBFIZ"):
		value = c.arm64ExtractBits(typeName, src, 0, mask, false, width)
		if lsb != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl %s %s, %d\n", shifted, typeName, value, lsb)
			value = "%" + shifted
		}
	case strings.HasPrefix(string(op), "SBFIZ"):
		value = c.arm64ExtractBits(typeName, src, 0, mask, true, width)
		if lsb != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl %s %s, %d\n", shifted, typeName, value, lsb)
			value = "%" + shifted
		}
	default:
		return fmt.Errorf("arm64: unhandled bitfield opcode %s", op)
	}
	if err != nil {
		return err
	}
	if bits == 32 {
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, value)
		value = "%" + z
	}
	return c.storeReg(ins.Args[3].Reg, value)
}

func (c *arm64Ctx) arm64ExtractBits(typeName, src string, lsb int64, mask uint64, signed bool, width int64) string {
	value := src
	if lsb != 0 {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", shifted, typeName, value, lsb)
		value = "%" + shifted
	}
	masked := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", masked, typeName, value, arm64IntConstant(typeName, mask))
	value = "%" + masked
	if signed {
		bits := int64(64)
		if typeName == "i32" {
			bits = 32
		}
		left := bits - width
		if left != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl %s %s, %d\n", shifted, typeName, value, left)
			extended := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr %s %%%s, %d\n", extended, typeName, shifted, left)
			value = "%" + extended
		}
	}
	return value
}

func (c *arm64Ctx) arm64InsertBits(typeName string, bits int64, src, dst string, dstLSB, width, srcLSB int64) (string, error) {
	if dstLSB < 0 || srcLSB < 0 || width <= 0 || dstLSB+width > bits || srcLSB+width > bits {
		return "", fmt.Errorf("arm64: invalid %s bit insertion", typeName)
	}
	mask := ^uint64(0)
	if width < 64 {
		mask = (uint64(1) << uint(width)) - 1
	}
	if bits == 32 {
		mask &= uint64(^uint32(0))
	}
	value := src
	if srcLSB != 0 {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", shifted, typeName, value, srcLSB)
		value = "%" + shifted
	}
	srcBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", srcBits, typeName, value, arm64IntConstant(typeName, mask))
	value = "%" + srcBits
	if dstLSB != 0 {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %d\n", shifted, typeName, value, dstLSB)
		value = "%" + shifted
	}
	fieldMask := mask << uint(dstLSB)
	if bits == 32 {
		fieldMask &= uint64(^uint32(0))
	}
	kept := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", kept, typeName, dst, arm64IntConstant(typeName, ^fieldMask))
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %s\n", out, typeName, kept, value)
	return "%" + out, nil
}

func arm64IntConstant(typeName string, value uint64) int64 {
	if typeName == "i32" {
		return int64(int32(value))
	}
	return int64(value)
}

func arm64CanonicalSysReg(name string) string {
	switch name {
	case "DIT":
		// LLVM inline-asm parser on current toolchains does not accept the DIT
		// alias directly; use its canonical system-register encoding name.
		return "S3_3_C4_C2_5"
	default:
		return name
	}
}

func arm64CompileSafeMRSValue(sysreg string) (string, bool) {
	switch sysreg {
	case "ID_AA64ISAR0_EL1", "ID_AA64PFR0_EL1", "ID_AA64ZFR0_EL1", "MIDR_EL1":
		// LLVM 19's inline-asm parser lags behind newer arm64 feature register names.
		// For compile-only corpus coverage, return a conservative zero value.
		return "0", true
	default:
		return "", false
	}
}
