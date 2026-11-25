package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
)

func (c *amd64Ctx) lowerAtomic(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "LOCK":
		// LOCK is a prefix in Plan 9 syntax; record it so the following memory
		// RMW instruction emits atomic LLVM IR (atomicrmw / cmpxchg).
		c.lockPrefix = true
		return true, false, nil

	case "CMPXCHG8B":
		if len(ins.Args) != 1 || !isX86MemOp(ins.Args[0]) {
			return true, false, fmt.Errorf("amd64 CMPXCHG8B expects mem: %q", ins.Raw)
		}
		word := func(r asm.Reg) (string, error) {
			return c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: r}, asm.I32)
		}
		ax, err := word(asm.AX)
		if err != nil {
			return true, false, err
		}
		dx, err := word(asm.DX)
		if err != nil {
			return true, false, err
		}
		bx, err := word(asm.BX)
		if err != nil {
			return true, false, err
		}
		cx, err := word(asm.CX)
		if err != nil {
			return true, false, err
		}
		pair := func(lo, hi string) string {
			lo64 := c.newTmp()
			hi64 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", lo64, lo)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", hi64, hi)
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 32\n", shifted, hi64)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", out, shifted, lo64)
			return "%" + out
		}
		expected := pair(ax, dx)
		desired := pair(bx, cx)
		ptr, ptrType, err := c.resolveMemPtr(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		if ptrType != "ptr" {
			return true, false, fmt.Errorf("amd64 CMPXCHG8B does not support segment-relative memory: %q", ins.Raw)
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, i64 %s, i64 %s seq_cst seq_cst, align 8\n", result, ptr, expected, desired)
		old := c.newTmp()
		success := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i64, i1 } %%%s, 0\n", old, result)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i64, i1 } %%%s, 1\n", success, result)
		oldLo := c.newTmp()
		oldHiShift := c.newTmp()
		oldHi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", oldLo, old)
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", oldHiShift, old)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", oldHi, oldHiShift)
		if err := c.storeRegSized(asm.AX, asm.I32, "%"+oldLo); err != nil {
			return true, false, err
		}
		if err := c.storeRegSized(asm.DX, asm.I32, "%"+oldHi); err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", success, c.flagsZSlot)
		return true, false, nil

	case "CMPXCHG16B":
		if len(ins.Args) != 1 || !isX86MemOp(ins.Args[0]) {
			return true, false, fmt.Errorf("amd64 CMPXCHG16B expects mem: %q", ins.Raw)
		}
		ax, err := c.loadReg(asm.AX)
		if err != nil {
			return true, false, err
		}
		dx, err := c.loadReg(asm.DX)
		if err != nil {
			return true, false, err
		}
		bx, err := c.loadReg(asm.BX)
		if err != nil {
			return true, false, err
		}
		cx, err := c.loadReg(asm.CX)
		if err != nil {
			return true, false, err
		}
		pack128 := func(lo, hi string) string {
			lo128, hi128, sh, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", lo128, lo)
			fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", hi128, hi)
			fmt.Fprintf(c.b, "  %%%s = shl i128 %%%s, 64\n", sh, hi128)
			fmt.Fprintf(c.b, "  %%%s = or i128 %%%s, %%%s\n", out, sh, lo128)
			return "%" + out
		}
		expected := pack128(ax, dx)
		desired := pack128(bx, cx)
		ptr, err := c.amd64AtomicPtrFromOp(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		res, old, okv, oldLo, oldHiSh, oldHi := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, i128 %s, i128 %s seq_cst seq_cst, align 16\n", res, ptr, expected, desired)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i128, i1 } %%%s, 0\n", old, res)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i128, i1 } %%%s, 1\n", okv, res)
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", oldLo, old)
		fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", oldHiSh, old)
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", oldHi, oldHiSh)
		if err := c.storeReg(asm.AX, "%"+oldLo); err != nil {
			return true, false, err
		}
		if err := c.storeReg(asm.DX, "%"+oldHi); err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", okv, c.flagsZSlot)
		return true, false, nil

	case "CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHGQ":
		if len(ins.Args) != 2 || (!isX86MemOp(ins.Args[1]) && ins.Args[1].Kind != asm.OpReg && ins.Args[1].Kind != asm.OpFP) {
			return true, false, fmt.Errorf("amd64 %s expects src, mem/reg: %q", op, ins.Raw)
		}
		ty := asm.I32
		align := 4
		switch op {
		case "CMPXCHGB":
			ty, align = asm.I8, 1
		case "CMPXCHGW":
			ty, align = asm.I16, 2
		case "CMPXCHGQ":
			ty, align = asm.I64, 8
		}
		exp, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, ty)
		if err != nil {
			return true, false, err
		}
		newv, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return true, false, err
		}
		if ins.Args[1].Kind == asm.OpReg {
			cur, err := c.evalIntSized(ins.Args[1], ty)
			if err != nil {
				return true, false, err
			}
			eq, nextDst, nextAX := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", eq, ty, cur, exp)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %s\n", nextDst, eq, ty, newv, ty, cur)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %s\n", nextAX, eq, ty, exp, ty, cur)
			if err := c.storeRegSized(ins.Args[1].Reg, ty, "%"+nextDst); err != nil {
				return true, false, err
			}
			if err := c.storeRegSized(asm.AX, ty, "%"+nextAX); err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", eq, c.flagsZSlot)
			return true, false, nil
		}
		ptr, err := c.amd64AtomicPtrFromOp(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		cx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s seq_cst seq_cst, align %d\n", cx, ptr, ty, exp, ty, newv, align)
		old := c.newTmp()
		okv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 0\n", old, ty, cx)
		fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 1\n", okv, ty, cx)
		if err := c.storeRegSized(asm.AX, ty, "%"+old); err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", okv, c.flagsZSlot)
		return true, false, nil

	case "XADDB", "XADDW", "XADDL", "XADDQ":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || (!isX86MemOp(ins.Args[1]) && ins.Args[1].Kind != asm.OpReg && ins.Args[1].Kind != asm.OpFP) {
			return true, false, fmt.Errorf("amd64 %s expects srcReg, mem/reg: %q", op, ins.Raw)
		}
		srcReg := ins.Args[0]
		ty := asm.I32
		switch op {
		case "XADDB":
			ty = asm.I8
		case "XADDW":
			ty = asm.I16
		case "XADDQ":
			ty = asm.I64
		}
		src, err := c.evalIntSized(srcReg, ty)
		if err != nil {
			return true, false, err
		}
		if ins.Args[1].Kind == asm.OpReg {
			dst, err := c.evalIntSized(ins.Args[1], ty)
			if err != nil {
				return true, false, err
			}
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", sum, ty, dst, src)
			if err := c.storeRegSized(srcReg.Reg, ty, dst); err != nil {
				return true, false, err
			}
			return true, false, c.storeRegSized(ins.Args[1].Reg, ty, "%"+sum)
		}
		ptr, err := c.amd64AtomicPtrFromOp(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw add ptr %s, %s %s seq_cst\n", old, ptr, ty, src)
		return true, false, c.storeRegSized(srcReg.Reg, ty, "%"+old)

	case "XCHGB", "XCHGW", "XCHGL", "XCHGQ":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects srcReg, dst: %q", op, ins.Raw)
		}
		srcReg, dstArg := ins.Args[0], ins.Args[1]
		if (srcReg.Kind == asm.OpMem || srcReg.Kind == asm.OpSym || srcReg.Kind == asm.OpFP) && dstArg.Kind == asm.OpReg {
			srcReg, dstArg = dstArg, srcReg
		}
		if srcReg.Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 %s expects register src: %q", op, ins.Raw)
		}
		ty := asm.I8
		switch op {
		case "XCHGW":
			ty = asm.I16
		case "XCHGL":
			ty = asm.I32
		case "XCHGQ":
			ty = asm.I64
		}
		src64, err := c.loadReg(srcReg.Reg)
		if err != nil {
			return true, false, err
		}
		if dstArg.Kind == asm.OpReg {
			dstReg := dstArg.Reg
			srcT, err := c.evalIntSized(srcReg, ty)
			if err != nil {
				return true, false, err
			}
			dstT, err := c.evalIntSized(dstArg, ty)
			if err != nil {
				return true, false, err
			}
			if err := c.storeRegSized(srcReg.Reg, ty, dstT); err != nil {
				return true, false, err
			}
			return true, false, c.storeRegSized(dstReg, ty, srcT)
		}
		if dstArg.Kind != asm.OpMem && dstArg.Kind != asm.OpSym && dstArg.Kind != asm.OpFP {
			return true, false, fmt.Errorf("amd64 %s expects srcReg, mem/reg: %q", op, ins.Raw)
		}
		src, err := c.amd64AtomicTruncFromI64(src64, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.amd64AtomicPtrFromOp(dstArg)
		if err != nil {
			return true, false, err
		}
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw xchg ptr %s, %s %s seq_cst\n", old, ptr, ty, src)
		old64, err := c.amd64AtomicExtendToI64("%"+old, ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(srcReg.Reg, old64)

	case "ORB", "ANDB", "ORW", "ANDW", "ORL", "ANDL", "ORQ", "ANDQ":
		if len(ins.Args) != 2 || (!isX86MemOp(ins.Args[1]) && ins.Args[1].Kind != asm.OpFP) {
			return false, false, nil
		}
		ty := asm.I8
		switch op {
		case "ORW", "ANDW":
			ty = asm.I16
		case "ORL", "ANDL":
			ty = asm.I32
		case "ORQ", "ANDQ":
			ty = asm.I64
		}
		src64, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		src, err := c.amd64AtomicTruncFromI64(src64, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.amd64AtomicPtrFromOp(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		rmw := "or"
		if op == "ANDB" || op == "ANDW" || op == "ANDL" || op == "ANDQ" {
			rmw = "and"
		}
		tmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s %s seq_cst\n", tmp, rmw, ptr, ty, src)
		// atomicrmw returns the old value, while x86 logical instructions set
		// flags from the new value. LOCK does not alter that flag behavior.
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %s\n", out, rmw, ty, tmp, src)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		zf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zf, ty, out)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		sf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", sf, ty, out)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
		return true, false, nil
	}
	return false, false, nil
}

func (c *amd64Ctx) amd64AtomicPtrFromOp(op asm.Operand) (string, error) {
	if op.Kind == asm.OpFP {
		alloca, _, ok := c.fpResultAlloca(op.FPOffset)
		if !ok {
			return "", fmt.Errorf("amd64 atomic operation unsupported FP slot +%d(FP)", op.FPOffset)
		}
		c.markFPResultWritten(op.FPOffset)
		return alloca, nil
	}
	ptr, ptrType, err := c.resolveMemPtr(op)
	if err != nil {
		return "", err
	}
	if ptrType != "ptr" {
		return "", fmt.Errorf("amd64 atomic operation does not support segment-relative memory")
	}
	return ptr, nil
}

// lowerLockedRMW emits genuine atomic LLVM IR (atomicrmw / cmpxchg seq_cst)
// for lockable x86 memory RMW instructions preceded by LOCK.
func (c *amd64Ctx) lowerLockedRMW(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	s := string(op)
	if len(s) < 4 {
		return false, false, nil
	}
	ty := asm.I64
	align := 8
	bits := 64
	switch s[len(s)-1] {
	case 'B':
		ty, align, bits = asm.I8, 1, 8
	case 'W':
		ty, align, bits = asm.I16, 2, 16
	case 'L':
		ty, align, bits = asm.I32, 4, 32
	case 'Q':
		ty, align, bits = asm.I64, 8, 64
	default:
		return false, false, nil
	}
	stem := s[:len(s)-1]

	setZS := func(val string) {
		zf, sf := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zf, ty, val)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", sf, ty, val)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
	}

	switch stem {
	case "ADD", "SUB", "XOR":
		if len(ins.Args) != 2 || (!isX86MemOp(ins.Args[1]) && ins.Args[1].Kind != asm.OpFP) {
			return false, false, nil
		}
		rhs, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.amd64AtomicPtrFromOp(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		rmw := "add"
		if stem == "SUB" {
			rmw = "sub"
		} else if stem == "XOR" {
			rmw = "xor"
		}
		old, out := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s %s seq_cst\n", old, rmw, ptr, ty, rhs)
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %s\n", out, rmw, ty, old, rhs)
		setZS("%" + out)
		switch stem {
		case "ADD":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %%%s\n", cf, ty, out, old)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		case "SUB":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %s\n", cf, ty, old, rhs)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		default:
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		}
		return true, false, nil

	case "INC", "DEC":
		if len(ins.Args) != 1 || (!isX86MemOp(ins.Args[0]) && ins.Args[0].Kind != asm.OpFP) {
			return false, false, nil
		}
		ptr, err := c.amd64AtomicPtrFromOp(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		rmw := "add"
		if stem == "DEC" {
			rmw = "sub"
		}
		old, out := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s 1 seq_cst\n", old, rmw, ptr, ty)
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, 1\n", out, rmw, ty, old)
		setZS("%" + out)
		return true, false, nil

	case "BTS", "BTR", "BTC":
		if bits == 8 || len(ins.Args) != 2 || (!isX86MemOp(ins.Args[1]) && ins.Args[1].Kind != asm.OpFP) {
			return false, false, nil
		}
		idx, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.amd64AtomicPtrFromOp(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		// A register bit index on a memory operand addresses an unbounded
		// bit string: adjust ptr by floor(idx/bits) * (bits/8) bytes.
		if ins.Args[0].Kind == asm.OpReg && isX86MemOp(ins.Args[1]) {
			shiftWord, shiftBytes := 6, 3
			if bits == 32 {
				shiftWord, shiftBytes = 5, 2
			} else if bits == 16 {
				shiftWord, shiftBytes = 4, 1
			}
			word, byteOff := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %d\n", word, ty, idx, shiftWord)
			fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %d\n", byteOff, ty, word, shiftBytes)
			off64 := "%" + byteOff
			if ty != asm.I64 {
				se := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = sext %s %%%s to i64\n", se, ty, byteOff)
				off64 = "%" + se
			}
			adj := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %s\n", adj, ptr, off64)
			ptr = "%" + adj
		}
		amt, bit := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", amt, ty, idx, bits-1)
		fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", bit, ty, amt)
		arg := "%" + bit
		rmw := "or"
		if stem == "BTR" {
			rmw = "and"
			inv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, -1\n", inv, ty, bit)
			arg = "%" + inv
		} else if stem == "BTC" {
			rmw = "xor"
		}
		old, masked, cf := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s %s seq_cst\n", old, rmw, ptr, ty, arg)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", masked, ty, old, bit)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", cf, ty, masked)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		return true, false, nil

	case "NEG", "NOT", "ADC", "SBB":
		isUnary := stem == "NEG" || stem == "NOT"
		dstIdx := 1
		if isUnary {
			dstIdx = 0
		}
		if len(ins.Args) != dstIdx+1 || (!isX86MemOp(ins.Args[dstIdx]) && ins.Args[dstIdx].Kind != asm.OpFP) {
			return false, false, nil
		}
		var rhs string
		if !isUnary {
			rhs, err = c.evalIntSized(ins.Args[0], ty)
			if err != nil {
				return true, false, err
			}
		}
		ptr, err := c.amd64AtomicPtrFromOp(ins.Args[dstIdx])
		if err != nil {
			return true, false, err
		}
		var carryVal string
		if stem == "ADC" || stem == "SBB" {
			cf := c.loadFlag(c.flagsCFSlot)
			cz := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", cz, cf, ty)
			carryVal = "%" + cz
		}
		loopLbl := "lock_cas_" + c.newTmp()
		doneLbl := "lock_done_" + c.newTmp()
		fmt.Fprintf(c.b, "  br label %%%s\n%s:\n", loopLbl, loopLbl)
		cur := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s seq_cst, align %d\n", cur, ty, ptr, align)
		next := c.newTmp()
		var midTmp string
		switch stem {
		case "NEG":
			fmt.Fprintf(c.b, "  %%%s = sub %s 0, %%%s\n", next, ty, cur)
		case "NOT":
			fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, -1\n", next, ty, cur)
		case "ADC":
			s1 := c.newTmp()
			midTmp = s1
			fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", s1, ty, cur, rhs)
			fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %s\n", next, ty, s1, carryVal)
		case "SBB":
			s1 := c.newTmp()
			midTmp = s1
			fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %s\n", s1, ty, cur, rhs)
			fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %s\n", next, ty, s1, carryVal)
		}
		cx, okv := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %%%s, %s %%%s seq_cst seq_cst, align %d\n", cx, ptr, ty, cur, ty, next, align)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i1 } %%%s, 1\n", okv, ty, cx)
		// loopLbl is the sole predecessor of doneLbl, so %cur/%next/%midTmp dominate doneLbl directly.
		fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n%s:\n", okv, doneLbl, loopLbl, doneLbl)
		if stem != "NOT" {
			setZS("%" + next)
			switch stem {
			case "NEG":
				cf := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", cf, ty, cur)
				fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
			case "ADC":
				c1, c2, cf := c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %%%s\n", c1, ty, midTmp, cur)
				fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %%%s\n", c2, ty, next, midTmp)
				fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", cf, c1, c2)
				fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
			case "SBB":
				b1, b2, cf := c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %s\n", b1, ty, cur, rhs)
				fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %s\n", b2, ty, midTmp, carryVal)
				fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", cf, b1, b2)
				fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
			}
		}
		return true, false, nil
	}
	return false, false, nil
}

func (c *amd64Ctx) amd64AtomicPtrFromMem(mem asm.MemRef) (string, error) {
	ptr, ptrType, err := c.ptrFromMem(mem)
	if err != nil {
		return "", err
	}
	if ptrType != "ptr" {
		return "", fmt.Errorf("amd64 atomic operation does not support segment-relative memory")
	}
	return ptr, nil
}

func (c *amd64Ctx) amd64AtomicTruncFromI64(v64 string, ty asm.LLVMType) (string, error) {
	switch ty {
	case asm.I64:
		return v64, nil
	case asm.I32, asm.I16, asm.I8, asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported trunc target %s", ty)
	}
}

func (c *amd64Ctx) amd64AtomicExtendToI64(v string, ty asm.LLVMType) (string, error) {
	switch ty {
	case asm.I64:
		return v, nil
	case asm.I32, asm.I16, asm.I8, asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, ty, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported extend source %s", ty)
	}
}
