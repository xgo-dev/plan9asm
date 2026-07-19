package plan9asm

import "fmt"

func (c *amd64Ctx) lowerArith(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "PUSHQ":
		// Stack-manipulation appears in syscall asm stubs (e.g. preserve return
		// address register around SYSCALL). Lower to the local virtual stack.
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 PUSHQ expects src: %q", ins.Raw)
		}
		v, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		c.pushI64(v)
		return true, false, nil
	case "POPQ":
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 POPQ expects dstReg: %q", ins.Raw)
		}
		v := c.popI64()
		if err := c.storeReg(ins.Args[0].Reg, v); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "PUSHFQ":
		// Flag register modeling is minimal; preserve stack shape only.
		c.pushI64("0")
		return true, false, nil
	case "POPFQ":
		_ = c.popI64()
		return true, false, nil
	case "LFENCE", "MFENCE", "SFENCE", "PAUSE", "PREFETCHNTA":
		// Ordering/prefetch hints do not change SSA-visible values here.
		return true, false, nil
	case "UNDEF":
		// Trap marker in runtime asm; keep translation progressing.
		return true, false, nil
	case "RDTSC":
		if err := c.storeReg(AX, "0"); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DX, "0"); err != nil {
			return true, false, err
		}
		return true, false, nil
	case OpCPUID:
		eax64, err := c.loadReg(AX)
		if err != nil {
			return true, false, err
		}
		ecx64, err := c.loadReg(CX)
		if err != nil {
			return true, false, err
		}
		eax32 := c.newTmp()
		ecx32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", eax32, eax64)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", ecx32, ecx64)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { i32, i32, i32, i32 } asm sideeffect \"cpuid\", \"={ax},={bx},={cx},={dx},{ax},{cx},~{dirflag},~{fpsr},~{flags}\"(i32 %%%s, i32 %%%s)\n", call, eax32, ecx32)
		storeOut := func(idx int, reg Reg) error {
			part := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32, i32, i32 } %%%s, %d\n", part, call, idx)
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, part)
			return c.storeReg(reg, "%"+wide)
		}
		if err := storeOut(0, AX); err != nil {
			return true, false, err
		}
		if err := storeOut(1, BX); err != nil {
			return true, false, err
		}
		if err := storeOut(2, CX); err != nil {
			return true, false, err
		}
		if err := storeOut(3, DX); err != nil {
			return true, false, err
		}
		return true, false, nil
	case OpXGETBV:
		ecx64, err := c.loadReg(CX)
		if err != nil {
			return true, false, err
		}
		ecx32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", ecx32, ecx64)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { i32, i32 } asm sideeffect \"xgetbv\", \"={ax},={dx},{cx},~{dirflag},~{fpsr},~{flags}\"(i32 %%%s)\n", call, ecx32)
		storeOut := func(idx int, reg Reg) error {
			part := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32 } %%%s, %d\n", part, call, idx)
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, part)
			return c.storeReg(reg, "%"+wide)
		}
		if err := storeOut(0, AX); err != nil {
			return true, false, err
		}
		if err := storeOut(1, DX); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "RDTSCP":
		if err := c.storeReg(AX, "0"); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DX, "0"); err != nil {
			return true, false, err
		}
		if err := c.storeReg(CX, "0"); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "MOVSB":
		si, err := c.loadReg(SI)
		if err != nil {
			return true, false, err
		}
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		ps := c.ptrFromAddrI64(si)
		pd := c.ptrFromAddrI64(di)
		v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s, align 1\n", v, ps)
		fmt.Fprintf(c.b, "  store i8 %%%s, ptr %s, align 1\n", v, pd)
		ns := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 1\n", ns, si)
		nd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 1\n", nd, di)
		if err := c.storeReg(SI, "%"+ns); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DI, "%"+nd); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "MOVSQ":
		si, err := c.loadReg(SI)
		if err != nil {
			return true, false, err
		}
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		ps := c.ptrFromAddrI64(si)
		pd := c.ptrFromAddrI64(di)
		v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", v, ps)
		fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s, align 1\n", v, pd)
		ns := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 8\n", ns, si)
		nd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 8\n", nd, di)
		if err := c.storeReg(SI, "%"+ns); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DI, "%"+nd); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "STOSQ":
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		ax, err := c.loadReg(AX)
		if err != nil {
			return true, false, err
		}
		pd := c.ptrFromAddrI64(di)
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", ax, pd)
		nd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 8\n", nd, di)
		if err := c.storeReg(DI, "%"+nd); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "NEGL":
		// 32-bit negate with x86 semantics: write back low 32 bits and zero-extend.
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 NEGL expects dst: %q", ins.Raw)
		}
		switch ins.Args[0].Kind {
		case OpReg:
			dv, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			t32 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t32, dv)
			neg := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 0, %%%s\n", neg, t32)
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, neg)
			if err := c.storeReg(ins.Args[0].Reg, "%"+z); err != nil {
				return true, false, err
			}
			c.setZSFlagsFromI32("%" + neg)
			return true, false, nil
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s, align 1\n", ld, p)
			neg := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 0, %%%s\n", neg, ld)
			fmt.Fprintf(c.b, "  store i32 %%%s, ptr %s, align 1\n", neg, p)
			c.setZSFlagsFromI32("%" + neg)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 NEGL expects reg/mem dst: %q", ins.Raw)
		}
	case "RCRQ":
		// Rotate through carry right (count=1) used by runtime time division path.
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm {
			return true, false, fmt.Errorf("amd64 RCRQ expects $count, dstReg: %q", ins.Raw)
		}
		if ins.Args[0].Imm != 1 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 RCRQ currently supports $1, reg: %q", ins.Raw)
		}
		dv, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		oldCF := c.loadFlag(c.flagsCFSlot)
		lsb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 1\n", lsb, dv)
		newCF := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", newCF, lsb)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newCF, c.flagsCFSlot)
		shr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 1\n", shr, dv)
		cf64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", cf64, oldCF)
		cfhi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 63\n", cfhi, cf64)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", out, shr, cfhi)
		if err := c.storeReg(ins.Args[1].Reg, "%"+out); err != nil {
			return true, false, err
		}
		c.setZSFlagsFromI64("%" + out)
		return true, false, nil

	case "ADDQ", "SUBQ", "XORQ", "ANDQ", "ORQ":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		loadDst := func() (string, func(string) error, error) {
			switch ins.Args[1].Kind {
			case OpReg:
				dst := ins.Args[1].Reg
				dv, err := c.loadReg(dst)
				if err != nil {
					return "", nil, err
				}
				return dv, func(v string) error { return c.storeReg(dst, v) }, nil
			case OpMem:
				addr, err := c.addrFromMem(ins.Args[1].Mem)
				if err != nil {
					return "", nil, err
				}
				p := c.ptrFromAddrI64(addr)
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", ld, p)
				return "%" + ld, func(v string) error {
					fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", v, p)
					return nil
				}, nil
			default:
				return "", nil, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
			}
		}
		dv, storeDst, err := loadDst()
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		switch op {
		case "ADDQ":
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", t, dv, src)
		case "SUBQ":
			fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", t, dv, src)
		case "XORQ":
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", t, dv, src)
		case "ANDQ":
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", t, dv, src)
		case "ORQ":
			fmt.Fprintf(c.b, "  %%%s = or i64 %s, %s\n", t, dv, src)
		}
		r := "%" + t
		if err := storeDst(r); err != nil {
			return true, false, err
		}
		switch op {
		case "ADDQ":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %s\n", cf, r, dv)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		case "SUBQ":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %s\n", cf, dv, src)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		default:
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		}
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		c.setZSFlagsFromI64(r)
		return true, false, nil

	case "ADCQ", "SBBQ":
		// Add/subtract with carry/borrow: src, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst := ins.Args[1].Reg
		dv, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		cfIn := c.loadFlag(c.flagsCFSlot)
		cf64t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", cf64t, cfIn)
		cf64 := "%" + cf64t

		dv128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", dv128, dv)
		src128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", src128, src)
		cf128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", cf128, cf64)

		if op == "ADCQ" {
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", sum, dv, src)
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %s\n", res, sum, cf64)
			out := "%" + res
			if err := c.storeReg(dst, out); err != nil {
				return true, false, err
			}

			total1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i128 %%%s, %%%s\n", total1, dv128, src128)
			total2 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i128 %%%s, %%%s\n", total2, total1, cf128)
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i128 %%%s, 18446744073709551615\n", cf, total2)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
			c.setZSFlagsFromI64(out)
			return true, false, nil
		}

		subtr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i128 %%%s, %%%s\n", subtr, src128, cf128)
		borrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i128 %%%s, %%%s\n", borrow, dv128, subtr)
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", res, dv, src)
		res2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, %s\n", res2, res, cf64)
		out := "%" + res2
		if err := c.storeReg(dst, out); err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", borrow, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		c.setZSFlagsFromI64(out)
		return true, false, nil

	case "ADCB":
		// 8-bit add with carry: src, dstReg/mem.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		var d8 string
		var storeDst func(string) error
		switch ins.Args[1].Kind {
		case OpReg:
			dst := ins.Args[1].Reg
			dv64, err := c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", t, dv64)
			d8 = "%" + t
			storeDst = func(v8 string) error {
				return c.storeRegSized(dst, I8, v8)
			}
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s, align 1\n", ld, p)
			d8 = "%" + ld
			storeDst = func(v8 string) error {
				fmt.Fprintf(c.b, "  store i8 %s, ptr %s, align 1\n", v8, p)
				return nil
			}
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
		}

		s8, err := c.evalIntSized(ins.Args[0], I8)
		if err != nil {
			return true, false, err
		}
		cfIn := c.loadFlag(c.flagsCFSlot)
		cf8t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i8\n", cf8t, cfIn)
		cf8 := "%" + cf8t

		sum := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i8 %s, %s\n", sum, d8, s8)
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i8 %%%s, %s\n", res, sum, cf8)
		out8 := "%" + res
		if err := storeDst(out8); err != nil {
			return true, false, err
		}

		d16 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i16\n", d16, d8)
		s16 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i16\n", s16, s8)
		cf16 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i16\n", cf16, cf8)
		total1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i16 %%%s, %%%s\n", total1, d16, s16)
		total2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i16 %%%s, %%%s\n", total2, total1, cf16)
		cf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ugt i16 %%%s, 255\n", cf, total2)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		zf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, 0\n", zf, res)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		sf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i8 %%%s, 0\n", sf, res)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
		return true, false, nil

	case "ADCXQ", "ADOXQ":
		// BMI2 add-with-carry chains.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst := ins.Args[1].Reg
		dv, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		carryIn := c.loadFlag(c.flagsCFSlot)
		flagOut := c.flagsCFSlot
		if op == "ADOXQ" {
			carryIn = c.loadFlag(c.flagsOFSlot)
			flagOut = c.flagsOFSlot
		}
		cf64t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", cf64t, carryIn)
		cf64 := "%" + cf64t
		sum := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", sum, dv, src)
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %s\n", res, sum, cf64)
		out := "%" + res
		if err := c.storeReg(dst, out); err != nil {
			return true, false, err
		}
		dv128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", dv128, dv)
		src128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", src128, src)
		cf128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", cf128, cf64)
		total1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i128 %%%s, %%%s\n", total1, dv128, src128)
		total2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i128 %%%s, %%%s\n", total2, total1, cf128)
		carry := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ugt i128 %%%s, 18446744073709551615\n", carry, total2)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, flagOut)
		// ADCX/ADOX do not define ZF/SF in the same way as ADD; keep current bits.
		return true, false, nil

	case "ADDL", "SUBL", "XORL", "ANDL", "ORL":
		// 32-bit arithmetic/logical ops: src, dstReg (result zero-extended to i64).
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		dstKind := ins.Args[1].Kind
		dtr := ""
		var storeDst func(string) error
		switch dstKind {
		case OpReg:
			dst := ins.Args[1].Reg
			dv64, err := c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, dv64)
			dtr = "%" + t
			storeDst = func(v32 string) error {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, v32)
				return c.storeReg(dst, "%"+z)
			}
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s, align 1\n", ld, p)
			dtr = "%" + ld
			storeDst = func(v32 string) error {
				fmt.Fprintf(c.b, "  store i32 %s, ptr %s, align 1\n", v32, p)
				return nil
			}
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
		}
		var s32 string
		switch ins.Args[0].Kind {
		case OpImm:
			s32 = fmt.Sprintf("%d", int32(ins.Args[0].Imm))
		case OpReg, OpFP, OpMem, OpSym:
			v64, err := c.evalI64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v64)
			s32 = "%" + tr
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
		}
		x := c.newTmp()
		switch op {
		case "ADDL":
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", x, dtr, s32)
		case "SUBL":
			fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", x, dtr, s32)
		case "XORL":
			fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x, dtr, s32)
		case "ANDL":
			fmt.Fprintf(c.b, "  %%%s = and i32 %s, %s\n", x, dtr, s32)
		case "ORL":
			fmt.Fprintf(c.b, "  %%%s = or i32 %s, %s\n", x, dtr, s32)
		}
		if err := storeDst("%" + x); err != nil {
			return true, false, err
		}
		switch op {
		case "ADDL":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %%%s, %s\n", cf, x, dtr)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		case "SUBL":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %s, %s\n", cf, dtr, s32)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		default:
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		}
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		c.setZSFlagsFromI32("%" + x)
		return true, false, nil

	case "ADDB", "XORB", "ANDB", "ORB":
		// 8-bit scalar ops: src, dstReg (stored in the selected byte lane).
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv64, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		d8 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", d8, dv64)
		var s8 string
		switch ins.Args[0].Kind {
		case OpImm:
			s8 = fmt.Sprintf("%d", int8(ins.Args[0].Imm))
		case OpReg, OpFP, OpMem, OpSym:
			v64, err := c.evalI64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", tr, v64)
			s8 = "%" + tr
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
		}
		x := c.newTmp()
		switch op {
		case "ADDB":
			fmt.Fprintf(c.b, "  %%%s = add i8 %%%s, %s\n", x, d8, s8)
		case "XORB":
			fmt.Fprintf(c.b, "  %%%s = xor i8 %%%s, %s\n", x, d8, s8)
		case "ANDB":
			fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, %s\n", x, d8, s8)
		case "ORB":
			fmt.Fprintf(c.b, "  %%%s = or i8 %%%s, %s\n", x, d8, s8)
		}
		if err := c.storeRegSized(dst, I8, "%"+x); err != nil {
			return true, false, err
		}
		if op == "ADDB" {
			d16 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", d16, d8)
			s16 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i16\n", s16, s8)
			total := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i16 %%%s, %%%s\n", total, d16, s16)
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i16 %%%s, 255\n", cf, total)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		} else {
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		}
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		zf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, 0\n", zf, x)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		sf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i8 %%%s, 0\n", sf, x)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
		return true, false, nil

	case "INCQ", "DECQ":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 %s expects dst: %q", op, ins.Raw)
		}
		var v string
		var storeDst func(string) error
		switch ins.Args[0].Kind {
		case OpReg:
			r := ins.Args[0].Reg
			dv, err := c.loadReg(r)
			if err != nil {
				return true, false, err
			}
			v = dv
			storeDst = func(out string) error { return c.storeReg(r, out) }
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", ld, p)
			v = "%" + ld
			storeDst = func(out string) error {
				fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", out, p)
				return nil
			}
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
		}
		t := c.newTmp()
		if op == "INCQ" {
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, 1\n", t, v)
		} else {
			fmt.Fprintf(c.b, "  %%%s = sub i64 %s, 1\n", t, v)
		}
		out := "%" + t
		if err := storeDst(out); err != nil {
			return true, false, err
		}
		c.setZSFlagsFromI64(out)
		return true, false, nil

	case "INCL", "DECL":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 %s expects dst: %q", op, ins.Raw)
		}
		var v64 string
		var storeDst func(string) error
		switch ins.Args[0].Kind {
		case OpReg:
			r := ins.Args[0].Reg
			dv, err := c.loadReg(r)
			if err != nil {
				return true, false, err
			}
			v64 = dv
			storeDst = func(out32 string) error {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, out32)
				return c.storeReg(r, "%"+z)
			}
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s, align 1\n", ld, p)
			v64 = "%" + ld
			storeDst = func(out32 string) error {
				fmt.Fprintf(c.b, "  store i32 %s, ptr %s, align 1\n", out32, p)
				return nil
			}
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
		}
		tr := c.newTmp()
		if ins.Args[0].Kind == OpMem {
			fmt.Fprintf(c.b, "  %%%s = add i32 0, %s\n", tr, v64)
		} else {
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v64)
		}
		x := c.newTmp()
		if op == "INCL" {
			fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, 1\n", x, tr)
		} else {
			fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, 1\n", x, tr)
		}
		if err := storeDst("%" + x); err != nil {
			return true, false, err
		}
		c.setZSFlagsFromI32("%" + x)
		return true, false, nil

	case "LEAQ", "LEAL":
		// LEA{Q,L} srcAddr, dstReg
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects srcAddr, dstReg: %q", op, ins.Raw)
		}
		dst := ins.Args[1].Reg
		storeLEA := func(addr string) error {
			if op == "LEAL" {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, addr)
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
				return c.storeReg(dst, "%"+z)
			}
			return c.storeReg(dst, addr)
		}
		switch ins.Args[0].Kind {
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			return true, false, storeLEA(addr)
		case OpFP:
			// LEA of a return slot, e.g. "LEAQ ret+32(FP), R8".
			alloca, _, ok := c.fpResultAlloca(ins.Args[0].FPOffset)
			if ok {
				c.markFPResultAddrTaken(ins.Args[0].FPOffset)
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, alloca)
				return true, false, storeLEA("%" + t)
			}
			// Fallback: treat FP slot value as pointer-like integer address.
			v, err := c.evalFPToI64(ins.Args[0].FPOffset)
			if err != nil {
				v = "0"
			}
			return true, false, storeLEA(v)
		case OpFPAddr:
			// Address of a return slot alloca.
			alloca, _, ok := c.fpResultAlloca(ins.Args[0].FPOffset)
			if ok {
				c.markFPResultAddrTaken(ins.Args[0].FPOffset)
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, alloca)
				return true, false, storeLEA("%" + t)
			}
			v, err := c.evalFPToI64(ins.Args[0].FPOffset)
			if err != nil {
				v = "0"
			}
			return true, false, storeLEA(v)
		case OpSym:
			p, err := c.ptrFromSB(ins.Args[0].Sym)
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, p)
			return true, false, storeLEA("%" + t)
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
		}

	case "POPCNTL", "POPCNTQ":
		// POPCNT{L,Q} srcReg, dstReg (count bits; L is 32-bit, Q is 64-bit).
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects srcReg, dstReg: %q", op, ins.Raw)
		}
		srcv, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		dst := ins.Args[1].Reg
		if op == "POPCNTL" {
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, srcv)
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.ctpop.i32(i32 %%%s)\n", call, tr)
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, call)
			return true, false, c.storeReg(dst, "%"+z)
		}
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.ctpop.i64(i64 %s)\n", call, srcv)
		return true, false, c.storeReg(dst, "%"+call)

	case "TZCNTQ":
		// TZCNTQ srcReg, dstReg.
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 TZCNTQ expects srcReg, dstReg: %q", ins.Raw)
		}
		srcv, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.cttz.i64(i64 %s, i1 false)\n", call, srcv)
		if err := c.storeReg(ins.Args[1].Reg, "%"+call); err != nil {
			return true, false, err
		}
		cf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", cf, srcv)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		c.setZSFlagsFromI64("%" + call)
		return true, false, nil

	case "BSFQ", "BSRQ", "BSWAPQ", "BSFL", "BSRL":
		// Bit scan/byte swap ops (reg, reg).
		src := Reg("")
		dst := Reg("")
		switch len(ins.Args) {
		case 1:
			if op != "BSWAPQ" || ins.Args[0].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 %s expects reg or srcReg,dstReg: %q", op, ins.Raw)
			}
			src = ins.Args[0].Reg
			dst = ins.Args[0].Reg
		case 2:
			if ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 %s expects srcReg, dstReg: %q", op, ins.Raw)
			}
			src = ins.Args[0].Reg
			dst = ins.Args[1].Reg
		default:
			return true, false, fmt.Errorf("amd64 %s expects 1 or 2 operands: %q", op, ins.Raw)
		}
		sv, err := c.loadReg(src)
		if err != nil {
			return true, false, err
		}
		switch op {
		case "BSFQ":
			// ZF is set when src == 0.
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", zf, sv)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			// dst = cttz(src). Use non-poison form for src==0.
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.cttz.i64(i64 %s, i1 false)\n", call, sv)
			return true, false, c.storeReg(dst, "%"+call)
		case "BSRQ":
			// ZF is set when src == 0.
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", zf, sv)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			// dst = 63 - ctlz(src). Use non-poison form for src==0.
			clz := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.ctlz.i64(i64 %s, i1 false)\n", clz, sv)
			sub := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i64 63, %%%s\n", sub, clz)
			return true, false, c.storeReg(dst, "%"+sub)
		case "BSWAPQ":
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.bswap.i64(i64 %s)\n", call, sv)
			return true, false, c.storeReg(dst, "%"+call)
		case "BSFL":
			// ZF is set when low 32-bit src == 0.
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, sv)
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, 0\n", zf, tr)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			// dst = zext(cttz(trunc32(src))). Use non-poison form for src==0.
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.cttz.i32(i32 %%%s, i1 false)\n", call, tr)
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, call)
			return true, false, c.storeReg(dst, "%"+z)
		case "BSRL":
			// ZF is set when low 32-bit src == 0.
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, sv)
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, 0\n", zf, tr)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			// dst = zext(31 - ctlz(trunc32(src))). Use non-poison form for src==0.
			clz := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.ctlz.i32(i32 %%%s, i1 false)\n", clz, tr)
			sub := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 31, %%%s\n", sub, clz)
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, sub)
			return true, false, c.storeReg(dst, "%"+z)
		}
		return true, false, fmt.Errorf("amd64: unsupported bit op %s", op)

	case "SETEQ", "SETGT", "SETGE", "SETHI", "SETCS":
		// SETcc dst: set byte based on flags.
		// We support register destinations and FP result slots.
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 %s expects one destination: %q", op, ins.Raw)
		}
		cond := ""
		switch op {
		case "SETEQ":
			cond = c.loadFlag(c.flagsZSlot)
		case "SETGT":
			// signed >
			slt := c.loadFlag(c.flagsSltSlot)
			z := c.loadFlag(c.flagsZSlot)
			t1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t1, slt, z)
			t2 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", t2, t1)
			cond = "%" + t2
		case "SETGE":
			slt := c.loadFlag(c.flagsSltSlot)
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", t, slt)
			cond = "%" + t
		case "SETHI":
			// unsigned >
			cf := c.loadFlag(c.flagsCFSlot)
			z := c.loadFlag(c.flagsZSlot)
			t1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t1, cf, z)
			t2 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", t2, t1)
			cond = "%" + t2
		case "SETCS":
			cond = c.loadFlag(c.flagsCFSlot)
		}
		switch ins.Args[0].Kind {
		case OpReg:
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i8 1, i8 0\n", sel, cond)
			return true, false, c.storeRegSized(ins.Args[0].Reg, I8, "%"+sel)
		case OpFP:
			return true, false, c.storeFPResult(ins.Args[0].FPOffset, I1, cond)
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg or fp destination: %q", op, ins.Raw)
		}

	case "CMOVQEQ", "CMOVQNE", "CMOVQCS", "CMOVQCC", "CMOVQGT":
		// Conditional move: src, dstReg
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst := ins.Args[1].Reg
		cur, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		cond := ""
		switch op {
		case "CMOVQEQ":
			cond = c.loadFlag(c.flagsZSlot)
		case "CMOVQNE":
			z := c.loadFlag(c.flagsZSlot)
			nz := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", nz, z)
			cond = "%" + nz
		case "CMOVQCS":
			cond = c.loadFlag(c.flagsCFSlot)
		case "CMOVQCC":
			cf := c.loadFlag(c.flagsCFSlot)
			nc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", nc, cf)
			cond = "%" + nc
		case "CMOVQGT":
			slt := c.loadFlag(c.flagsSltSlot)
			z := c.loadFlag(c.flagsZSlot)
			t1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t1, slt, z)
			t2 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", t2, t1)
			cond = "%" + t2
		}
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", sel, cond, src, cur)
		return true, false, c.storeReg(dst, "%"+sel)

	case "ANDNL", "ANDNQ":
		// BMI1 ANDN: dst = ~src2 & src1
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src1, src2, dstReg: %q", op, ins.Raw)
		}
		src1, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		src2, err := c.evalI64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		dst := ins.Args[2].Reg
		if op == "ANDNQ" {
			n := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, -1\n", n, src2)
			a := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %s\n", a, n, src1)
			return true, false, c.storeReg(dst, "%"+a)
		}
		s1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", s1, src1)
		s2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", s2, src2)
		n := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i32 %%%s, -1\n", n, s2)
		a := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", a, n, s1)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, a)
		return true, false, c.storeReg(dst, "%"+z)

	case "BEXTRQ":
		// BMI1 bit field extract: control, src, dst.
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 BEXTRQ expects control, src, dstReg: %q", ins.Raw)
		}
		ctrl, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		src, err := c.evalI64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		start := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 255\n", start, ctrl)
		lenShift := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 8\n", lenShift, ctrl)
		length := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 255\n", length, lenShift)
		startOK := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, 64\n", startOK, start)
		safeStart := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 63\n", safeStart, startOK, start)
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %%%s\n", shifted, src, safeStart)
		rawLen := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 0\n", rawLen, startOK, length)
		remain := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 64, %%%s\n", remain, safeStart)
		useRawLen := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, %%%s\n", useRawLen, rawLen, remain)
		effLen := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %%%s\n", effLen, useRawLen, rawLen, remain)
		isFull := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, 64\n", isFull, effLen)
		safeLen := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", safeLen, effLen)
		one := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 1, %%%s\n", one, safeLen)
		maskTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, -1\n", maskTmp, one)
		mask := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 -1, i64 %%%s\n", mask, isFull, maskTmp)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %%%s\n", out, shifted, mask)
		return true, false, c.storeReg(ins.Args[2].Reg, "%"+out)

	case "BZHIQ":
		// BMI2 zero high bits: index, src, dst.
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 BZHIQ expects index, src, dstReg: %q", ins.Raw)
		}
		idx, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		src, err := c.evalI64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		valid := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, 64\n", valid, idx)
		isZero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", isZero, idx)
		safeIdx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", safeIdx, idx)
		one := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 1, %%%s\n", one, safeIdx)
		maskTmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, -1\n", maskTmp, one)
		maskOrZero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 0, i64 %%%s\n", maskOrZero, isZero, maskTmp)
		mask := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 -1\n", mask, valid, maskOrZero)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %%%s\n", out, src, mask)
		return true, false, c.storeReg(ins.Args[2].Reg, "%"+out)

	case "SHRQ", "SHLQ", "SARQ", "SHLL", "SHRL", "SARL", "SALQ", "SALL":
		// Shift ops:
		// - 2-operand: amt, dst (in-place)
		// - 3-operand: amt, src, dst
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("amd64 %s expects amt,dst or amt,src,dst: %q", op, ins.Raw)
		}
		if ins.Args[len(ins.Args)-1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s destination must be reg: %q", op, ins.Raw)
		}
		dst := ins.Args[len(ins.Args)-1].Reg
		srcReg := dst
		if len(ins.Args) == 3 {
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 %s src must be reg in 3-operand form: %q", op, ins.Raw)
			}
			srcReg = ins.Args[1].Reg
		}
		dv, err := c.loadReg(srcReg)
		if err != nil {
			return true, false, err
		}
		amtMask := int64(63)
		valTy := I64
		if op == "SHLL" || op == "SHRL" || op == "SARL" || op == "SALL" {
			amtMask = 31
			valTy = I32
		}
		amtI64 := ""
		switch ins.Args[0].Kind {
		case OpImm:
			amtI64 = fmt.Sprintf("%d", ins.Args[0].Imm&amtMask)
		case OpReg:
			av, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", m, av, amtMask)
			amtI64 = "%" + m
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported shift amt: %q", op, ins.Raw)
		}

		if valTy == I64 {
			t := c.newTmp()
			switch op {
			case "SHRQ":
				fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %s\n", t, dv, amtI64)
			case "SHLQ", "SALQ":
				fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %s\n", t, dv, amtI64)
			case "SARQ":
				fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, %s\n", t, dv, amtI64)
			}
			return true, false, c.storeReg(dst, "%"+t)
		}

		// 32-bit shifts: operate on low 32, zero-extend to 64.
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, dv)
		amt32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", amt32, amtI64)
		sh := c.newTmp()
		if op == "SHLL" || op == "SALL" {
			fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %%%s\n", sh, tr, amt32)
		} else if op == "SARL" {
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %%%s, %%%s\n", sh, tr, amt32)
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, %%%s\n", sh, tr, amt32)
		}
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, sh)
		return true, false, c.storeReg(dst, "%"+z)

	case "SHLB":
		// 8-bit logical left shift: amt, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 SHLB expects amt, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv64, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		d8 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", d8, dv64)
		var amt string
		switch ins.Args[0].Kind {
		case OpImm:
			amt = fmt.Sprintf("%d", ins.Args[0].Imm&31)
		case OpReg:
			av, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 31\n", m, av)
			amt = "%" + m
		default:
			return true, false, fmt.Errorf("amd64 SHLB unsupported shift amt: %q", ins.Raw)
		}
		inRange := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, 8\n", inRange, amt)
		safeAmt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 7\n", safeAmt, inRange, amt)
		amt8 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", amt8, safeAmt)
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i8 %%%s, %%%s\n", sh, d8, amt8)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 0\n", out, inRange, sh)
		return true, false, c.storeRegSized(dst, I8, "%"+out)

	case "SHLXQ", "SHRXQ":
		// BMI2 variable shifts: amt, src, dst.
		if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects amt, srcReg, dstReg: %q", op, ins.Raw)
		}
		src, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		var amt string
		switch ins.Args[0].Kind {
		case OpImm:
			amt = fmt.Sprintf("%d", ins.Args[0].Imm&63)
		case OpReg:
			av, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", m, av)
			amt = "%" + m
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported shift amt: %q", op, ins.Raw)
		}
		t := c.newTmp()
		if op == "SHLXQ" {
			fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %s\n", t, src, amt)
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %s\n", t, src, amt)
		}
		return true, false, c.storeReg(ins.Args[2].Reg, "%"+t)

	case "ROLL":
		// 32-bit rotate-left: count, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 ROLL expects count, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv64, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		dv32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", dv32, dv64)

		var cnt32 string
		switch ins.Args[0].Kind {
		case OpImm:
			cnt32 = fmt.Sprintf("%d", uint32(ins.Args[0].Imm))
		case OpReg:
			cv64, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, cv64)
			cnt32 = "%" + tr
		default:
			return true, false, fmt.Errorf("amd64 ROLL unsupported count: %q", ins.Raw)
		}

		cm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, 31\n", cm, cnt32)
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 32, %%%s\n", neg, cm)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %%%s\n", lhs, dv32, cm)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, %%%s\n", rhs, dv32, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", rot, lhs, rhs)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, rot)
		return true, false, c.storeReg(dst, "%"+z)

	case "ROLQ":
		// 64-bit rotate-left: count, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 ROLQ expects count, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		var cnt string
		switch ins.Args[0].Kind {
		case OpImm:
			cnt = fmt.Sprintf("%d", uint64(ins.Args[0].Imm)&63)
		case OpReg:
			cv, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", m, cv)
			cnt = "%" + m
		default:
			return true, false, fmt.Errorf("amd64 ROLQ unsupported count: %q", ins.Raw)
		}
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 64, %s\n", neg, cnt)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %s\n", lhs, dv, cnt)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %%%s\n", rhs, dv, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", rot, lhs, rhs)
		return true, false, c.storeReg(dst, "%"+rot)

	case "RORQ":
		// 64-bit rotate-right: count, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 RORQ expects count, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		var cnt string
		switch ins.Args[0].Kind {
		case OpImm:
			cnt = fmt.Sprintf("%d", uint64(ins.Args[0].Imm)&63)
		case OpReg:
			cv, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", m, cv)
			cnt = "%" + m
		default:
			return true, false, fmt.Errorf("amd64 RORQ unsupported count: %q", ins.Raw)
		}
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 64, %s\n", neg, cnt)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %s\n", lhs, dv, cnt)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %%%s\n", rhs, dv, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", rot, lhs, rhs)
		return true, false, c.storeReg(dst, "%"+rot)

	case "RORL":
		// 32-bit rotate-right: count, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 RORL expects count, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv64, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		dv32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", dv32, dv64)
		var cnt32 string
		switch ins.Args[0].Kind {
		case OpImm:
			cnt32 = fmt.Sprintf("%d", uint32(ins.Args[0].Imm)&31)
		case OpReg:
			cv64, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, cv64)
			cm := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", cm, tr)
			cnt32 = "%" + cm
		default:
			return true, false, fmt.Errorf("amd64 RORL unsupported count: %q", ins.Raw)
		}
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 32, %s\n", neg, cnt32)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, %s\n", lhs, dv32, cnt32)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %%%s\n", rhs, dv32, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", rot, lhs, rhs)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, rot)
		return true, false, c.storeReg(dst, "%"+z)

	case "RORXL", "RORXQ":
		// BMI2 rotate-right without flags:
		// - RORXL $imm, srcReg, dstReg (32-bit)
		// - RORXQ $imm, srcReg, dstReg (64-bit)
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects $imm, srcReg, dstReg: %q", op, ins.Raw)
		}
		src, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		dst := ins.Args[2].Reg
		if op == "RORXQ" {
			n := uint64(ins.Args[0].Imm) & 63
			neg := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i64 64, %d\n", neg, n)
			nm := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", nm, neg)
			lhs := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", lhs, src, n)
			rhs := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %%%s\n", rhs, src, nm)
			rot := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", rot, lhs, rhs)
			return true, false, c.storeReg(dst, "%"+rot)
		}
		n := uint32(ins.Args[0].Imm) & 31
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, src)
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 32, %d\n", neg, n)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, %d\n", lhs, tr, n)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %%%s\n", rhs, tr, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", rot, lhs, rhs)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, rot)
		return true, false, c.storeReg(dst, "%"+z)

	case "NOTB":
		// NOT does not modify flags. For a register operand, only the selected
		// low byte is changed and the remaining register bits are preserved.
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 NOTB expects one operand: %q", ins.Raw)
		}
		switch ins.Args[0].Kind {
		case OpReg:
			r := ins.Args[0].Reg
			v64, err := c.loadReg(r)
			if err != nil {
				return true, false, err
			}
			v8 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", v8, v64)
			not := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i8 %%%s, -1\n", not, v8)
			return true, false, c.storeRegSized(r, I8, "%"+not)
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			load := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s, align 1\n", load, p)
			not := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i8 %%%s, -1\n", not, load)
			fmt.Fprintf(c.b, "  store i8 %%%s, ptr %s, align 1\n", not, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 NOTB expects reg or mem: %q", ins.Raw)
		}

	case "NOTL":
		// 32-bit bitwise NOT, result zero-extended to 64-bit.
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 NOTL expects reg: %q", ins.Raw)
		}
		r := ins.Args[0].Reg
		v64, err := c.loadReg(r)
		if err != nil {
			return true, false, err
		}
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v64)
		x := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i32 %%%s, -1\n", x, tr)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, x)
		return true, false, c.storeReg(r, "%"+z)

	case "NOTQ":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 NOTQ expects one operand: %q", ins.Raw)
		}
		switch ins.Args[0].Kind {
		case OpReg:
			r := ins.Args[0].Reg
			v, err := c.loadReg(r)
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, -1\n", t, v)
			return true, false, c.storeReg(r, "%"+t)
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", ld, p)
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %%%s, -1\n", t, ld)
			fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s, align 1\n", t, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 NOTQ expects reg or mem: %q", ins.Raw)
		}

	case "BSWAPL":
		// BSWAPL reg: byte swap low 32 bits and zero-extend result to i64.
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 BSWAPL expects reg: %q", ins.Raw)
		}
		r := ins.Args[0].Reg
		v64, err := c.loadReg(r)
		if err != nil {
			return true, false, err
		}
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v64)
		bswap := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bswap.i32(i32 %%%s)\n", bswap, tr)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, bswap)
		return true, false, c.storeReg(r, "%"+z)

	case "MULQ":
		// MULQ src: RDX:RAX = RAX * src (unsigned).
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 MULQ expects src: %q", ins.Raw)
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		ax, err := c.loadReg(AX)
		if err != nil {
			return true, false, err
		}
		a128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", a128, ax)
		b128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", b128, src)
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i128 %%%s, %%%s\n", p, a128, b128)
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", lo, p)
		hiShift := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", hiShift, p)
		hi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", hi, hiShift)
		if err := c.storeReg(AX, "%"+lo); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DX, "%"+hi); err != nil {
			return true, false, err
		}
		cf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", cf, hi)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		return true, false, nil

	case "MULXQ":
		// BMI2 MULXQ src, loDst, hiDst: {hi,lo} = RDX * src (unsigned).
		if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 MULXQ expects src, loDst, hiDst: %q", ins.Raw)
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dx, err := c.loadReg(DX)
		if err != nil {
			return true, false, err
		}
		a128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", a128, dx)
		b128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", b128, src)
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i128 %%%s, %%%s\n", p, a128, b128)
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", lo, p)
		hiShift := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", hiShift, p)
		hi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", hi, hiShift)
		if err := c.storeReg(ins.Args[1].Reg, "%"+lo); err != nil {
			return true, false, err
		}
		if err := c.storeReg(ins.Args[2].Reg, "%"+hi); err != nil {
			return true, false, err
		}
		return true, false, nil

	case "MULL":
		// MULL src: EDX:EAX = EAX * src (unsigned 32-bit)
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 MULL expects src: %q", ins.Raw)
		}
		src64, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		ax64, err := c.loadReg(AX)
		if err != nil {
			return true, false, err
		}
		ax32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", ax32, ax64)
		src32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", src32, src64)
		az := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", az, ax32)
		bz := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", bz, src32)
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", p, az, bz)
		lo32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo32, p)
		hiShift := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hiShift, p)
		hi32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi32, hiShift)
		lo64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", lo64, lo32)
		hi64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", hi64, hi32)
		if err := c.storeReg(AX, "%"+lo64); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DX, "%"+hi64); err != nil {
			return true, false, err
		}
		return true, false, nil

	case "DIVL":
		// DIVL src: unsigned divide EDX:EAX by src; quotient->EAX remainder->EDX.
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 DIVL expects src: %q", ins.Raw)
		}
		src64, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		ax64, err := c.loadReg(AX)
		if err != nil {
			return true, false, err
		}
		dx64, err := c.loadReg(DX)
		if err != nil {
			return true, false, err
		}
		ax32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", ax32, ax64)
		dx32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", dx32, dx64)
		src32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", src32, src64)
		az := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", az, ax32)
		dz := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", dz, dx32)
		divisor := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", divisor, src32)
		hi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 32\n", hi, dz)
		dividend := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", dividend, hi, az)
		q := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = udiv i64 %%%s, %%%s\n", q, dividend, divisor)
		r := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = urem i64 %%%s, %%%s\n", r, dividend, divisor)
		q32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", q32, q)
		r32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", r32, r)
		q64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", q64, q32)
		r64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", r64, r32)
		if err := c.storeReg(AX, "%"+q64); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DX, "%"+r64); err != nil {
			return true, false, err
		}
		return true, false, nil

	case "IMULQ", "IMUL3Q":
		// IMULQ src         -> RDX:RAX = signed RAX*src
		// IMULQ src, dst    -> dst = signed(dst*src)
		// IMUL3Q imm,src,dst -> dst = signed(src*imm)
		switch len(ins.Args) {
		case 1:
			src, err := c.evalI64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			ax, err := c.loadReg(AX)
			if err != nil {
				return true, false, err
			}
			a128 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i64 %s to i128\n", a128, ax)
			b128 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i64 %s to i128\n", b128, src)
			p := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i128 %%%s, %%%s\n", p, a128, b128)
			lo := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", lo, p)
			hiShift := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr i128 %%%s, 64\n", hiShift, p)
			hi := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", hi, hiShift)
			if err := c.storeReg(AX, "%"+lo); err != nil {
				return true, false, err
			}
			if err := c.storeReg(DX, "%"+hi); err != nil {
				return true, false, err
			}
			return true, false, nil
		case 2:
			if ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 IMULQ expects src, dstReg: %q", ins.Raw)
			}
			src, err := c.evalI64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			dst := ins.Args[1].Reg
			dv, err := c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
			a128 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i64 %s to i128\n", a128, dv)
			b128 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i64 %s to i128\n", b128, src)
			p := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i128 %%%s, %%%s\n", p, a128, b128)
			lo := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", lo, p)
			return true, false, c.storeReg(dst, "%"+lo)
		case 3:
			if op != "IMUL3Q" || ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 %s expects imm, src, dstReg: %q", op, ins.Raw)
			}
			imm, err := c.evalI64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			src, err := c.evalI64(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			a128 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i64 %s to i128\n", a128, src)
			b128 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i64 %s to i128\n", b128, imm)
			p := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i128 %%%s, %%%s\n", p, a128, b128)
			lo := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", lo, p)
			return true, false, c.storeReg(ins.Args[2].Reg, "%"+lo)
		default:
			return true, false, fmt.Errorf("amd64 %s expects 1/2/3 operands: %q", op, ins.Raw)
		}

	case "NEGQ":
		// NEGQ reg
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 NEGQ expects reg: %q", ins.Raw)
		}
		r := ins.Args[0].Reg
		v, err := c.loadReg(r)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 0, %s\n", t, v)
		out := "%" + t
		if err := c.storeReg(r, out); err != nil {
			return true, false, err
		}
		cf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %s, 0\n", cf, v)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		c.setZSFlagsFromI64(out)
		return true, false, nil
	}
	return false, false, nil
}
