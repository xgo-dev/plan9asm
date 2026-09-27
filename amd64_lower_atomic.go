package plan9asm

import "fmt"

func (c *amd64Ctx) lowerAtomic(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if spec, recognized := amd64ExchangeSpecs[Op(normalizeInstructionOpcode(op))]; recognized {
		return c.lowerExchange(op, spec, ins)
	}
	if _, _, recognized := amd64CompareExchangeProperties(normalizeInstructionOpcode(op)); recognized {
		return c.lowerCompareExchange(op, ins)
	}
	switch op {
	case "LOCK":
		// LOCK is a prefix in Plan 9 syntax. Our lowering emits atomic IR for
		// the following memory RMW instruction, so the prefix itself is a no-op.
		return true, false, nil

	case "ORB", "ANDB", "ORL", "ANDL", "ORQ", "ANDQ":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpMem {
			return false, false, nil
		}
		ty := I8
		switch op {
		case "ORL", "ANDL":
			ty = I32
		case "ORQ", "ANDQ":
			ty = I64
		}
		src64, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		src, err := c.amd64AtomicTruncFromI64(src64, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.amd64AtomicPtrFromMem(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		rmw := "or"
		if op == "ANDB" || op == "ANDL" || op == "ANDQ" {
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

func (c *amd64Ctx) amd64AtomicPtrFromMem(mem MemRef) (string, error) {
	ptr, ptrType, err := c.ptrFromMem(mem)
	if err != nil {
		return "", err
	}
	if ptrType != "ptr" {
		return "", fmt.Errorf("amd64 atomic operation does not support segment-relative memory")
	}
	return ptr, nil
}

func (c *amd64Ctx) amd64AtomicTruncFromI64(v64 string, ty LLVMType) (string, error) {
	switch ty {
	case I64:
		return v64, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported trunc target %s", ty)
	}
}

func (c *amd64Ctx) amd64AtomicExtendToI64(v string, ty LLVMType) (string, error) {
	switch ty {
	case I64:
		return v, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, ty, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported extend source %s", ty)
	}
}
