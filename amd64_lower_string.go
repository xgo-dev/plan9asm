package plan9asm

import (
	"fmt"
)

func (c *amd64Ctx) lowerString(ins Instr) (ok bool, terminated bool, err error) {
	form, ok, err := x86StringInstructionProperties(ins, c.goarch)
	if !ok {
		return false, false, nil
	}
	if form.kind == "" {
		return true, false, err
	}
	// Preserve the existing consumption order: a malformed opcode suffix has
	// not consumed a prefix; mode/operand rejection after a valid head has.
	prefix := c.repeatPrefix
	c.repeatPrefix = ""
	if err != nil {
		return true, false, err
	}
	kind, typ, width := form.kind, form.typ, form.width

	count := "1"
	if prefix != "" {
		cx, err := c.loadReg(CX)
		if err != nil {
			return true, false, err
		}
		if c.goarch == "386" {
			cx32 := c.truncI64(cx, I32)
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, cx32)
			count = "%" + wide
		} else {
			count = cx
		}
	}
	direction := c.loadDirectionFlag()

	switch kind {
	case "movs":
		si, err := c.loadReg(SI)
		if err != nil {
			return true, false, err
		}
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void @%s(i64 %s, i64 %s, i64 %s, i1 %s)\n", x86StringHelperName(kind, width), di, si, count, direction)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %d\n", bytes, count, width)
		if err := c.storeStringIndex(SI, si, "%"+bytes, direction); err != nil {
			return true, false, err
		}
		if err := c.storeStringIndex(DI, di, "%"+bytes, direction); err != nil {
			return true, false, err
		}

	case "stos":
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, typ)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void @%s(i64 %s, %s %s, i64 %s, i1 %s)\n", x86StringHelperName(kind, width), di, typ, value, count, direction)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %d\n", bytes, count, width)
		if err := c.storeStringIndex(DI, di, "%"+bytes, direction); err != nil {
			return true, false, err
		}

	case "scas":
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		needle, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, typ)
		if err != nil {
			return true, false, err
		}
		whileEqual := prefix == "REP"
		resultType := fmt.Sprintf("{ i64, i64, %s, i1 }", typ)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @%s(i64 %s, %s %s, i64 %s, i1 %s, i1 %t)\n", call, resultType, x86StringHelperName(kind, width), di, typ, needle, count, direction, whileEqual)
		next := c.newTmp()
		remaining := c.newTmp()
		lastValue := c.newTmp()
		executed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 0\n", next, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 1\n", remaining, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 2\n", lastValue, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 3\n", executed, resultType, call)
		if err := c.storeReg(DI, "%"+next); err != nil {
			return true, false, err
		}
		// SCAS sets all six status flags from accumulator minus the last
		// element read, not just the equality flag used to control repetition.
		c.setStringCompareFlags(typ, needle, "%"+lastValue, "%"+executed, prefix != "")
		if prefix != "" {
			if err := c.storeStringCount("%" + remaining); err != nil {
				return true, false, err
			}
		}

	case "cmps":
		si, err := c.loadReg(SI)
		if err != nil {
			return true, false, err
		}
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		whileEqual := prefix == "REP"
		resultType := fmt.Sprintf("{ i64, i64, i64, %s, %s, i1 }", typ, typ)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @%s(i64 %s, i64 %s, i64 %s, i1 %s, i1 %t)\n", call, resultType, x86StringHelperName(kind, width), si, di, count, direction, whileEqual)
		nextSI := c.newTmp()
		nextDI := c.newTmp()
		remaining := c.newTmp()
		left := c.newTmp()
		right := c.newTmp()
		executed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 0\n", nextSI, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 1\n", nextDI, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 2\n", remaining, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 3\n", left, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 4\n", right, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 5\n", executed, resultType, call)
		if err := c.storeReg(SI, "%"+nextSI); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DI, "%"+nextDI); err != nil {
			return true, false, err
		}
		if prefix != "" {
			if err := c.storeStringCount("%" + remaining); err != nil {
				return true, false, err
			}
		}
		c.setStringCompareFlags(typ, "%"+left, "%"+right, "%"+executed, prefix != "")

	case "lods":
		si, err := c.loadReg(SI)
		if err != nil {
			return true, false, err
		}
		resultType := fmt.Sprintf("{ i64, i64, %s, i1 }", typ)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @%s(i64 %s, i64 %s, i1 %s)\n", call, resultType, x86StringHelperName(kind, width), si, count, direction)
		nextSI := c.newTmp()
		remaining := c.newTmp()
		loaded := c.newTmp()
		executed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 0\n", nextSI, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 1\n", remaining, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 2\n", loaded, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 3\n", executed, resultType, call)
		if err := c.storeReg(SI, "%"+nextSI); err != nil {
			return true, false, err
		}
		var oldAccumulator string
		if prefix != "" {
			old, err := c.loadReg(AX)
			if err != nil {
				return true, false, err
			}
			oldAccumulator = old
		}
		if err := c.storeRegSized(AX, typ, "%"+loaded); err != nil {
			return true, false, err
		}
		if prefix != "" {
			written, err := c.loadReg(AX)
			if err != nil {
				return true, false, err
			}
			// An empty repeat executes no accumulator write at all. Selecting
			// only the low operand width before storeRegSized would still clear
			// AMD64's high 32 bits for LODSL even on that empty path.
			selected := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 %s\n", selected, executed, written, oldAccumulator)
			if err := c.storeReg(AX, "%"+selected); err != nil {
				return true, false, err
			}
			if err := c.storeStringCount("%" + remaining); err != nil {
				return true, false, err
			}
		}
	}

	if prefix != "" && kind != "scas" && kind != "cmps" {
		if err := c.storeStringCount("0"); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}

func x86StringHelperName(kind string, width int) string {
	suffix := map[int]string{1: "b", 2: "w", 4: "l", 8: "q"}[width]
	if kind == "movs" {
		return "__plan9asm_movs" + suffix
	}
	return "__plan9asm_rep_" + kind + suffix
}

func (c *amd64Ctx) setStringCompareFlags(typ LLVMType, left, right, executed string, preserveEmpty bool) {
	flags := c.x86StatusFlagSlots()
	old := make([]string, len(flags))
	if preserveEmpty {
		for index, flag := range flags {
			old[index] = c.loadFlag(flag.slot)
		}
	}
	c.setCmpFlagsSized(typ, left, right)
	if preserveEmpty {
		// REP/REPN with a zero initial count performs no comparison and
		// preserves all six status flags. The helper also performs no load.
		for index, flag := range flags {
			current := c.loadFlag(flag.slot)
			selected := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %s\n", selected, executed, current, old[index])
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selected, flag.slot)
		}
	}
}

func (c *amd64Ctx) storeStringCount(value string) error {
	if c.goarch == "386" {
		return c.storeRegSized(CX, I32, c.truncI64(value, I32))
	}
	return c.storeRegSized(CX, I64, value)
}

func (c *amd64Ctx) loadDirectionFlag() string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", t, c.directionSlot)
	return "%" + t
}

func (c *amd64Ctx) storeStringIndex(reg Reg, old, delta, backward string) error {
	forward := c.newTmp()
	reverse := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", forward, old, delta)
	fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", reverse, old, delta)
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %%%s, i64 %%%s\n", next, backward, reverse, forward)
	return c.storeReg(reg, "%"+next)
}
