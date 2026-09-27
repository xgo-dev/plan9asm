package plan9asm

import "fmt"

func (c *amd64Ctx) abi0CallStackPtr(off int64) (string, error) {
	sp, err := c.loadReg(SP)
	if err != nil {
		return "", fmt.Errorf("ABI0 call stack: %w", err)
	}
	addr := sp
	if off != 0 {
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", next, sp, off)
		addr = "%" + next
	}
	ptr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", ptr, addr)
	return "%" + ptr, nil
}

func (c *amd64Ctx) abi0CallArgs(callee string, sig FuncSig) ([]string, error) {
	slotsByArg := make([][]FrameSlot, len(sig.Args))
	for _, slot := range sig.Frame.Params {
		if slot.Index < 0 || slot.Index >= len(sig.Args) {
			return nil, fmt.Errorf("amd64 call %q: ABI0 parameter at +%d has invalid argument index %d", callee, slot.Offset, slot.Index)
		}
		slotsByArg[slot.Index] = append(slotsByArg[slot.Index], slot)
	}
	args := make([]string, 0, len(sig.Args))
	for argIndex, argType := range sig.Args {
		slots := slotsByArg[argIndex]
		if len(slots) == 0 {
			return nil, fmt.Errorf("amd64 call %q: ABI0 argument %d has no frame slot", callee, argIndex)
		}
		if len(slots) == 1 && len(frameSlotFields(slots[0])) == 0 {
			if slots[0].Type != argType {
				return nil, fmt.Errorf("amd64 call %q: ABI0 argument %d frame type %s does not match %s", callee, argIndex, slots[0].Type, argType)
			}
			ptr, err := c.abi0CallStackPtr(slots[0].Offset)
			if err != nil {
				return nil, err
			}
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", value, argType, ptr)
			args = append(args, fmt.Sprintf("%s %%%s", argType, value))
			continue
		}
		aggregate := "undef"
		for _, slot := range slots {
			if len(frameSlotFields(slot)) == 0 {
				return nil, fmt.Errorf("amd64 call %q: ABI0 aggregate argument %d has a scalar frame slot", callee, argIndex)
			}
			ptr, err := c.abi0CallStackPtr(slot.Offset)
			if err != nil {
				return nil, err
			}
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", value, slot.Type, ptr)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %%%s%s\n", inserted, argType, aggregate, slot.Type, value, frameSlotExtractSuffix(slot))
			aggregate = "%" + inserted
		}
		args = append(args, fmt.Sprintf("%s %s", argType, aggregate))
	}
	return args, nil
}

func (c *amd64Ctx) storeABI0CallResult(callee string, sig FuncSig, result string) error {
	if len(sig.Frame.Results) == 0 {
		return fmt.Errorf("amd64 call %q: ABI0 result %s has no frame slot", callee, sig.Ret)
	}
	fields, aggregate := parseLiteralStructFields(sig.Ret)
	for _, slot := range sig.Frame.Results {
		value := result
		if aggregate {
			if slot.Index < 0 || slot.Index >= len(fields) || fields[slot.Index] != slot.Type {
				return fmt.Errorf("amd64 call %q: ABI0 result slot %d does not match %s", callee, slot.Index, sig.Ret)
			}
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", extracted, sig.Ret, result, slot.Index)
			value = "%" + extracted
		} else if slot.Index != 0 || slot.Type != sig.Ret {
			return fmt.Errorf("amd64 call %q: ABI0 scalar result frame does not match %s", callee, sig.Ret)
		}
		ptr, err := c.abi0CallStackPtr(slot.Offset)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", slot.Type, value, ptr)
	}
	return nil
}
