package plan9asm

import "fmt"

// Native compact arrays advance only for enabled lanes. Ordinary masked LLVM
// intrinsics may discard a dead read; guarded volatile accesses retain the
// source instruction's enabled access/fault, even when its vector is unused.
// No inbounds, alignment, extent or allocation assumption follows from a GEP.
func (c *amd64Ctx) lowerNativeCompactMemory(ins Instr, form x86PackedCompactForm) error {
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return fmt.Errorf("%w: compact memory needs its original native address size", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(ins.Args[form.memory])
	if err != nil {
		return err
	}
	width, bits := form.byteWidth, form.laneBits
	if form.mask < 0 {
		if form.expand {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load volatile <%d x i8>, %s %s, align 1\n", value, width, pointerType, pointer)
			return c.storePackedMoveOperand(ins.Args[form.destination], width, "%"+value)
		}
		value, err := c.loadPackedCompareBytes(ins.Args[0], width)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile <%d x i8> %s, %s %s, align 1\n", width, value, pointerType, pointer)
		return nil
	}
	mask, err := c.loadK(ins.Args[form.mask].Reg)
	if err != nil {
		return err
	}
	lanes := width * 8 / bits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, bits)
	value := "zeroinitializer"
	if !form.expand || !form.zeroing {
		operand := ins.Args[0]
		if form.expand {
			operand = ins.Args[form.destination]
		}
		value, err = c.loadPackedCompareLanes(operand, width, bits, false)
		if err != nil {
			return err
		}
	}
	offset := "0"
	for lane := 0; lane < lanes; lane++ {
		active := amd64MaskBitI1(c, mask, lane)
		address := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 %s\n", address, pointerType, pointer, offset)
		if form.expand {
			loaded, err := c.loadX86ScalarIf(bits, active, func() (string, error) {
				loaded := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %%%s, align 1\n", loaded, bits, pointerType, address)
				return "%" + loaded, nil
			})
			if err != nil {
				return err
			}
			if !form.zeroing {
				old, selected := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", old, vectorType, value, lane)
				fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %s, i%d %%%s\n", selected, active, bits, loaded, bits, old)
				loaded = "%" + selected
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %s, i32 %d\n", inserted, vectorType, value, bits, loaded, lane)
			value = "%" + inserted
		} else {
			element := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", element, vectorType, value, lane)
			storeLabel, joinLabel := c.newTmp()+"_compact_store", c.newTmp()+"_compact_join"
			fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n%s:\n", active, storeLabel, joinLabel, storeLabel)
			fmt.Fprintf(c.b, "  store volatile i%d %%%s, %s %%%s, align 1\n", bits, element, pointerType, address)
			fmt.Fprintf(c.b, "  br label %%%s\n%s:\n", joinLabel, joinLabel)
		}
		step, next := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %d, i64 0\n", step, active, bits/8)
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", next, offset, step)
		offset = "%" + next
	}
	if form.expand {
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytes, vectorType, value, width)
		return c.storePackedMoveOperand(ins.Args[form.destination], width, "%"+bytes)
	}
	return nil
}
