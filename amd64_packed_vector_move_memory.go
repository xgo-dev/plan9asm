package plan9asm

import "fmt"

// Unaligned packed moves are bit copies with no alignment precondition. Keep
// physical reads and writes observable without requiring an AVX512 host merely
// to transport a Z-width software vector. Volatile accesses do not assert that
// an incoming address is valid, nonnull, initialized, aligned or dereferenceable.
// A target may split a non-native vector width; this is not an atomicity proof.
func (c *amd64Ctx) lowerUnalignedPackedMoveMemory(ins Instr, form amd64PackedVectorMoveForm) error {
	memory := ins.Args[form.memory]
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(memory)
	if err != nil {
		return err
	}
	width := form.byteWidth
	if form.mask < 0 {
		if form.memoryWrite {
			value, err := c.loadPackedCompareBytes(ins.Args[0], width)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store volatile <%d x i8> %s, %s %s, align 1\n", width, value, pointerType, pointer)
			return nil
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load volatile <%d x i8>, %s %s, align 1\n", value, width, pointerType, pointer)
		return c.storePackedMoveOperand(ins.Args[form.destination], width, "%"+value)
	}

	mask, err := c.loadK(ins.Args[form.mask].Reg)
	if err != nil {
		return err
	}
	bits := form.spec.elementBits
	lanes := width * 8 / bits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, bits)
	value := "zeroinitializer"
	if form.memoryWrite {
		value, err = c.loadPackedCompareLanes(ins.Args[0], width, bits, false)
	} else if !form.zeroing {
		value, err = c.loadPackedCompareLanes(ins.Args[form.destination], width, bits, false)
	}
	if err != nil {
		return err
	}

	for lane := 0; lane < lanes; lane++ {
		condition := amd64MaskBitI1(c, mask, lane)
		address := c.newTmp()
		// No inbounds GEP: inactive lanes, including a null base, need no
		// allocation. Only the guarded branch accesses the selected bytes.
		fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 %d\n", address, pointerType, pointer, lane*bits/8)
		if form.memoryWrite {
			element := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", element, vectorType, value, lane)
			storeLabel, joinLabel := c.newTmp()+"_packed_store", c.newTmp()+"_packed_join"
			fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n%s:\n", condition, storeLabel, joinLabel, storeLabel)
			fmt.Fprintf(c.b, "  store volatile i%d %%%s, %s %%%s, align 1\n", bits, element, pointerType, address)
			fmt.Fprintf(c.b, "  br label %%%s\n%s:\n", joinLabel, joinLabel)
			continue
		}
		loaded, err := c.loadX86ScalarIf(bits, condition, func() (string, error) {
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
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %s, i%d %%%s\n", selected, condition, bits, loaded, bits, old)
			loaded = "%" + selected
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %s, i32 %d\n", inserted, vectorType, value, bits, loaded, lane)
		value = "%" + inserted
	}
	if form.memoryWrite {
		return nil
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytes, vectorType, value, width)
	return c.storePackedMoveOperand(ins.Args[form.destination], width, "%"+bytes)
}
