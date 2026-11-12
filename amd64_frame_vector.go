package plan9asm

import "fmt"

// fpVectorSlot locates the scalar ABI0 field containing one byte of a vector
// memory operand. Aggregate parameters have several independently allocated
// fields on amd64; treating the first field as a contiguous pointer is wrong.
func (c *amd64Ctx) fpVectorSlot(off int64) (FrameSlot, bool, bool) {
	for _, slot := range c.sig.Frame.Params {
		size := x86FrameTypeSize(slot.Type)
		if slot.Type == Ptr {
			size = int64(goWordSize(c.goarch))
		}
		if off >= slot.Offset && off < slot.Offset+size {
			return slot, false, true
		}
	}
	for _, slot := range c.fpResults {
		size := x86FrameTypeSize(slot.Type)
		if slot.Type == Ptr {
			size = int64(goWordSize(c.goarch))
		}
		if off >= slot.Offset && off < slot.Offset+size {
			return slot, true, true
		}
	}
	return FrameSlot{}, false, false
}

func (c *amd64Ctx) validateFPVectorSpan(off int64, byteWidth int) error {
	for i := 0; i < byteWidth; i++ {
		if _, _, ok := c.fpVectorSlot(off + int64(i)); !ok {
			return fmt.Errorf("undeclared FP vector byte at +%d(FP)", off+int64(i))
		}
	}
	return nil
}

func (c *amd64Ctx) loadFPVectorBytes(off int64, byteWidth int) (string, error) {
	return c.loadFPVectorBytesMode(off, byteWidth, false)
}

// Integer byte views may observe an intermediate noncanonical bool byte, but
// only after their independent whole-function canonical result proof. Existing
// SIMD views keep their old logical-field policy and never acquire this mode.
func (c *amd64Ctx) loadFPVectorField(slot FrameSlot, result, physicalBool bool) (string, LLVMType, error) {
	if physicalBool && slot.Type == I1 {
		if !c.abi0BoolResultByteStorage() {
			return "", "", fmt.Errorf("%w: FP bool byte lacks a checked storage role", ErrProbeNeedsContext)
		}
		pointer := c.fpParamAlloca[slot.Offset]
		if result {
			pointer, _, _ = c.fpResultAlloca(slot.Offset)
		}
		if c.classicFrame != "" {
			pointer = c.classicFramePtr(slot.Offset)
		}
		if pointer == "" {
			return "", "", fmt.Errorf("missing physical FP bool storage at +%d(FP)", slot.Offset)
		}
		return c.loadFPStorage(I8, pointer, ", align 1"), I8, nil
	}
	if result {
		value, err := c.loadFPResult(slot)
		return value, slot.Type, err
	}
	value, err := c.loadFPParamValue(slot)
	return value, slot.Type, err
}

func (c *amd64Ctx) loadFPVectorBytesMode(off int64, byteWidth int, physicalBool bool) (string, error) {
	if err := c.validateFPVectorSpan(off, byteWidth); err != nil {
		return "", err
	}
	value := "zeroinitializer"
	words := make(map[int64]string)
	for i := 0; i < byteWidth; i++ {
		slot, result, _ := c.fpVectorSlot(off + int64(i))
		word, found := words[slot.Offset]
		if !found {
			scalar, typ, err := c.loadFPVectorField(slot, result, physicalBool)
			if err != nil {
				return "", err
			}
			word, err = c.fpVectorScalarBits(typ, scalar)
			if err != nil {
				return "", err
			}
			words[slot.Offset] = word
		}
		shift := (off + int64(i) - slot.Offset) * 8
		if shift != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", shifted, word, shift)
			word = "%" + shifted
		}
		part := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", part, word)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i8> %s, i8 %%%s, i32 %d\n", inserted, byteWidth, value, part, i)
		value = "%" + inserted
	}
	return value, nil
}

func (c *amd64Ctx) fpVectorScalarBits(typ LLVMType, scalar string) (string, error) {
	switch typ {
	case I64:
		return scalar, nil
	case Ptr:
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", converted, scalar)
		return "%" + converted, nil
	case LLVMType("double"):
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", converted, scalar)
		return "%" + converted, nil
	case LLVMType("float"):
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", bits, scalar)
		scalar = "%" + bits
		typ = I32
	}
	bits, ok := amd64IntegerTypeBits(typ)
	if !ok {
		return "", fmt.Errorf("unsupported FP vector field type %s", typ)
	}
	wide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i64\n", wide, bits, scalar)
	return "%" + wide, nil
}

func (c *amd64Ctx) storeFPVectorBytes(off int64, byteWidth int, value, metadata string) error {
	return c.storeFPVectorBytesMode(off, byteWidth, value, metadata, false)
}

func (c *amd64Ctx) storeFPVectorBytesMode(off int64, byteWidth int, value, metadata string, physicalBool bool) error {
	if err := c.validateFPVectorSpan(off, byteWidth); err != nil {
		return err
	}
	if physicalBool && !c.abi0BoolResultByteStorage() {
		for i := 0; i < byteWidth; i++ {
			if slot, _, _ := c.fpVectorSlot(off + int64(i)); slot.Type == I1 {
				return fmt.Errorf("%w: FP bool byte lacks a checked storage role", ErrProbeNeedsContext)
			}
		}
	}
	if c.classicFrame != "" {
		for i := 0; i < byteWidth; i++ {
			part := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", part, byteWidth, value, i)
			fmt.Fprintf(c.b, "  store i8 %%%s, ptr %s, align 1%s\n", part, c.classicFramePtr(off+int64(i)), metadata)
			if slot, result, ok := c.fpVectorSlot(off + int64(i)); ok && result {
				c.markFPResultWritten(slot.Offset)
			}
		}
		return nil
	}

	updated := make(map[int64]string)
	order := make([]FrameSlot, 0, byteWidth/4)
	for i := 0; i < byteWidth; i++ {
		current := off + int64(i)
		slot, result, _ := c.fpVectorSlot(current)
		bits, found := updated[slot.Offset]
		if !found {
			scalar, typ, err := c.loadFPVectorField(slot, result, physicalBool)
			if err != nil {
				return err
			}
			bits, err = c.fpVectorScalarBits(typ, scalar)
			if err != nil {
				return err
			}
			order = append(order, slot)
		}
		part := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", part, byteWidth, value, i)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", wide, part)
		shift := (current - slot.Offset) * 8
		inserted := "%" + wide
		if shift != 0 {
			tmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", tmp, inserted, shift)
			inserted = "%" + tmp
		}
		cleared := c.newTmp()
		mask := ^(uint64(0xff) << uint(shift))
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", cleared, bits, mask)
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", merged, cleared, inserted)
		updated[slot.Offset] = "%" + merged
	}
	for _, slot := range order {
		bits := updated[slot.Offset]
		converted := bits
		typ := slot.Type
		if physicalBool && typ == I1 {
			typ = I8
		}
		switch typ {
		case I64:
		case Ptr:
			tmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", tmp, bits)
			converted = "%" + tmp
		case LLVMType("double"):
			tmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", tmp, bits)
			converted = "%" + tmp
		case LLVMType("float"):
			narrow, tmp := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, bits)
			fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", tmp, narrow)
			converted = "%" + tmp
		default:
			width, ok := amd64IntegerTypeBits(typ)
			if !ok || width > 64 {
				return fmt.Errorf("unsupported FP vector field type %s", slot.Type)
			}
			tmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", tmp, bits, width)
			converted = "%" + tmp
		}
		if err := c.storeFPResultWithMetadata(slot.Offset, typ, converted, metadata); err != nil {
			return err
		}
	}
	return nil
}
