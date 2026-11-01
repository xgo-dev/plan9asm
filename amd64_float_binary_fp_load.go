package plan9asm

import "fmt"

// FP operands describe checked virtual ABI0 fields. Loading one field using
// the whole instruction width loses later fields (or reads past an alloca).
func (c *amd64Ctx) loadFloatBinaryFPBits(source Operand, bits int) (string, error) {
	bytes, err := c.loadFPVectorBytes(source.FPOffset, bits/8)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", value, bits/8, bytes, bits)
	return "%" + value, nil
}

func (c *amd64Ctx) loadFloatBinaryScalar(source Operand, bits int, mask string) (string, error) {
	if source.Kind != OpFP {
		return c.loadFMA3Scalar(source, bits, mask)
	}
	if err := c.validateFPVectorSpan(source.FPOffset, bits/8); err != nil {
		return "", err
	}
	load := func() (string, error) { return c.loadFloatBinaryFPBits(source, bits) }
	var value string
	var err error
	if mask == "" {
		value, err = load()
	} else {
		value, err = c.loadX86ScalarIf(bits, amd64MaskBitI1(c, mask, 0), load)
	}
	if err != nil {
		return "", err
	}
	floating := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to %s\n", floating, bits, value, amd64FMA3LLVMType(1, bits))
	return "%" + floating, nil
}

func (c *amd64Ctx) loadFloatBinaryPacked(source Operand, width, bits int, broadcast bool, mask string) (string, error) {
	if source.Kind != OpFP {
		return c.loadMaskedPackedCompareLanes(source, width, bits, broadcast, mask)
	}
	memoryBytes := width
	if broadcast {
		memoryBytes = bits / 8
	}
	if err := c.validateFPVectorSpan(source.FPOffset, memoryBytes); err != nil {
		return "", err
	}
	lanes := width * 8 / bits
	if broadcast {
		load := func() (string, error) { return c.loadFloatBinaryFPBits(source, bits) }
		var value string
		var err error
		if mask == "" {
			value, err = load()
		} else {
			relevant, active := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", relevant, mask, uint64(1)<<uint(lanes)-1)
			fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", active, relevant)
			value, err = c.loadX86ScalarIf(bits, "%"+active, load)
		}
		if err != nil {
			return "", err
		}
		return amd64SplatInteger(c, lanes, bits, value), nil
	}
	if mask == "" {
		return c.loadPackedCompareLanes(source, width, bits, false)
	}
	// Do not turn separately declared fields into an invented native pointer.
	// Each active lane loads its complete checked byte span independently.
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		part := source
		part.FPOffset += int64(lane * bits / 8)
		value, err := c.loadX86ScalarIf(bits, amd64MaskBitI1(c, mask, lane), func() (string, error) {
			return c.loadFloatBinaryFPBits(part, bits)
		})
		if err != nil {
			return "", err
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n", inserted, lanes, bits, result, bits, value, lane)
		result = "%" + inserted
	}
	return result, nil
}
