package plan9asm

import "fmt"

type arm64RawIntegerCompare struct {
	predicate   string
	testBits    bool
	scalar      bool
	zero        bool
	arrangement arm64VectorArrangement
	destination int
	first       int
	second      int
}

type arm64RawIntegerCompareEncoding struct {
	mask      uint32
	value     uint32
	predicate string
	zero      bool
	testBits  bool
	scalar    bool
}

var arm64RawIntegerCompareEncodings = [...]arm64RawIntegerCompareEncoding{
	{0xff20fc00, 0x7e208c00, "eq", false, false, true},
	{0xbf20fc00, 0x2e208c00, "eq", false, false, false},
	{0xff20fc00, 0x5e203c00, "sge", false, false, true},
	{0xbf20fc00, 0x0e203c00, "sge", false, false, false},
	{0xff20fc00, 0x5e203400, "sgt", false, false, true},
	{0xbf20fc00, 0x0e203400, "sgt", false, false, false},
	{0xff20fc00, 0x7e203400, "ugt", false, false, true},
	{0xbf20fc00, 0x2e203400, "ugt", false, false, false},
	{0xff20fc00, 0x7e203c00, "uge", false, false, true},
	{0xbf20fc00, 0x2e203c00, "uge", false, false, false},
	{0xff20fc00, 0x5e208c00, "ne", false, true, true},
	{0xbf20fc00, 0x0e208c00, "ne", false, true, false},
	{0xff3ffc00, 0x5e209800, "eq", true, false, true},
	{0xbf3ffc00, 0x0e209800, "eq", true, false, false},
	{0xff3ffc00, 0x7e208800, "sge", true, false, true},
	{0xbf3ffc00, 0x2e208800, "sge", true, false, false},
	{0xff3ffc00, 0x5e208800, "sgt", true, false, true},
	{0xbf3ffc00, 0x0e208800, "sgt", true, false, false},
	{0xff3ffc00, 0x7e209800, "sle", true, false, true},
	{0xbf3ffc00, 0x2e209800, "sle", true, false, false},
	{0xff3ffc00, 0x5e20a800, "slt", true, false, true},
	{0xbf3ffc00, 0x0e20a800, "slt", true, false, false},
}

func decodeARM64RawIntegerCompare(word uint32) (arm64RawIntegerCompare, bool) {

	var decoded arm64RawIntegerCompareEncoding
	matched := false
	for _, candidate := range arm64RawIntegerCompareEncodings {
		if word&candidate.mask == candidate.value {
			decoded = candidate
			matched = true
			break
		}
	}
	if !matched {
		return arm64RawIntegerCompare{}, false
	}

	bits := 64
	lanes := 1
	if !decoded.scalar {
		size := int(word>>22) & 3
		vectorBits := 64
		if word&(1<<30) != 0 {
			vectorBits = 128
		}
		if size == 3 && vectorBits != 128 {
			return arm64RawIntegerCompare{}, false
		}
		bits = 8 << size
		lanes = vectorBits / bits
	}
	form := arm64RawIntegerCompare{
		predicate:   decoded.predicate,
		testBits:    decoded.testBits,
		scalar:      decoded.scalar,
		zero:        decoded.zero,
		arrangement: arm64VectorArrangement{elementBits: bits, lanes: lanes},
		destination: int(word & 31),
		first:       int(word>>5) & 31,
	}
	if !decoded.zero {
		form.second = int(word>>16) & 31
	}
	return form, true
}

func (c *arm64Ctx) lowerRawIntegerCompare(form arm64RawIntegerCompare) error {
	first, err := c.loadRawARM64VectorOperand(form.first, form.arrangement, 0, form.scalar)
	if err != nil {
		return err
	}
	second := "zeroinitializer"
	if !form.zero {
		second, err = c.loadRawARM64VectorOperand(form.second, form.arrangement, 0, form.scalar)
		if err != nil {
			return err
		}
	}
	vectorType := fmt.Sprintf("<%d x i%d>", form.arrangement.lanes, form.arrangement.elementBits)
	if form.testBits {
		anded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", anded, vectorType, first, second)
		first = "%" + anded
		second = "zeroinitializer"
	}
	compared := c.newTmp()
	allBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", compared, form.predicate, vectorType, first, second)
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to %s\n", allBits, form.arrangement.lanes, compared, vectorType)
	return c.storeRawARM64VectorResult(form.destination, form.arrangement, "%"+allBits, form.scalar)
}
