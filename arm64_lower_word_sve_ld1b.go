package plan9asm

import "fmt"

type arm64RawSVELD1B struct {
	elementBits int
	predicate   int
	base        int
	index       int
	vector      int
}

func decodeARM64RawSVELD1B(word uint32) (arm64RawSVELD1B, bool) {
	if word&0xff80e000 != 0xa4004000 {
		return arm64RawSVELD1B{}, false
	}
	return arm64RawSVELD1B{
		elementBits: 8 << ((word >> 21) & 3),
		predicate:   int((word >> 10) & 7),
		base:        int((word >> 5) & 31),
		index:       int((word >> 16) & 31),
		vector:      int(word & 31),
	}, true
}

func (c *arm64Ctx) lowerRawSVELD1B(form arm64RawSVELD1B) error {
	predicate, err := c.loadPReg(form.predicate)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(form.elementBits)
	if err != nil {
		return err
	}
	narrowPredicate := predicate
	if form.elementBits != 8 {
		narrowPredicate = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x %d x i1> @llvm.aarch64.sve.convert.from.svbool.nxv%di1(<vscale x 16 x i1> %s)\n", narrowPredicate, lanes, lanes, predicate)
		narrowPredicate = "%" + narrowPredicate
	}
	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	if form.base == 31 {
		baseReg = SP
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return err
	}
	index := ZR
	if form.index != 31 {
		index = Reg(fmt.Sprintf("R%d", form.index))
	}
	indexValue, err := c.loadReg(index)
	if err != nil {
		return err
	}
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", address, base, indexValue)
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", pointer, address)
	loaded := c.newTmp()
	vectorType := fmt.Sprintf("<vscale x %d x i8>", lanes)
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.masked.load.nxv%di8.p0(ptr align 1 %%%s, %s %s, %s zeroinitializer)\n", loaded, vectorType, lanes, pointer, predicateType, narrowPredicate, vectorType)
	value := "%" + loaded
	if form.elementBits != 8 {
		widenedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, form.elementBits)
		widened := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", widened, vectorType, value, widenedType)
		value = "%" + widened
	}
	if form.elementBits != 8 {
		bytes := c.newTmp()
		widenedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, form.elementBits)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 16 x i8>\n", bytes, widenedType, value)
		value = "%" + bytes
	}
	return c.storeZReg(form.vector, value)
}
