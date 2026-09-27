package plan9asm

import "fmt"

type arm64RawSVEDupGeneral struct {
	elementBits int
	source      int
	destination int
}

// decodeARM64RawSVEDupGeneral covers the complete SVE DUP (general) encoding:
// DUP Zd.T, Rn, where T is B/H/S/D and R31 denotes SP (not ZR).
func decodeARM64RawSVEDupGeneral(word uint32) (arm64RawSVEDupGeneral, bool) {
	if word&0xff3ffc00 != 0x05203800 {
		return arm64RawSVEDupGeneral{}, false
	}
	return arm64RawSVEDupGeneral{
		elementBits: 8 << (int(word>>22) & 3),
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawSVEDupGeneral(form arm64RawSVEDupGeneral) error {
	reg := Reg(fmt.Sprintf("R%d", form.source))
	if form.source == 31 {
		reg = SP
	}
	source, err := c.loadReg(reg)
	if err != nil {
		return err
	}
	if form.elementBits != 64 {
		narrowed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrowed, source, form.elementBits)
		source = "%" + narrowed
	}
	lanes := 128 / form.elementBits
	vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, form.elementBits)
	inserted := c.newTmp()
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s poison, i%d %s, i64 0\n", inserted, vectorType, form.elementBits, source)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <vscale x %d x i32> zeroinitializer\n", splat, vectorType, inserted, vectorType, lanes)
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <vscale x 16 x i8>\n", bytes, vectorType, splat)
	return c.storeZReg(form.destination, "%"+bytes)
}
