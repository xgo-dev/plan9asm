package plan9asm

import "fmt"

type arm64RawSVEPTrue struct {
	elementBits int
	pattern     int
	destination int
}

func decodeARM64RawSVEPTrue(word uint32) (arm64RawSVEPTrue, bool) {
	if word&0xff3ffc10 != 0x2518e000 {
		return arm64RawSVEPTrue{}, false
	}
	pattern := int(word>>5) & 31
	// Unknown pattern encodings architecturally produce an empty predicate;
	// they are not undefined instructions (Arm PTRUE / DecodePredCount).
	return arm64RawSVEPTrue{
		elementBits: 8 << (int(word>>22) & 3),
		pattern:     pattern,
		destination: int(word) & 15,
	}, true
}

func (c *arm64Ctx) lowerRawSVEPTrue(form arm64RawSVEPTrue) error {
	lanes := 128 / form.elementBits
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	predicate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ptrue.nxv%di1(i32 %d)\n", predicate, predicateType, lanes, form.pattern)
	value := "%" + predicate
	if form.elementBits != 8 {
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv%di1(%s %s)\n",
			converted, lanes, predicateType, value)
		value = "%" + converted
	}
	return c.storePReg(form.destination, value)
}
