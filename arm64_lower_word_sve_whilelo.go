package plan9asm

import "fmt"

type arm64RawSVEWhileLO struct {
	elementBits int
	predicate   int
	first       int
	second      int
}

func decodeARM64RawSVEWhileLO(word uint32) (arm64RawSVEWhileLO, bool) {
	if word&0xff20fc00 != 0x25201c00 {
		return arm64RawSVEWhileLO{}, false
	}
	elementBits := 8 << ((word >> 22) & 3)
	return arm64RawSVEWhileLO{
		elementBits: int(elementBits),
		predicate:   int(word & 15),
		first:       int((word >> 5) & 31),
		second:      int((word >> 16) & 31),
	}, true
}

func (c *arm64Ctx) lowerRawSVEWhileLO(form arm64RawSVEWhileLO) error {
	first, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.first)))
	if err != nil {
		return err
	}
	second, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.second)))
	if err != nil {
		return err
	}
	lanes := 128 / form.elementBits
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.whilelo.nxv%di1.i64(i64 %s, i64 %s)\n", result, predicateType, lanes, first, second)
	if err := c.storePRegElements(form.predicate, form.elementBits, "%"+result); err != nil {
		return err
	}
	governing, _, err := c.allTruePRegElements(form.elementBits)
	if err != nil {
		return err
	}
	c.setSVEPredicateFlags(governing, "%"+result, predicateType, lanes)
	return nil
}
