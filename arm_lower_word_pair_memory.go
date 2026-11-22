package plan9asm

import "fmt"

type armRawPairMemory struct {
	address   armIntegerMemoryForm
	first     int
	base      int
	condition string
}

// LDRD and STRD share the A32 extra load/store address encoding. Bit 22
// chooses an unshifted register offset or an eight-bit split immediate.
func decodeARMRawPairMemory(word uint32) (armRawPairMemory, bool, error) {
	if word&0x0e1000d0 != 0x000000d0 {
		return armRawPairMemory{}, false, nil
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawPairMemory{}, false, nil
	}
	first := int(word>>12) & 15
	base := int(word>>16) & 15
	load := word&(1<<5) == 0
	postIndex := word&(1<<24) == 0
	write := word&(1<<21) != 0
	writeback := postIndex || write
	if first%2 != 0 || first >= 14 || postIndex && write {
		return armRawPairMemory{}, true, fmt.Errorf("invalid ARM LDRD/STRD pair or address mode in %#08x", word)
	}
	if writeback && (base == 15 || base == first || base == first+1) {
		return armRawPairMemory{}, true, fmt.Errorf("invalid ARM LDRD/STRD writeback base in %#08x", word)
	}
	var offset Operand
	if word&(1<<22) != 0 {
		offset = Operand{Kind: OpImm, Imm: int64((word>>4)&0xf0 | word&0xf)}
	} else {
		index := int(word & 15)
		if word&0xf00 != 0 || index == 15 || load && (index == first || index == first+1) {
			return armRawPairMemory{}, true, fmt.Errorf("invalid ARM LDRD/STRD register offset in %#08x", word)
		}
		offset = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("R%d", index))}
	}
	address := armIntegerMemoryForm{
		base:      Reg(fmt.Sprintf("R%d", base)),
		offset:    offset,
		load:      load,
		postIndex: postIndex,
		writeback: writeback,
		subtract:  word&(1<<23) == 0,
	}
	return armRawPairMemory{address: address, first: first, base: base, condition: condition}, true, nil
}

func (c *armCtx) lowerARMRawPairMemory(form armRawPairMemory) error {
	return c.emitConditionalEffect(form.condition, func() error {
		address, updated, err := c.integerMemoryAddress(form.address)
		if err != nil {
			return err
		}
		first := Reg(fmt.Sprintf("R%d", form.first))
		second := Reg(fmt.Sprintf("R%d", form.first+1))
		// Use a hardware register pair so the backend preserves the original
		// doubleword access and its architectural alignment and fault behavior.
		if form.address.load {
			pair := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call { i32, i32 } asm sideeffect \"ldrd $0, $1, [$2]\", "+
				"\"=&{r0},=&{r1},r,~{memory}\"(i32 %s)\n", pair, address)
			for index, reg := range []Reg{first, second} {
				part := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32 } %%%s, %d\n", part, pair, index)
				if err := c.storeReg(reg, "%"+part); err != nil {
					return err
				}
			}
		} else {
			low, err := c.loadReg(first)
			if err != nil {
				return err
			}
			high, err := c.loadReg(second)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect \"strd $1, $2, [$0]\", \"r,{r0},{r1},~{memory}\"(i32 %s, i32 %s, i32 %s)\n",
				address, low, high)
		}
		if form.address.writeback {
			return c.storeReg(form.address.base, updated)
		}
		return nil
	})
}
