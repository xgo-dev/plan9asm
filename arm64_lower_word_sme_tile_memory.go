package plan9asm

import "fmt"

type arm64RawSMETileMemory struct {
	bits      int
	tile      int
	index     int
	row       int
	predicate int
	base      int
	offset    int
	vertical  bool
	store     bool
}

// SME ZA tile LD1/ST1 share one four-width grammar. The low four bits encode
// tile number and slice index together; their split depends on element width.
// Bit 4 is reserved and must not be mistaken for part of the tile field.
func decodeARM64RawSMETileMemory(word uint32) (arm64RawSMETileMemory, bool) {
	const variableFields = uint32(0x00ffffef)
	if word&^variableFields != 0xe0000000 {
		return arm64RawSMETileMemory{}, false
	}
	size := int(word>>22) & 3
	indexBits := 4 - size
	indexAndTile := int(word) & 15
	return arm64RawSMETileMemory{
		bits:      8 << size,
		tile:      indexAndTile >> indexBits,
		index:     indexAndTile & ((1 << indexBits) - 1),
		row:       12 + int(word>>13&3),
		predicate: int(word>>10) & 7,
		base:      int(word>>5) & 31,
		offset:    int(word>>16) & 31,
		vertical:  word&(1<<15) != 0,
		store:     word&(1<<21) != 0,
	}, true
}

func (c *arm64Ctx) lowerRawSMETileMemory(form arm64RawSMETileMemory) error {
	predicate, err := c.loadPReg(form.predicate)
	if err != nil {
		return err
	}
	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	if form.base == 31 {
		baseReg = SP
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return err
	}
	row, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.row)))
	if err != nil {
		return err
	}

	width := map[int]string{8: "b", 16: "h", 32: "w", 64: "d"}[form.bits]
	tileWidth := map[int]string{8: "b", 16: "h", 32: "s", 64: "d"}[form.bits]
	direction := "h"
	if form.vertical {
		direction = "v"
	}
	mnemonic := "ld1" + width
	predicateMode := "/z"
	if form.store {
		mnemonic = "st1" + width
		predicateMode = ""
	}
	assembly := fmt.Sprintf("%s {za%d%s.%s[w12, %d]}, $0%s, [$1]",
		mnemonic, form.tile, direction, tileWidth, form.index, predicateMode)
	if form.offset == 31 {
		assembly = "mov w12, ${2:w}; " + assembly
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(<vscale x 16 x i1> %s, i64 %s, i64 %s)\n",
			assembly, "@3Upl,r,r,~{memory},~{x12}", predicate, base, row)
		return nil
	}

	offset, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.offset)))
	if err != nil {
		return err
	}
	address := "[$1, $2]"
	if form.bits != 8 {
		shift := map[int]int{16: 1, 32: 2, 64: 3}[form.bits]
		address = fmt.Sprintf("[$1, $2, lsl #%d]", shift)
	}
	assembly = fmt.Sprintf("%s {za%d%s.%s[w12, %d]}, $0%s, %s",
		mnemonic, form.tile, direction, tileWidth, form.index, predicateMode, address)
	assembly = "mov w12, ${3:w}; " + assembly
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(<vscale x 16 x i1> %s, i64 %s, i64 %s, i64 %s)\n",
		assembly, "@3Upl,r,r,r,~{memory},~{x12}", predicate, base, offset, row)
	return nil
}
