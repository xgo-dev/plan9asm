package plan9asm

import (
	"fmt"
	"strings"
)

func decodeARM64RawZAZero(word uint32) (uint8, bool) {
	if word&^uint32(0xff) != 0xc0080000 {
		return 0, false
	}
	return uint8(word), true
}

func (c *arm64Ctx) lowerRawZAZero(mask uint8) error {
	tiles := make([]string, 0, 8)
	for tile := 0; tile < 8; tile++ {
		if mask&(1<<tile) != 0 {
			tiles = append(tiles, fmt.Sprintf("za%d.d", tile))
		}
	}
	mnemonic := "zero {" + strings.Join(tiles, ", ") + "}"
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", mnemonic, "~{memory}")
	return nil
}
