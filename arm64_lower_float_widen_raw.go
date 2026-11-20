package plan9asm

import "fmt"

type arm64RawVectorFloatWiden struct {
	sourceBits  int
	upper       bool
	source      int
	destination int
}

func decodeARM64RawVectorFloatWiden(word uint32) (arm64RawVectorFloatWiden, bool) {
	if word&0xbfbffc00 != 0x0e217800 {
		return arm64RawVectorFloatWiden{}, false
	}
	sourceBits := 16
	if word&(1<<22) != 0 {
		sourceBits = 32
	}
	return arm64RawVectorFloatWiden{
		sourceBits:  sourceBits,
		upper:       word&(1<<30) != 0,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawVectorFloatWiden(form arm64RawVectorFloatWiden) error {
	return c.lowerARM64VectorFloatWidenForm(form.sourceBits, form.upper,
		Reg(fmt.Sprintf("V%d", form.source)), Reg(fmt.Sprintf("V%d", form.destination)))
}
