package plan9asm

type amd64PackedFloatingDotForm uint8

const (
	// amd64PackedFloatingDotLegacy is Go's yxshuf table: imm8, X/m128, X.
	amd64PackedFloatingDotLegacy amd64PackedFloatingDotForm = iota
	// amd64PackedFloatingDotVEX128 is Go's _yvdppd table: imm8, X/m128,
	// X, X. The Go 386 frontend cannot represent the four operands.
	amd64PackedFloatingDotVEX128
	// amd64PackedFloatingDotVEX128Or256 is Go's _yvblendpd table, adding
	// the corresponding Y/m256, Y, Y row.
	amd64PackedFloatingDotVEX128Or256
)

type amd64PackedFloatingDotSpec struct {
	form     amd64PackedFloatingDotForm
	laneBits int
}

// amd64PackedFloatingDotSpecs is the complete Go 1.27 grammar for the SSE4.1
// and AVX floating dot-product family. The form class captures operand count,
// legal vector widths, and the 386 frontend restriction; laneBits selects the
// hardware intrinsic and immediate-bit interpretation.
var amd64PackedFloatingDotSpecs = map[Op]amd64PackedFloatingDotSpec{
	"DPPD":  {form: amd64PackedFloatingDotLegacy, laneBits: 64},
	"DPPS":  {form: amd64PackedFloatingDotLegacy, laneBits: 32},
	"VDPPD": {form: amd64PackedFloatingDotVEX128, laneBits: 64},
	"VDPPS": {form: amd64PackedFloatingDotVEX128Or256, laneBits: 32},
}

func (c *amd64Ctx) lowerPackedFloatingDot(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerNativePackedReduction(op, ins)
}
