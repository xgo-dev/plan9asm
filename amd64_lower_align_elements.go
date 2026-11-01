package plan9asm

import "strings"

// Preserve the original family registry for source-op extraction.
var amd64VectorAlignSpecs = map[Op]int{
	"VALIGND": 32,
	"VALIGNQ": 64,
}

func (c *amd64Ctx) lowerVectorAlign(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64VectorAlignSpecs[Op(base)]; !known {
		return false, false, nil
	}
	return c.lowerPackedAlignFamily(op, ins)
}
