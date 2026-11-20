package plan9asm

import (
	"fmt"
	"strings"
)

type amd64MaskBroadcastSpec struct {
	sourceBits int
	laneBits   int
}

// amd64MaskBroadcastSpecs is the complete Go 1.27 _yvpbroadcastmb2q grammar.
// The low byte/word of a K register is zero-extended and broadcast into every
// qword/dword lane of an EVEX X, Y, or Z destination.
var amd64MaskBroadcastSpecs = map[Op]amd64MaskBroadcastSpec{
	"VPBROADCASTMB2Q": {sourceBits: 8, laneBits: 64},
	"VPBROADCASTMW2D": {sourceBits: 16, laneBits: 32},
}

func (c *amd64Ctx) lowerMaskRegisterBroadcast(op Op, ins Instr) (ok bool, terminated bool, err error) {
	f, known, err := x86BroadcastProperties(op, ins, c.goarch)
	if !known || f.kind != x86BroadcastMask {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	spec := amd64MaskBroadcastSpecs[Op(strings.ToUpper(string(op)))]
	byteWidth := f.byteWidth
	mask, err := c.loadK(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, mask, spec.sourceBits)
	scalar := "%" + narrow
	if spec.sourceBits != spec.laneBits {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i%d\n", wide, spec.sourceBits, scalar, spec.laneBits)
		scalar = "%" + wide
	}
	lanes := byteWidth * 8 / spec.laneBits
	result := amd64SplatInteger(c, lanes, spec.laneBits, scalar)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(ins.Args[1], byteWidth, "%"+out)
}
