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
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64MaskBroadcastSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed form in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects K source and X/Y/Z destination: %q", c.goarch, baseOp, ins.Raw)
	}
	if _, validMask := amd64ParseKReg(ins.Args[0].Reg); !validMask {
		return true, false, fmt.Errorf("%s %s source must be K0-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(ins.Args[1].Reg)
	if (byteWidth != 16 && byteWidth != 32 && byteWidth != 64) || !c.isGoPackedVectorMoveRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go's EVEX X/Y/Z class: %q", c.goarch, baseOp, ins.Raw)
	}
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
	return true, false, c.storeVectorBytes(ins.Args[1].Reg, byteWidth, "%"+out)
}
