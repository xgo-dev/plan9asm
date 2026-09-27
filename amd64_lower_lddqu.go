package plan9asm

import (
	"fmt"
	"strings"
)

type amd64UnalignedLoadSpec struct {
	maxBytes int
	vector   bool
}

// amd64UnalignedLoadSpecs is the complete Go 1.27 ylddqu/_yvlddqu grammar.
// Both instructions are load-only; legacy LDDQU is X-width, while VLDDQU
// adds the VEX Y-width row.
var amd64UnalignedLoadSpecs = map[Op]amd64UnalignedLoadSpec{
	"LDDQU":  {maxBytes: 16},
	"VLDDQU": {maxBytes: 32, vector: true},
}

func (c *amd64Ctx) lowerUnalignedVectorLoad(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64UnalignedLoadSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed form in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || !isAMD64MemoryOperand(ins.Args[0]) || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects memory, X%s: %q", c.goarch, baseOp, map[bool]string{true: "/Y"}[spec.maxBytes == 32], ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(ins.Args[1].Reg)
	validDestination := c.isGoVEXVectorRegister(ins.Args[1], byteWidth, false)
	if spec.vector {
		validDestination = amd64VEXVectorRegister(ins.Args[1], byteWidth)
	}
	if (byteWidth != 16 && byteWidth != 32) || byteWidth > spec.maxBytes || !validDestination {
		return true, false, fmt.Errorf("%s %s destination width or register is outside its Go 1.27 table: %q", c.goarch, baseOp, ins.Raw)
	}
	if !spec.vector && ins.Args[0].Kind == OpMem && !x86MemoryRegistersValidForArch(ins.Args[0].Mem, c.goarch) {
		return true, false, fmt.Errorf("%s %s source uses an out-of-range address register: %q", c.goarch, baseOp, ins.Raw)
	}
	value, err := c.loadPackedCompareBytes(ins.Args[0], byteWidth)
	if err != nil {
		return true, false, err
	}
	return true, false, c.storeVectorBytes(ins.Args[1].Reg, byteWidth, value)
}
