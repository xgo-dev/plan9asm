package plan9asm

import "fmt"

type arm64RawTableLookup struct {
	extension   bool
	lanes       int
	tableCount  int
	index       int
	firstTable  int
	destination int
}

func decodeARM64RawTableLookup(word uint32) (arm64RawTableLookup, bool) {
	// Advanced SIMD TBL/TBX (vector). Q, len, op and the three register
	// fields are variable; every remaining bit is architecturally fixed.
	if word&0xbfe08c00 != 0x0e000000 {
		return arm64RawTableLookup{}, false
	}
	lanes := 8
	if word&(1<<30) != 0 {
		lanes = 16
	}
	return arm64RawTableLookup{
		extension:   word&(1<<12) != 0,
		lanes:       lanes,
		tableCount:  int(word>>13)&3 + 1,
		index:       int(word>>16) & 31,
		firstTable:  int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawTableLookup(form arm64RawTableLookup) error {
	arrangement := fmt.Sprintf("B%d", form.lanes)
	reg := func(index int) Reg {
		return Reg(fmt.Sprintf("V%d.%s", index, arrangement))
	}
	tables := make([]Reg, form.tableCount)
	for i := range tables {
		// Table operands are always full 128-bit vectors, independently of Q.
		tables[i] = Reg(fmt.Sprintf("V%d.B16", (form.firstTable+i)%32))
	}
	op := Op("VTBL")
	if form.extension {
		op = "VTBX"
	}
	ins := Instr{
		Op:  op,
		Raw: "decoded ARM64 WORD as " + string(op),
		Args: []Operand{
			{Kind: OpReg, Reg: reg(form.index)},
			{Kind: OpRegList, RegList: tables},
			{Kind: OpReg, Reg: reg(form.destination)},
		},
	}
	ok, _, err := c.lowerARM64VectorTableLookup(op, ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", op)
	}
	return err
}
