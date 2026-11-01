package plan9asm

import "fmt"

type arm64RawFloatBinary struct {
	op          Op
	arrangement arm64VectorArrangement
	first       int
	second      int
	destination int
}

func decodeARM64RawFloatBinary(word uint32) (arm64RawFloatBinary, bool) {
	const registers = uint32(31 | 31<<5 | 31<<16)
	halfForms := map[uint32]Op{
		0x0e401400: "VFADD", 0x4e401400: "VFADD",
		0x0ec01400: "VFSUB", 0x4ec01400: "VFSUB",
		0x2e401c00: "VFMUL", 0x6e401c00: "VFMUL",
		0x2e403c00: "VFDIV", 0x6e403c00: "VFDIV",
		0x0e403400: "VFMAX", 0x4e403400: "VFMAX",
		0x0ec03400: "VFMIN", 0x4ec03400: "VFMIN",
		0x0e400400: "VFMAXNM", 0x4e400400: "VFMAXNM",
		0x0ec00400: "VFMINNM", 0x4ec00400: "VFMINNM",
		0x2ec01400: "VFABD", 0x6ec01400: "VFABD",
		0x0e401c00: "VFMULX", 0x4e401c00: "VFMULX",
	}
	if op, ok := halfForms[word&^registers]; ok {
		lanes := 4
		if word&(1<<30) != 0 {
			lanes = 8
		}
		return arm64RawFloatBinary{
			op:          op,
			arrangement: arm64VectorArrangement{elementBits: 16, lanes: lanes},
			first:       int(word>>5) & 31,
			second:      int(word>>16) & 31,
			destination: int(word) & 31,
		}, true
	}

	var op Op
	switch word & 0xbfa0fc00 { // Ignore Q, size, Rm, Rn, and Rd.
	case 0x0e20d400:
		op = "VFADD"
	case 0x0ea0d400:
		op = "VFSUB"
	case 0x2e20dc00:
		op = "VFMUL"
	case 0x2e20fc00:
		op = "VFDIV"
	case 0x0e20f400:
		op = "VFMAX"
	case 0x0ea0f400:
		op = "VFMIN"
	case 0x0e20c400:
		op = "VFMAXNM"
	case 0x0ea0c400:
		op = "VFMINNM"
	case 0x2ea0d400:
		op = "VFABD"
	case 0x0e20dc00:
		op = "VFMULX"
	default:
		return arm64RawFloatBinary{}, false
	}

	elementBits := 32
	if word&(1<<22) != 0 {
		elementBits = 64
	}
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	// The 64-bit scalar-sized D1 combination is reserved for this vector class.
	if elementBits == 64 && vectorBits == 64 {
		return arm64RawFloatBinary{}, false
	}

	return arm64RawFloatBinary{
		op:          op,
		arrangement: arm64VectorArrangement{elementBits: elementBits, lanes: vectorBits / elementBits},
		first:       int(word>>5) & 31,
		second:      int(word>>16) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawFloatBinary(form arm64RawFloatBinary) error {
	arrangement := arm64VectorArrangementName(form.arrangement)
	ins := Instr{
		Op:  form.op,
		Raw: fmt.Sprintf("decoded ARM64 WORD as %s", form.op),
		Args: []Operand{
			// Plan 9 vector arithmetic lists Vm, Vn, Vd; the architectural
			// encoding stores Vn in Rn and Vm in Rm.
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.second, arrangement))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.first, arrangement))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.destination, arrangement))},
		},
	}
	ok, _, err := c.lowerARM64VectorFloatArithmeticForm(form.op, ins, true)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", form.op)
	}
	return err
}
