package plan9asm

import "fmt"

const arm64LiteralLoadOp Op = "ARM64_LITERAL_LOAD"

type arm64LiteralLoadForm struct {
	bits         int
	register     int
	displacement int64
	vector       bool
	signed       bool
}

func decodeARM64RawLiteralLoad(word uint32) (arm64LiteralLoadForm, bool) {
	if word&0x3b000000 != 0x18000000 {
		return arm64LiteralLoadForm{}, false
	}
	opc := word >> 30
	if opc == 3 { // PRFM shares the GP encoding; SIMD reserves this row.
		return arm64LiteralLoadForm{}, false
	}
	form := arm64LiteralLoadForm{
		bits: 32 << opc, register: int(word & 31),
		displacement: int64(int32(word<<8)>>13) * 4,
		vector:       word&(1<<26) != 0,
	}
	if !form.vector && opc == 2 {
		form.bits, form.signed = 32, true // LDRSW reads 32 bits and writes 64.
	}
	return form, true
}

func (form arm64LiteralLoadForm) destination() Reg {
	switch {
	case form.vector && form.bits == 128:
		return Reg(fmt.Sprintf("V%d", form.register))
	case form.vector:
		return Reg(fmt.Sprintf("F%d", form.register))
	case form.register == 31:
		return ZR
	default:
		return Reg(fmt.Sprintf("R%d", form.register))
	}
}

func (form arm64LiteralLoadForm) opcode() string {
	if form.signed {
		return "LDRSW"
	}
	return "LDR"
}

func (c *arm64Ctx) lowerARM64LiteralLoad(ins Instr) error {
	if !ins.arm64Encoded || len(ins.Args) != 3 || ins.Args[0].Kind != OpIdent ||
		ins.Args[1].Kind != OpImm || ins.Args[2].Kind != OpReg {
		return fmt.Errorf("ARM64 literal load needs its proven raw layout: %q", ins.Raw)
	}
	form, known := decodeARM64RawLiteralLoad(uint32(ins.Args[1].Imm))
	if !known || ins.Args[2].Reg != form.destination() {
		return fmt.Errorf("ARM64 literal load lost its encoding: %q", ins.Raw)
	}
	pointer, ok := c.arm64RawDataPointer(ins.Args[0].Ident)
	if !ok {
		return fmt.Errorf("ARM64 literal load lost its data pool: %q", ins.Raw)
	}

	// The original displacement need only be word-aligned. Keep the memory
	// operation at its original width, including a read to WZR/XZR.
	loaded := c.newTmp()
	if form.bits == 128 {
		fmt.Fprintf(c.b, "  %%%s = load volatile <16 x i8>, ptr %s, align 4\n", loaded, pointer)
		return c.storeVReg(ins.Args[2].Reg, "%"+loaded)
	}
	fmt.Fprintf(c.b, "  %%%s = load volatile i%d, ptr %s, align 4\n", loaded, form.bits, pointer)
	value := "%" + loaded
	if form.bits == 32 && ins.Args[2].Reg != ZR {
		extension := "zext"
		if form.signed {
			extension = "sext"
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s to i64\n", wide, extension, value)
		value = "%" + wide
	}
	return c.storeReg(ins.Args[2].Reg, value)
}
