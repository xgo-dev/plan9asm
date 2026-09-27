package plan9asm

import "fmt"

type arm64RawSVELoadStore struct {
	load      bool
	predicate bool
	immediate int
	base      int
	vector    int
}

// decodeARM64RawSVELoadStore covers the complete unpredicated SVE LDR/STR
// scalar-base formats for Z and P registers. The signed imm9 is measured in
// vector bytes for Z registers and predicate bytes (VL/8) for P registers.
func decodeARM64RawSVELoadStore(word uint32) (arm64RawSVELoadStore, bool) {
	form := arm64RawSVELoadStore{}
	switch word & 0xffc0e000 {
	case 0x85804000:
		form.load = true
	case 0xe5804000:
		form.load = false
	case 0x85800000, 0xe5800000:
		if word&16 != 0 { // Pt is four bits, unlike Zt.
			return arm64RawSVELoadStore{}, false
		}
		form.predicate = true
		form.load = word&(1<<30) == 0
	default:
		return arm64RawSVELoadStore{}, false
	}
	imm9 := int(word>>16&0x3f)<<3 | int(word>>10&7)
	if imm9&0x100 != 0 {
		imm9 -= 0x200
	}
	form.immediate = imm9
	form.base = int(word>>5) & 31
	form.vector = int(word) & 31
	return form, true
}

func (c *arm64Ctx) lowerRawSVELoadStore(form arm64RawSVELoadStore) error {
	baseReg := Reg(fmt.Sprintf("R%d", form.base))
	if form.base == 31 {
		baseReg = Reg("RSP")
	}
	prefix, operation := "Z", "STR"
	if form.predicate {
		prefix = "P"
	}
	if form.load {
		operation = "LDR"
	}
	register := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, form.vector))}
	displacement := fmt.Sprintf("VL*%d", form.immediate)
	if form.immediate < 0 {
		displacement = fmt.Sprintf("-VL*%d", -form.immediate)
	}
	memory := Operand{Kind: OpMem, Mem: MemRef{Base: baseReg, OffRaw: displacement}}
	args := []Operand{register, memory}
	if form.load {
		args = []Operand{memory, register}
	}
	ins := Instr{Op: Op(prefix + operation), Args: args}
	if form.predicate {
		_, _, err := c.lowerARM64SVEPredicateLoadStore(ins.Op, ins)
		return err
	}
	_, _, err := c.lowerARM64SVEWholeVectorMemory(ins.Op, ins)
	return err
}
