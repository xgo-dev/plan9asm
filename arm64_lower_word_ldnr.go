package plan9asm

import "fmt"

type arm64RawLDnR struct {
	count         int
	post          bool
	postRegister  int
	base          int
	firstRegister int
	arrangement   arm64VectorArrangement
}

func decodeARM64RawLDnR(word uint32) (arm64RawLDnR, bool) {
	// Advanced SIMD load single structure and replicate to all lanes. Q, the
	// structure count bits, post-index bit/register, element size, base, and
	// first destination register are all variable.
	if word&0xbf40d000 != 0x0d40c000 {
		return arm64RawLDnR{}, false
	}
	post := word&(1<<23) != 0
	postRegister := int(word>>16) & 31
	if !post && postRegister != 0 {
		return arm64RawLDnR{}, false
	}
	count := 1 + (int(word>>21) & 1) + 2*(int(word>>13)&1)
	elementBits := 8 << (int(word>>10) & 3)
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	return arm64RawLDnR{
		count:         count,
		post:          post,
		postRegister:  postRegister,
		base:          int(word>>5) & 31,
		firstRegister: int(word & 31),
		arrangement:   arm64VectorArrangement{elementBits: elementBits, lanes: vectorBits / elementBits},
	}, true
}

func (c *arm64Ctx) lowerRawLDnR(form arm64RawLDnR) error {
	op := Op(fmt.Sprintf("VLD%dR", form.count))
	rawOp := op
	if form.post {
		rawOp += ".P"
	}
	base := Reg(fmt.Sprintf("R%d", form.base))
	if form.base == 31 {
		base = SP
	}
	memory := MemRef{Base: base}
	if form.post {
		if form.postRegister == 31 {
			memory.Off = int64(form.count * form.arrangement.elementBits / 8)
		} else {
			memory.Index = Reg(fmt.Sprintf("R%d", form.postRegister))
		}
	}
	arrangement := arm64VectorArrangementName(form.arrangement)
	registers := make([]Reg, form.count)
	for i := range registers {
		registers[i] = Reg(fmt.Sprintf("V%d.%s", (form.firstRegister+i)%32, arrangement))
	}
	ins := Instr{
		Op:  rawOp,
		Raw: fmt.Sprintf("decoded ARM64 WORD as %s", rawOp),
		Args: []Operand{
			{Kind: OpMem, Mem: memory},
			{Kind: OpRegList, RegList: registers},
		},
	}
	ok, _, err := c.lowerARM64StructureLoadStore(op, form.post, ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", rawOp)
	}
	return err
}
