package plan9asm

type x86PackedSubtractForm struct {
	x86PackedBinaryForm
	laneBits int
	mode     amd64PackedSubtractMode
}

func x86PackedSubtractProperties(ins Instr, arch string) (x86PackedSubtractForm, bool, error) {
	form, known, err := x86PackedArithmeticProperties(ins.Op, ins, arch, x86PackedArithmeticSubtract)
	return x86PackedSubtractForm{form.x86PackedBinaryForm, form.spec.laneBits, form.spec.mode}, known, err
}
