package plan9asm

type x86PackedLowMultiplyForm = x86PackedArithmeticForm

func x86PackedLowMultiplyProperties(op Op, ins Instr, arch string) (x86PackedLowMultiplyForm, bool, error) {
	return x86PackedArithmeticProperties(op, ins, arch, x86PackedArithmeticLowMultiply)
}
