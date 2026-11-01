package plan9asm

type x86FloatAddSubForm = x86FloatArithmeticForm

func x86FloatAddSubProperties(ins Instr, arch string) (x86FloatAddSubForm, bool, error) {
	return x86FloatArithmeticProperties(ins, arch, x86FloatAddSubtract)
}
