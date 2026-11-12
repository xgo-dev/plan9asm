package plan9asm

func x86RawFP16BinarySourceForm(ins Instr, arch string) (x86FP16BinaryForm, bool) {
	f, known, err := x86FP16BinaryProperties(ins, arch)
	return f, known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86LoweredFP16BinaryStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	f, known, err := x86FP16BinaryProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	return x86ScalarFPFloatBinaryTransferWithRead(ins, f.x86FloatBinaryForm, state, owned, arch, true), true
}
