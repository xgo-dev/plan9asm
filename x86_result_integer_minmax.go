package plan9asm

func x86RawIntegerMinMaxSource(ins Instr, arch string) bool {
	form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && ins.x86Encoded && x86RawOrdinaryVectorSource(ins, arch)
}

// A decoder-local constant keeps its existing exact DATA/return consumer.
// This shape supplies no missing input, standalone or native-address role.
func x86RawIntegerMinMaxLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && form.memory == form.first &&
		ins.x86RIPMemoryRead.source == form.first && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}
