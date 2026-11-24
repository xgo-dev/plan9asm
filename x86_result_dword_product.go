package plan9asm

func x86RawDwordProductResultSource(ins Instr, arch string) bool {
	form, known, err := x86DwordProductProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && x86RawOrdinaryVectorSource(ins, arch)
}
