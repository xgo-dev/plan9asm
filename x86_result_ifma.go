package plan9asm

func x86RawIFMASource(ins Instr, arch string) bool {
	_, known, err := x86IFMAProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}
