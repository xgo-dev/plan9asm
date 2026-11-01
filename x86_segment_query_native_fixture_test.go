package plan9asm

// Both the actual Go program and independent GNU opcode reference seed every
// observed status bit. XOR would leave AF undefined before the complete LAHF
// observation. MOV additionally makes the SUB input an explicit source fact;
// no instruction-proof relaxation is needed to recognize a self-subtraction.
func x86SegmentQueryNativeFlagSeed(overflow bool) (goSource, gnuSource string) {
	if overflow {
		return "MOVB $127,DL\nADDB $1,DL\nSTC\n", "movb $127,%%dl; addb $1,%%dl; stc; "
	}
	return "MOVL $0,DX\nSUBL DX,DX\nSTC\n", "movl $0,%%edx; subl %%edx,%%edx; stc; "
}
