package plan9asm

// ARM64FPAccessBytes describes the complete byte width of a wide FP memory
// operand. It lets assembly-only signature inference retain every accessed
// word, rather than just the offset written in source. It is not a Go
// declaration or permission to access padding in a declaration-backed frame.
// Unknown and malformed forms return zero; translation still validates every
// operand and the complete supplied frame layout independently.
func ARM64FPAccessBytes(ins Instr, operand int) int64 {
	if len(ins.Args) != 2 || operand < 0 || operand >= len(ins.Args) ||
		ins.Args[operand].Kind != OpFP {
		return 0
	}
	var width int64
	if spec, ok := arm64IntegerPairSpecs[ins.Op]; ok {
		memoryIndex := 1
		if spec.load {
			memoryIndex = 0
		}
		pair := ins.Args[1-memoryIndex]
		if operand != memoryIndex || pair.Kind != OpRegList || len(pair.RegList) != 2 {
			return 0
		}
		for _, reg := range pair.RegList {
			if !isARM64GeneralOrZeroReg(reg) {
				return 0
			}
		}
		if spec.load && pair.RegList[0] == pair.RegList[1] {
			return 0
		}
		width = int64(spec.elementBytes * 2)
	} else if ins.Op == "FMOVQ" {
		other := ins.Args[1-operand]
		if other.Kind != OpReg {
			return 0
		}
		if _, ok := arm64ParseFReg(other.Reg); !ok {
			return 0
		}
		width = 16
	}
	const maxOffset = int64(1<<63 - 1)
	offset := ins.Args[operand].FPOffset
	if offset < 0 || width == 0 || offset > maxOffset-width {
		return 0
	}
	return width
}
