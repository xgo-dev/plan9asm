package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedWordShuffle implements the complete Go 1.27 PSHUFHW/PSHUFLW
// and VPSHUFHW/VPSHUFLW tables. The selected four-word half is shuffled
// independently in every 128-bit lane; the other half remains unchanged.
func (c *amd64Ctx) lowerPackedWordShuffle(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	raw := strings.ToUpper(string(rawOp))
	parts := strings.Split(raw, ".")
	baseOp := Op(parts[0])
	switch baseOp {
	case "PSHUFW", "PSHUFHW", "PSHUFLW", "VPSHUFHW", "VPSHUFLW":
		// handled below
	default:
		return false, false, nil
	}
	if len(parts) > 2 || len(parts) == 2 && parts[1] != "Z" {
		return true, false, fmt.Errorf("amd64 %s has a suffix outside Go 1.27's word-shuffle tables: %q", baseOp, ins.Raw)
	}
	zeroing := len(parts) == 2
	high := baseOp == "PSHUFHW" || baseOp == "VPSHUFHW"
	if baseOp == "PSHUFW" {
		if zeroing {
			return true, false, fmt.Errorf("%s PSHUFW does not accept instruction suffixes: %q", c.goarch, ins.Raw)
		}
		if len(ins.Args) != 3 || !amd64SignedImmediate(ins.Args[0], 8) {
			return true, false, fmt.Errorf("%s PSHUFW expects $signed-imm8, M/m64, M: %q", c.goarch, ins.Raw)
		}
		source, destination := ins.Args[1], ins.Args[2]
		if destination.Kind != OpReg {
			return true, false, fmt.Errorf("%s PSHUFW destination must be M0..M7: %q", c.goarch, ins.Raw)
		}
		if _, ok := amd64ParseMReg(destination.Reg); !ok {
			return true, false, fmt.Errorf("%s PSHUFW destination must be M0..M7: %q", c.goarch, ins.Raw)
		}
		if source.Kind == OpReg {
			if _, ok := amd64ParseMReg(source.Reg); !ok {
				return true, false, fmt.Errorf("%s PSHUFW source must be M0..M7 or memory: %q", c.goarch, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("%s PSHUFW source must be M0..M7 or memory: %q", c.goarch, ins.Raw)
		}
		if source.Kind == OpMem && !x86MemoryRegistersValidForArch(source.Mem, c.goarch) {
			return true, false, fmt.Errorf("%s PSHUFW source address uses an out-of-range register: %q", c.goarch, ins.Raw)
		}
		value, err := c.evalIntSized(source, I64)
		if err != nil {
			return true, false, err
		}
		result := c.emitMMXWordShuffle(value, uint8(ins.Args[0].Imm))
		return true, false, c.storeReg(destination.Reg, result)
	}

	if baseOp == "PSHUFHW" || baseOp == "PSHUFLW" {
		if zeroing {
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
		}
		if len(ins.Args) != 3 || !amd64UnsignedImmediate(ins.Args[0], 8) {
			return true, false, fmt.Errorf("amd64 %s expects $unsigned-imm8, X/m128, X: %q", baseOp, ins.Raw)
		}
		source, destination := ins.Args[1], ins.Args[2]
		if !c.isGoVEXVectorRegister(source, 16, true) || !c.isGoVEXVectorRegister(destination, 16, false) {
			return true, false, fmt.Errorf("amd64 %s operands are outside Go 1.27's X/m128, X classes: %q", baseOp, ins.Raw)
		}
		value, err := c.loadPackedCompareBytes(source, 16)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedWordShuffle(16, value, uint8(ins.Args[0].Imm), high)
		return true, false, c.storeX(destination.Reg, result)
	}

	masked := len(ins.Args) == 4
	if len(ins.Args) != 3 && !masked || !amd64VectorByteShiftImmediate(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s expects $imm8, X|Y|Z/mem, [K,] X|Y|Z: %q", baseOp, ins.Raw)
	}
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed Go 1.27's assembler operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s.Z requires a writemask: %q", baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if destination.Kind != OpReg || byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's X/Y/Z classes: %q", baseOp, ins.Raw)
	}
	source := ins.Args[1]
	if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s source must match its destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("amd64 %s source must be a vector register or memory: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Imm < 0 && amd64PackedWordShuffleRequiresEVEX(source, destination, byteWidth, masked) {
		return true, false, fmt.Errorf("amd64 %s EVEX form requires an unsigned imm8: %q", baseOp, ins.Raw)
	}

	maskValue := ""
	if masked {
		mask := ins.Args[2]
		maskIndex, validMask := amd64ParseKReg(mask.Reg)
		if mask.Kind != OpReg || !validMask || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form requires K1..K7: %q", baseOp, ins.Raw)
		}
		maskValue, err = c.loadK(mask.Reg)
		if err != nil {
			return true, false, err
		}
	}
	value, err := c.loadPackedCompareBytes(source, byteWidth)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedWordShuffle(byteWidth, value, uint8(ins.Args[0].Imm), high)
	if masked {
		old, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		words := byteWidth / 2
		computedWords := c.newTmp()
		oldWords := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i16>\n", computedWords, byteWidth, result, words)
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i16>\n", oldWords, byteWidth, old, words)
		maskedWords := amd64ApplyIntegerLaneMask(c, words, 16, "%"+computedWords, "%"+oldWords, maskValue, zeroing)
		maskedBytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x i8>\n", maskedBytes, words, maskedWords, byteWidth)
		result = "%" + maskedBytes
	}
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, result)
}

func (c *amd64Ctx) emitMMXWordShuffle(source string, immediate uint8) string {
	sourceWords := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <4 x i16>\n", sourceWords, source)
	result := "zeroinitializer"
	for destinationWord := 0; destinationWord < 4; destinationWord++ {
		sourceWord := int(immediate >> (2 * destinationWord) & 3)
		extracted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i16> %%%s, i32 %d\n", extracted, sourceWords, sourceWord)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i16> %s, i16 %%%s, i32 %d\n", inserted, result, extracted, destinationWord)
		result = "%" + inserted
	}
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i16> %s to i64\n", bits, result)
	return "%" + bits
}

func amd64PackedWordShuffleRequiresEVEX(source, destination Operand, byteWidth int, masked bool) bool {
	if byteWidth == 64 || masked {
		return true
	}
	for _, operand := range []Operand{source, destination} {
		if operand.Kind != OpReg {
			continue
		}
		index, ok := amd64VectorRegisterIndex(operand.Reg, byteWidth)
		if !ok || index >= 16 {
			return true
		}
	}
	return false
}

func (c *amd64Ctx) emitPackedWordShuffle(byteWidth int, source string, immediate uint8, high bool) string {
	words := byteWidth / 2
	sourceWords := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i16>\n", sourceWords, byteWidth, source, words)
	result := "zeroinitializer"
	for destinationWord := 0; destinationWord < words; destinationWord++ {
		laneWord := destinationWord % 8
		sourceWord := destinationWord
		shuffle := laneWord < 4 && !high || laneWord >= 4 && high
		if shuffle {
			selector := laneWord
			halfBase := destinationWord - laneWord
			if high {
				selector -= 4
				halfBase += 4
			}
			sourceWord = halfBase + int(immediate>>(2*selector)&3)
		}
		extracted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i16> %%%s, i32 %d\n", extracted, words, sourceWords, sourceWord)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i16> %s, i16 %%%s, i32 %d\n", inserted, words, result, extracted, destinationWord)
		result = "%" + inserted
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x i8>\n", bytes, words, result, byteWidth)
	return "%" + bytes
}
