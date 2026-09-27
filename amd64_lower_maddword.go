package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedWordMultiplyAdd implements both complete packed multiply-add
// families in Go 1.27: PMADDWL/VPMADDWD and PMADDUBSW/VPMADDUBSW.
func (c *amd64Ctx) lowerPackedWordMultiplyAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	switch baseOp {
	case "PMADDWL":
		return c.lowerLegacyPackedWordMultiplyAdd(suffix, ins)
	case "PMADDUBSW":
		return c.lowerLegacyPackedUnsignedSignedByteMultiplyAdd(suffix, ins)
	case "VPMADDWD":
		return c.lowerVectorPackedMultiplyAdd(baseOp, suffix, ins, false)
	case "VPMADDUBSW":
		return c.lowerVectorPackedMultiplyAdd(baseOp, suffix, ins, true)
	default:
		return false, false, nil
	}
}

func (c *amd64Ctx) lowerLegacyPackedUnsignedSignedByteMultiplyAdd(suffix string, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("%s PMADDUBSW does not accept instruction suffixes: %q", c.goarch, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !c.isGoLegacyXReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("%s PMADDUBSW expects X/m128, X: %q", c.goarch, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s PMADDUBSW source is outside Go 1.27's legacy X class: %q", c.goarch, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s PMADDUBSW source must be X or memory: %q", c.goarch, ins.Raw)
	}
	// Intel's first encoded source is the legacy destination and supplies
	// unsigned bytes. Plan 9 lists the signed r/m source first.
	signedBytes, err := c.loadPackedCompareBytes(ins.Args[0], 16)
	if err != nil {
		return true, false, err
	}
	unsignedBytes, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	signed := c.bitcastVectorBytesToIntegerLanes(16, 16, 8, signedBytes)
	unsigned := c.bitcastVectorBytesToIntegerLanes(16, 16, 8, unsignedBytes)
	result := c.emitPackedUnsignedSignedByteMultiplyAdd(16, signed, unsigned)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %s to <16 x i8>\n", out, result)
	return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerLegacyPackedWordMultiplyAdd(suffix string, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("%s PMADDWL does not accept instruction suffixes: %q", c.goarch, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s PMADDWL expects MMX/m64, MMX or X/m128, X: %q", c.goarch, ins.Raw)
	}
	destination := ins.Args[1].Reg
	if _, mmx := amd64ParseMReg(destination); mmx {
		if c.goarch == "386" {
			return true, false, fmt.Errorf("386 PMADDWL MMX form is illegal in 32-bit mode: %q", ins.Raw)
		}
		firstBits, err := c.loadLegacyMMXPackedSource(ins.Args[0])
		if err != nil {
			return true, false, fmt.Errorf("amd64 PMADDWL MMX source: %w", err)
		}
		secondBits, err := c.loadReg(destination)
		if err != nil {
			return true, false, err
		}
		first := c.bitcastI64ToIntegerLanes(4, 16, firstBits)
		second := c.bitcastI64ToIntegerLanes(4, 16, secondBits)
		result := c.emitPackedWordMultiplyAdd(4, first, second)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i32> %s to i64\n", bits, result)
		return true, false, c.storeReg(destination, "%"+bits)
	}

	if !c.isGoLegacyXReg(destination) {
		return true, false, fmt.Errorf("%s PMADDWL destination is outside Go 1.27's legacy X class: %q", c.goarch, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s PMADDWL source is outside Go 1.27's legacy X class: %q", c.goarch, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s PMADDWL source must be X or memory: %q", c.goarch, ins.Raw)
	}
	firstBytes, err := c.loadPackedCompareBytes(ins.Args[0], 16)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(destination)
	if err != nil {
		return true, false, err
	}
	first := c.bitcastVectorBytesToIntegerLanes(16, 8, 16, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, 8, 16, secondBytes)
	result := c.emitPackedWordMultiplyAdd(8, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %s to <16 x i8>\n", out, result)
	return true, false, c.storeX(destination, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedMultiplyAdd(baseOp, suffix string, ins Instr, unsignedSignedBytes bool) (bool, bool, error) {
	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("%s %s has a suffix absent from its Go 1.27 optab: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects src1, src2, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects a vector-register destination: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 {
		return true, false, fmt.Errorf("%s %s expects an X, Y, or Z destination: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoPackedVectorMoveRegister(destination, byteWidth) || !c.isGoPackedVectorMoveRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s second source and destination must be same-width vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match its destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	var mask string
	if masked {
		if !amd64NonzeroKOperand(ins.Args[2]) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		var err error
		mask, err = c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
	}
	firstBytes, err := c.loadPackedCompareBytes(ins.Args[0], byteWidth)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	inputLaneBits := 16
	resultLaneBits := 32
	if unsignedSignedBytes {
		inputLaneBits = 8
		resultLaneBits = 16
	}
	inputLanes := byteWidth * 8 / inputLaneBits
	first := c.bitcastVectorBytesToIntegerLanes(byteWidth, inputLanes, inputLaneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, inputLanes, inputLaneBits, secondBytes)
	var result string
	if unsignedSignedBytes {
		// Plan 9's r/m source (first argument) supplies signed bytes; the
		// encoded V source (second argument) supplies unsigned bytes.
		result = c.emitPackedUnsignedSignedByteMultiplyAdd(inputLanes, first, second)
	} else {
		result = c.emitPackedWordMultiplyAdd(inputLanes, first, second)
	}
	resultLanes := inputLanes / 2
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, resultLanes, resultLaneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, resultLanes, resultLaneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, resultLanes, resultLaneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPackedWordMultiplyAdd(wordLanes int, first, second string) string {
	wordType := fmt.Sprintf("<%d x i16>", wordLanes)
	wideType := fmt.Sprintf("<%d x i32>", wordLanes)
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	products := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", firstWide, wordType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", secondWide, wordType, second, wideType)
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", products, wideType, firstWide, secondWide)
	resultLanes := wordLanes / 2
	result := "zeroinitializer"
	for lane := 0; lane < resultLanes; lane++ {
		low := c.newTmp()
		high := c.newTmp()
		sum := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", low, wideType, products, lane*2)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", high, wideType, products, lane*2+1)
		fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", sum, low, high)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i32> %s, i32 %%%s, i32 %d\n", inserted, resultLanes, result, sum, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitPackedUnsignedSignedByteMultiplyAdd(byteLanes int, signedBytes, unsignedBytes string) string {
	byteType := fmt.Sprintf("<%d x i8>", byteLanes)
	wideType := fmt.Sprintf("<%d x i32>", byteLanes)
	signedWide := c.newTmp()
	unsignedWide := c.newTmp()
	products := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", signedWide, byteType, signedBytes, wideType)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", unsignedWide, byteType, unsignedBytes, wideType)
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", products, wideType, signedWide, unsignedWide)
	resultLanes := byteLanes / 2
	result := "zeroinitializer"
	for lane := 0; lane < resultLanes; lane++ {
		low := c.newTmp()
		high := c.newTmp()
		sum := c.newTmp()
		below := c.newTmp()
		lowerClamped := c.newTmp()
		above := c.newTmp()
		clamped := c.newTmp()
		narrow := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", low, wideType, products, lane*2)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", high, wideType, products, lane*2+1)
		fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", sum, low, high)
		fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, -32768\n", below, sum)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 -32768, i32 %%%s\n", lowerClamped, below, sum)
		fmt.Fprintf(c.b, "  %%%s = icmp sgt i32 %%%s, 32767\n", above, lowerClamped)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 32767, i32 %%%s\n", clamped, above, lowerClamped)
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i16\n", narrow, clamped)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i16> %s, i16 %%%s, i32 %d\n", inserted, resultLanes, result, narrow, lane)
		result = "%" + inserted
	}
	return result
}
