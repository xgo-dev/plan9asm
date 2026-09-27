package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedCarrylessMultiply implements Go 1.27's complete legacy and
// vector PCLMULQDQ tables. VPCLMULQDQ applies one independent 64x64->128
// carryless multiplication to every 128-bit lane.
func (c *amd64Ctx) lowerPackedCarrylessMultiply(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	raw := strings.ToUpper(string(rawOp))
	if strings.Contains(raw, ".") {
		base := strings.SplitN(raw, ".", 2)[0]
		if base == "PCLMULQDQ" || base == "VPCLMULQDQ" {
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", base, ins.Raw)
		}
		return false, false, nil
	}
	op := Op(raw)
	if op != "PCLMULQDQ" && op != "VPCLMULQDQ" {
		return false, false, nil
	}

	if op == "PCLMULQDQ" {
		if len(ins.Args) != 3 || !amd64UnsignedImmediate(ins.Args[0], 8) {
			return true, false, fmt.Errorf("amd64 PCLMULQDQ expects $imm8, X/m128, X: %q", ins.Raw)
		}
		source, destination := ins.Args[1], ins.Args[2]
		if !c.isGoVEXVectorRegister(destination, 16, false) {
			return true, false, fmt.Errorf("amd64 PCLMULQDQ destination is outside Go 1.27's X register class: %q", ins.Raw)
		}
		if !c.isGoVEXVectorRegister(source, 16, true) {
			return true, false, fmt.Errorf("amd64 PCLMULQDQ source is outside Go 1.27's X/m128 class: %q", ins.Raw)
		}
		second, err := c.loadPackedCompareBytes(source, 16)
		if err != nil {
			return true, false, err
		}
		first, err := c.loadX(destination.Reg)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedCarrylessMultiply(16, first, second, uint8(ins.Args[0].Imm))
		return true, false, c.storeX(destination.Reg, result)
	}

	// Go's 386 assembly parser rejects every four-operand VPCLMULQDQ form.
	if c.goarch == "386" {
		return true, false, fmt.Errorf("386 VPCLMULQDQ is outside Go 1.27's accepted instruction forms: %q", ins.Raw)
	}
	if len(ins.Args) != 4 || !amd64UnsignedImmediate(ins.Args[0], 8) {
		return true, false, fmt.Errorf("amd64 VPCLMULQDQ expects $imm8, X|Y|Z/mem, X|Y|Z, X|Y|Z: %q", ins.Raw)
	}
	destination := ins.Args[3]
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if destination.Kind != OpReg || byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 VPCLMULQDQ destination is outside Go 1.27's X/Y/Z register classes: %q", ins.Raw)
	}
	rmSource, vSource := ins.Args[1], ins.Args[2]
	if rmSource.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(rmSource, byteWidth) {
			return true, false, fmt.Errorf("amd64 VPCLMULQDQ first source must match its destination width: %q", ins.Raw)
		}
	} else if !isAMD64MemoryOperand(rmSource) {
		return true, false, fmt.Errorf("amd64 VPCLMULQDQ first source must be a vector register or memory: %q", ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(vSource, byteWidth) {
		return true, false, fmt.Errorf("amd64 VPCLMULQDQ second source must match its destination width: %q", ins.Raw)
	}
	second, err := c.loadPackedCompareBytes(rmSource, byteWidth)
	if err != nil {
		return true, false, err
	}
	first, err := c.loadPackedCompareBytes(vSource, byteWidth)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedCarrylessMultiply(byteWidth, first, second, uint8(ins.Args[0].Imm))
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, result)
}

func (c *amd64Ctx) emitPackedCarrylessMultiply(byteWidth int, firstBytes, secondBytes string, immediate uint8) string {
	qwords := byteWidth / 8
	first := c.newTmp()
	second := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", first, byteWidth, firstBytes, qwords)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", second, byteWidth, secondBytes, qwords)
	result := "zeroinitializer"
	for lane := 0; lane < byteWidth/16; lane++ {
		firstLane := c.newTmp()
		secondLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i64> %%%s, <%d x i64> poison, <2 x i32> <i32 %d, i32 %d>\n", firstLane, qwords, first, qwords, lane*2, lane*2+1)
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i64> %%%s, <%d x i64> poison, <2 x i32> <i32 %d, i32 %d>\n", secondLane, qwords, second, qwords, lane*2, lane*2+1)
		product := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> %%%s, <2 x i64> %%%s, i8 %d)\n", product, firstLane, secondLane, immediate)
		for word := 0; word < 2; word++ {
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 %d\n", extracted, product, word)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %%%s, i32 %d\n", inserted, qwords, result, extracted, lane*2+word)
			result = "%" + inserted
		}
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", bytes, qwords, result, byteWidth)
	return "%" + bytes
}
