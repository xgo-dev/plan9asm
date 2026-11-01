package plan9asm

import "fmt"

// Both Go packed multiply-add families share the same ordered operand,
// memory and write-generation contract.
func (c *amd64Ctx) lowerPackedWordMultiplyAdd(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedPhysical(op, ins, x86PackedMultiplyAdd)
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
