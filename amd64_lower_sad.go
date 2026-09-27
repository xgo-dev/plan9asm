package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedSADKind uint8

const (
	amd64PackedSADBlockSum amd64PackedSADKind = iota
	amd64PackedSADMultiple
	amd64PackedSADDoubleBlock
)

type amd64PackedSADForm uint8

const (
	amd64PackedSADLegacyX amd64PackedSADForm = iota
	amd64PackedSADVEXXY
	amd64PackedSADEVEXXYZ
)

type amd64PackedSADSpec struct {
	kind amd64PackedSADKind
	form amd64PackedSADForm
}

// amd64PackedSADSpecs is the complete Go 1.27 byte-SAD grammar. PSADBW uses
// fixed eight-byte block sums, MPSADBW uses one immediate-selected four-byte
// block and sliding windows, and VDBPSADBW independently selects four dwords
// before its sliding SAD. Their vector spellings intentionally differ:
// VPSADBW has EVEX X/Y/Z rows, VMPSADBW is VEX X/Y only, and VDBPSADBW adds
// EVEX writemasking to X/Y/Z.
var amd64PackedSADSpecs = map[Op]amd64PackedSADSpec{
	"PSADBW":    {kind: amd64PackedSADBlockSum, form: amd64PackedSADLegacyX},
	"VPSADBW":   {kind: amd64PackedSADBlockSum, form: amd64PackedSADEVEXXYZ},
	"MPSADBW":   {kind: amd64PackedSADMultiple, form: amd64PackedSADLegacyX},
	"VMPSADBW":  {kind: amd64PackedSADMultiple, form: amd64PackedSADVEXXY},
	"VDBPSADBW": {kind: amd64PackedSADDoubleBlock, form: amd64PackedSADEVEXXYZ},
}

// lowerPackedSumAbsoluteDifferences implements Go 1.27's complete byte-SAD
// family. Only VDBPSADBW has masking and a suffix form.
func (c *amd64Ctx) lowerPackedSumAbsoluteDifferences(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64PackedSADSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if spec.kind == amd64PackedSADDoubleBlock {
		return c.lowerDoubleBlockSumAbsoluteDifferences(baseOp, rawOp, ins)
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
	}
	if spec.kind == amd64PackedSADMultiple {
		return c.lowerMultipleSumAbsoluteDifferences(baseOp, spec, ins)
	}
	if spec.form == amd64PackedSADLegacyX {
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !c.isGoLegacyXReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("%s PSADBW expects X/m source and an in-range X destination: %q", c.goarch, ins.Raw)
		}
		if ins.Args[0].Kind == OpReg && !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s PSADBW register source must be an in-range X register: %q", c.goarch, ins.Raw)
		}
		if ins.Args[0].Kind == OpMem && !x86MemoryRegistersValidForArch(ins.Args[0].Mem, c.goarch) {
			return true, false, fmt.Errorf("%s PSADBW source uses an out-of-range address register: %q", c.goarch, ins.Raw)
		}
		first, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		second, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedSumAbsoluteByteDifferences(16, first, second)
		return true, false, c.storeX(ins.Args[1].Reg, result)
	}

	if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 VPSADBW expects src1, src2, destination: %q", ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(ins.Args[2].Reg)
	if byteWidth == 0 {
		return true, false, fmt.Errorf("amd64 VPSADBW destination must be X, Y, or Z: %q", ins.Raw)
	}
	if !amd64VectorRegisterHasWidth(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("amd64 VPSADBW second source must match its destination width: %q", ins.Raw)
	}
	if ins.Args[0].Kind == OpReg && !amd64VectorRegisterHasWidth(ins.Args[0], byteWidth) {
		return true, false, fmt.Errorf("amd64 VPSADBW first source must match its destination width: %q", ins.Raw)
	}
	first, err := c.loadPackedCompareBytes(ins.Args[0], byteWidth)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedSumAbsoluteByteDifferences(byteWidth, first, second)
	return true, false, c.storeVectorBytes(ins.Args[2].Reg, byteWidth, result)
}

// lowerDoubleBlockSumAbsoluteDifferences implements the EVEX VDBPSADBW table.
// Go's Plan 9 order is imm8, SRC2, SRC1, [K,] destination. The shared x86
// encoder table exists on 386, but cmd/asm cannot represent its four- and
// five-operand forms there.
func (c *amd64Ctx) lowerDoubleBlockSumAbsoluteDifferences(baseOp, rawOp string, ins Instr) (bool, bool, error) {
	zeroing := rawOp == baseOp+".Z"
	if rawOp != baseOp && !zeroing {
		return true, false, fmt.Errorf("amd64 %s accepts only the optional .Z suffix: %q", baseOp, ins.Raw)
	}
	if c.goarch == "386" && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s is outside Go 1.27's accepted instruction forms: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 5
	if len(ins.Args) != 4 && !masked || !amd64UnsignedImmediate(ins.Args[0], 8) {
		return true, false, fmt.Errorf("amd64 %s expects $imm8, X|Y|Z/mem, X|Y|Z, [K,] X|Y|Z: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s.Z requires K1-K7: %q", baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if destination.Kind != OpReg || byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's X/Y/Z register classes: %q", baseOp, ins.Raw)
	}
	source2, source1 := ins.Args[1], ins.Args[2]
	if source2.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source2, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s SRC2 register must match its destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source2) {
		return true, false, fmt.Errorf("amd64 %s SRC2 must be a matching vector register or memory: %q", baseOp, ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(source1, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s SRC1 must match its destination width: %q", baseOp, ins.Raw)
	}
	maskValue := ""
	if masked {
		mask := ins.Args[3]
		if !amd64NonzeroKOperand(mask) {
			return true, false, fmt.Errorf("amd64 %s masked form requires K1-K7: %q", baseOp, ins.Raw)
		}
		loaded, err := c.loadK(mask.Reg)
		if err != nil {
			return true, false, err
		}
		maskValue = loaded
	}
	source2Bytes, err := c.loadPackedCompareBytes(source2, byteWidth)
	if err != nil {
		return true, false, err
	}
	source1Bytes, err := c.loadPackedCompareBytes(source1, byteWidth)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth / 2
	result := c.emitDoubleBlockSumAbsoluteDifferences(byteWidth, source1Bytes, source2Bytes, uint8(ins.Args[0].Imm))
	if masked {
		oldBytes, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, 16, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, 16, result, old, maskValue, zeroing)
	}
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x i8>\n", bytesValue, lanes, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+bytesValue)
}

func (c *amd64Ctx) emitDoubleBlockSumAbsoluteDifferences(byteWidth int, source1, source2 string, immediate uint8) string {
	shuffled := "poison"
	for laneBase := 0; laneBase < byteWidth; laneBase += 16 {
		for destinationDWord := 0; destinationDWord < 4; destinationDWord++ {
			sourceDWord := int(immediate>>(2*destinationDWord)) & 3
			for byteInDWord := 0; byteInDWord < 4; byteInDWord++ {
				sourceIndex := laneBase + sourceDWord*4 + byteInDWord
				destinationIndex := laneBase + destinationDWord*4 + byteInDWord
				value, inserted := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", value, byteWidth, source2, sourceIndex)
				fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i8> %s, i8 %%%s, i32 %d\n", inserted, byteWidth, shuffled, value, destinationIndex)
				shuffled = "%" + inserted
			}
		}
	}

	lanes := byteWidth / 2
	result := "poison"
	for blockBase := 0; blockBase < byteWidth; blockBase += 8 {
		for outputInBlock := 0; outputInBlock < 4; outputInBlock++ {
			source1Base := blockBase
			if outputInBlock >= 2 {
				source1Base += 4
			}
			tmpBase := blockBase + outputInBlock
			sum := ""
			for byteInDWord := 0; byteInDWord < 4; byteInDWord++ {
				firstByte, secondByte := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", firstByte, byteWidth, source1, source1Base+byteInDWord)
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", secondByte, byteWidth, shuffled, tmpBase+byteInDWord)
				firstWide, secondWide := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", firstWide, firstByte)
				fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", secondWide, secondByte)
				firstMinusSecond, secondMinusFirst, firstGreater, difference := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = sub i16 %%%s, %%%s\n", firstMinusSecond, firstWide, secondWide)
				fmt.Fprintf(c.b, "  %%%s = sub i16 %%%s, %%%s\n", secondMinusFirst, secondWide, firstWide)
				fmt.Fprintf(c.b, "  %%%s = icmp uge i16 %%%s, %%%s\n", firstGreater, firstWide, secondWide)
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %%%s, i16 %%%s\n", difference, firstGreater, firstMinusSecond, secondMinusFirst)
				if sum == "" {
					sum = "%" + difference
				} else {
					added := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = add i16 %s, %%%s\n", added, sum, difference)
					sum = "%" + added
				}
			}
			outputLane := blockBase/2 + outputInBlock
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i16> %s, i16 %s, i32 %d\n", inserted, lanes, result, sum, outputLane)
			result = "%" + inserted
		}
	}
	return result
}

func (c *amd64Ctx) lowerMultipleSumAbsoluteDifferences(baseOp string, spec amd64PackedSADSpec, ins Instr) (bool, bool, error) {
	if len(ins.Args) == 0 || ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("%s %s expects a Yu8 immediate: %q", c.goarch, baseOp, ins.Raw)
	}
	immediate := uint8(ins.Args[0].Imm)
	if spec.form == amd64PackedSADLegacyX {
		if len(ins.Args) != 3 || !c.isGoVEXVectorRegister(ins.Args[2], 16, false) {
			return true, false, fmt.Errorf("%s %s expects imm8, X/m128, X: %q", c.goarch, baseOp, ins.Raw)
		}
		if !c.isGoVEXVectorRegister(ins.Args[1], 16, true) {
			return true, false, fmt.Errorf("%s %s source must be X/m128: %q", c.goarch, baseOp, ins.Raw)
		}
		if ins.Args[1].Kind == OpMem && !x86MemoryRegistersValidForArch(ins.Args[1].Mem, c.goarch) {
			return true, false, fmt.Errorf("%s %s source uses an out-of-range address register: %q", c.goarch, baseOp, ins.Raw)
		}
		first, err := c.loadPackedCompareBytes(ins.Args[1], 16)
		if err != nil {
			return true, false, err
		}
		second, err := c.loadPackedCompareBytes(ins.Args[2], 16)
		if err != nil {
			return true, false, err
		}
		result := c.emitMultipleSumAbsoluteDifferences(16, first, second, immediate)
		return true, false, c.storeX(ins.Args[2].Reg, result)
	}

	if c.goarch == "386" && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 4 || ins.Args[3].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects imm8, source1, source2, destination: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(ins.Args[3].Reg)
	if byteWidth != 16 && byteWidth != 32 {
		return true, false, fmt.Errorf("amd64 %s destination must be a VEX X or Y register: %q", baseOp, ins.Raw)
	}
	if !c.isGoVEXVectorRegister(ins.Args[3], byteWidth, false) || !c.isGoVEXVectorRegister(ins.Args[2], byteWidth, false) {
		return true, false, fmt.Errorf("amd64 %s second source and destination must be matching VEX registers: %q", baseOp, ins.Raw)
	}
	if !c.isGoVEXVectorRegister(ins.Args[1], byteWidth, true) {
		return true, false, fmt.Errorf("amd64 %s first source must be a matching VEX register or memory: %q", baseOp, ins.Raw)
	}
	first, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedCompareBytes(ins.Args[2], byteWidth)
	if err != nil {
		return true, false, err
	}
	result := c.emitMultipleSumAbsoluteDifferences(byteWidth, first, second, immediate)
	return true, false, c.storeVectorBytes(ins.Args[3].Reg, byteWidth, result)
}

func (c *amd64Ctx) emitMultipleSumAbsoluteDifferences(byteWidth int, first, second string, immediate uint8) string {
	intrinsic := "llvm.x86.sse41.mpsadbw"
	lanes := 8
	if byteWidth == 32 {
		intrinsic = "llvm.x86.avx2.mpsadbw"
		lanes = 16
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <%d x i16> @%s(<%d x i8> %s, <%d x i8> %s, i8 %d)\n", result, lanes, intrinsic, byteWidth, second, byteWidth, first, immediate)
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %%%s to <%d x i8>\n", bytesValue, lanes, result, byteWidth)
	return "%" + bytesValue
}

func (c *amd64Ctx) emitPackedSumAbsoluteByteDifferences(byteWidth int, first, second string) string {
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext <%d x i8> %s to <%d x i16>\n", firstWide, byteWidth, first, byteWidth)
	fmt.Fprintf(c.b, "  %%%s = zext <%d x i8> %s to <%d x i16>\n", secondWide, byteWidth, second, byteWidth)
	firstMinusSecond := c.newTmp()
	secondMinusFirst := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub <%d x i16> %%%s, %%%s\n", firstMinusSecond, byteWidth, firstWide, secondWide)
	fmt.Fprintf(c.b, "  %%%s = sub <%d x i16> %%%s, %%%s\n", secondMinusFirst, byteWidth, secondWide, firstWide)
	firstGreater := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp uge <%d x i16> %%%s, %%%s\n", firstGreater, byteWidth, firstWide, secondWide)
	differences := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i16> %%%s, <%d x i16> %%%s\n", differences, byteWidth, firstGreater, byteWidth, firstMinusSecond, byteWidth, secondMinusFirst)

	groups := byteWidth / 8
	result := "zeroinitializer"
	for group := 0; group < groups; group++ {
		sum := ""
		for lane := group * 8; lane < (group+1)*8; lane++ {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i16> %%%s, i32 %d\n", value, byteWidth, differences, lane)
			if sum == "" {
				sum = "%" + value
				continue
			}
			added := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i16 %s, %%%s\n", added, sum, value)
			sum = "%" + added
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i64\n", wide, sum)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %%%s, i32 %d\n", inserted, groups, result, wide, group)
		result = "%" + inserted
	}
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", bytesValue, groups, result, byteWidth)
	return "%" + bytesValue
}
