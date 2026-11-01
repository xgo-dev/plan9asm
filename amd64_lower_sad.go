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

// One ordered grammar governs both lowering and original-source effects.
func (c *amd64Ctx) lowerPackedSumAbsoluteDifferences(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64PackedSADSpecs[Op(base)]; !known {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("packed SAD dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, _, err := x86PackedSADProperties(ins, c.goarch)
	if err != nil {
		return true, false, err
	}
	first, second, destination := ins.Args[form.first], ins.Args[form.second], ins.Args[form.destination]
	if form.constantZero(ins) {
		if form.legacy {
			return true, false, c.storeLegacyPackedLogical(destination, "zeroinitializer")
		}
		return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "zeroinitializer")
	}
	if form.legacy && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: %s m128 needs original native storage, not virtual FP/SP/BP", ErrProbeNeedsContext, ins.Op)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	b, err := c.loadPackedCompareBytes(second, form.byteWidth)
	if err != nil {
		return true, false, err
	}
	var result string
	if form.legacy && form.memory >= 0 {
		// Keep the precise legacy opcode/read/fault behavior. A separately
		// synthesized align-1 or MOVDQA load is not an equivalent contract.
		result, err = c.emitPackedSADNativeMemory(first, b, form)
	} else {
		a, loadErr := c.loadPackedUnpackSource(first, x86PackedUnpackForm{
			x86PackedBinaryForm: form.x86PackedBinaryForm, spec: x86PackedUnpackSpec{laneBits: 8},
		})
		if loadErr != nil {
			return true, false, loadErr
		}
		switch form.spec.kind {
		case amd64PackedSADBlockSum:
			result = c.emitPackedSumAbsoluteByteDifferences(form.byteWidth, a, b)
		case amd64PackedSADMultiple:
			result = c.emitMultipleSumAbsoluteDifferences(form.byteWidth, a, b, form.immediate)
		case amd64PackedSADDoubleBlock:
			words := c.emitDoubleBlockSumAbsoluteDifferences(form.byteWidth, b, a, form.immediate)
			if form.mask >= 0 {
				mask, loadErr := c.loadK(ins.Args[form.mask].Reg)
				if loadErr != nil {
					return true, false, loadErr
				}
				old := "zeroinitializer"
				if !form.zeroing {
					old, loadErr = c.loadPackedCompareLanes(destination, form.byteWidth, 16, false)
					if loadErr != nil {
						return true, false, loadErr
					}
				}
				words = amd64ApplyIntegerLaneMask(c, form.byteWidth/2, 16, words, old, mask, form.zeroing)
			}
			bytes := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x i8>\n", bytes, form.byteWidth/2, words, form.byteWidth)
			result = "%" + bytes
		}
	}
	if err != nil {
		return true, false, err
	}
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, result)
	}
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, result)
}

func (c *amd64Ctx) emitPackedSADNativeMemory(source Operand, data string, form x86PackedSADForm) (string, error) {
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	segment := ""
	switch pointerType {
	case "ptr addrspace(256)":
		segment = "%gs:"
	case "ptr addrspace(257)":
		segment = "%fs:"
	}
	opcode := "psadbw "
	if form.spec.kind == amd64PackedSADMultiple {
		opcode = fmt.Sprintf("mpsadbw $$%d, ", form.immediate)
	}
	carrier, value, bytes := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", carrier, data)
	fmt.Fprintf(c.b, "  %%%s = call <4 x i32> asm sideeffect %q, %q(<4 x i32> %%%s, %s %s)\n",
		value, opcode+segment+"($2), $0", "=x,0,r,~{memory}", carrier, pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bytes, value)
	return "%" + bytes, nil
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
