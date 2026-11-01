package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerHorizontalInteger(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	_, recognized := amd64HorizontalIntegerSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("horizontal integer dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, recognized, err := x86HorizontalIntegerProperties(ins, c.goarch)
	if err != nil || !recognized {
		return recognized, false, err
	}
	spec, byteWidth := form.spec, form.byteWidth
	if form.memory >= 0 && ins.Args[form.memory].Kind == OpFP {
		if err := c.validateFPVectorSpan(ins.Args[form.memory].FPOffset, byteWidth); err != nil {
			return true, false, err
		}
	}
	destination := ins.Args[form.destination].Reg
	if form.mmx {
		memoryBytes := 0
		if form.memory >= 0 {
			memoryBytes = byteWidth
		}
		firstBits, err := c.loadPackedUnpackMMXSource(ins.Args[form.first], memoryBytes)
		if err != nil {
			return true, false, err
		}
		secondBits, err := c.loadReg(destination)
		if err != nil {
			return true, false, err
		}
		first := c.bitcastI64ToIntegerLanes(2, 32, firstBits)
		second := c.bitcastI64ToIntegerLanes(2, 32, secondBits)
		result := c.emitHorizontalInteger(spec, 8, first, second)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i32> %s to i64\n", bits, result)
		return true, false, c.storeReg(destination, "%"+bits)
	}
	firstOperand := ins.Args[form.first]
	if !spec.vector && form.memory >= 0 && (firstOperand.Kind == OpFP || ins.x86AddressBits != 0 ||
		firstOperand.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(firstOperand, c.goarch)) {
		return true, false, fmt.Errorf("%w: legacy horizontal m128 needs original native backing/alignment", ErrProbeNeedsContext)
	}
	second, err := c.loadHorizontalIntegerOperand(ins.Args[form.second], byteWidth, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	var result string
	if !spec.vector && form.memory >= 0 {
		result, err = c.emitPackedBinaryNativeMemory(firstOperand, spec.laneBits, second, strings.ToLower(baseOp))
	} else {
		var first string
		first, err = c.loadHorizontalIntegerOperand(firstOperand, byteWidth, spec.laneBits)
		if err == nil {
			result = c.emitHorizontalInteger(spec, byteWidth, first, second)
		}
	}
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / spec.laneBits
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	if !spec.vector {
		return true, false, c.storeLegacyPackedLogical(ins.Args[form.destination], "%"+out)
	}
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], byteWidth, "%"+out)
}

func (c *amd64Ctx) loadHorizontalIntegerOperand(operand Operand, byteWidth, laneBits int) (string, error) {
	bytesValue, err := c.loadX86PackedShiftBytes(operand, byteWidth, true)
	if err != nil {
		return "", err
	}
	lanes := byteWidth * 8 / laneBits
	return c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, bytesValue), nil
}

func (c *amd64Ctx) emitHorizontalInteger(spec amd64HorizontalIntegerSpec, byteWidth int, first, second string) string {
	lanes := byteWidth * 8 / spec.laneBits
	lanesPer128 := 128 / spec.laneBits
	// The legacy MMX PHADDD row is one 64-bit lane group rather than one
	// 128-bit group, but the same half-from-each-source construction applies.
	if byteWidth == 8 {
		lanesPer128 = lanes
	}
	typeName := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	elementType := fmt.Sprintf("i%d", spec.laneBits)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		position := lane % lanesPer128
		block := lane - position
		source := second
		pair := position
		if position >= lanesPer128/2 {
			source = first
			pair -= lanesPer128 / 2
		}
		leftIndex := block + 2*pair
		rightIndex := leftIndex + 1
		left := c.newTmp()
		right := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", left, typeName, source, leftIndex)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", right, typeName, source, rightIndex)
		value := c.emitHorizontalIntegerPair(spec, "%"+left, "%"+right)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %s, i32 %d\n", inserted, typeName, result, elementType, value, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitHorizontalIntegerPair(spec amd64HorizontalIntegerSpec, left, right string) string {
	operation := "add"
	if spec.subtract {
		operation = "sub"
	}
	if !spec.saturate {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i%d %s, %s\n", value, operation, spec.laneBits, left, right)
		return "%" + value
	}
	leftWide := c.newTmp()
	rightWide := c.newTmp()
	value := c.newTmp()
	below := c.newTmp()
	lowerClamped := c.newTmp()
	above := c.newTmp()
	clamped := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", leftWide, left)
	fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", rightWide, right)
	fmt.Fprintf(c.b, "  %%%s = %s i32 %%%s, %%%s\n", value, operation, leftWide, rightWide)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, -32768\n", below, value)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 -32768, i32 %%%s\n", lowerClamped, below, value)
	fmt.Fprintf(c.b, "  %%%s = icmp sgt i32 %%%s, 32767\n", above, lowerClamped)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 32767, i32 %%%s\n", clamped, above, lowerClamped)
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i16\n", result, clamped)
	return "%" + result
}
