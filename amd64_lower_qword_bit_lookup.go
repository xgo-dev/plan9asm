package plan9asm

import (
	"fmt"
)

type amd64QwordBitLookupOutput uint8

const (
	amd64QwordBitLookupBytes amd64QwordBitLookupOutput = iota
	amd64QwordBitLookupMask
)

type amd64QwordBitLookupSpec struct {
	output    amd64QwordBitLookupOutput
	broadcast bool
}

// amd64QwordBitLookupSpecs groups the two AVX-512 byte-control operations
// that select bits inside corresponding qword lanes. They share the same core
// rotate/lookup grammar but produce either bytes or a packed K mask.
var amd64QwordBitLookupSpecs = map[Op]amd64QwordBitLookupSpec{
	"VPMULTISHIFTQB": {output: amd64QwordBitLookupBytes, broadcast: true},
	"VPSHUFBITQMB":   {output: amd64QwordBitLookupMask},
}

func (c *amd64Ctx) lowerQwordBitLookup(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86QwordLookupProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	spec, byteWidth := form.spec, form.byteWidth
	first, second := ins.Args[form.first], ins.Args[form.second]
	destination := ins.Args[form.destination]
	var writeMask string
	if form.mask >= 0 {
		writeMask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	if form.memory >= 0 && first.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(first, c.goarch) &&
		!x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
		return true, false, fmt.Errorf("%w: qword lookup needs its original native storage binding", ErrProbeNeedsContext)
	}
	var dataQwords, controls string
	switch spec.output {
	case amd64QwordBitLookupBytes:
		// VPMULTISHIFTQB is E4NF: even a zero write mask retains the full
		// source tuple, or the independent m64 broadcast.
		dataQwords, err = c.loadX86PackedShiftLanes(first, byteWidth, 64, form.broadcast, "")
		if err == nil {
			controls, err = c.loadPackedCompareBytes(second, byteWidth)
		}
	case amd64QwordBitLookupMask:
		dataQwords, err = c.loadPackedCompareLanes(second, byteWidth, 64, false)
		if err == nil {
			// VPSHUFBITQMB is E4 with byte-granular fault suppression. Its
			// mask is not a license to suppress the other family's E4NF read.
			controls, err = c.loadX86PackedShiftLanes(first, byteWidth, 8, false, writeMask)
		}
	}
	if err != nil {
		return true, false, err
	}
	selectedBytes := c.emitQwordBitLookupBytes(byteWidth, dataQwords, controls)

	if spec.output == amd64QwordBitLookupBytes {
		if form.mask >= 0 {
			old, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
			if loadErr != nil {
				return true, false, loadErr
			}
			selectedBytes = amd64ApplyIntegerLaneMask(c, byteWidth, 8, selectedBytes, old, writeMask, form.zeroing)
		}
		return true, false, c.storePackedMoveOperand(destination, byteWidth, selectedBytes)
	}

	ones := c.newTmp()
	predicates := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and <%d x i8> %s, %s\n", ones, byteWidth, selectedBytes, llvmSplatInteger(byteWidth, 8, 1))
	fmt.Fprintf(c.b, "  %%%s = icmp ne <%d x i8> %%%s, zeroinitializer\n", predicates, byteWidth, ones)
	packedType := fmt.Sprintf("i%d", byteWidth)
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %%%s to %s\n", packed, byteWidth, predicates, packedType)
	result := "%" + packed
	if byteWidth < 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", wide, packedType, result)
		result = "%" + wide
	}
	if form.mask >= 0 {
		maskedResult := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", maskedResult, result, writeMask)
		result = "%" + maskedResult
	}
	return true, false, c.storeK(destination.Reg, result)
}

// emitQwordBitLookupBytes rotates each corresponding data qword right by the
// low six bits of a control byte. Its low byte is VPMULTISHIFTQB's result;
// its low bit is VPSHUFBITQMB's gathered mask bit.
func (c *amd64Ctx) emitQwordBitLookupBytes(byteWidth int, dataQwords, controls string) string {
	result := "zeroinitializer"
	qwords := byteWidth / 8
	for lane := 0; lane < byteWidth; lane++ {
		data := c.newTmp()
		controlByte := c.newTmp()
		controlWide := c.newTmp()
		control := c.newTmp()
		right := c.newTmp()
		negated := c.newTmp()
		wrappedLeftCount := c.newTmp()
		left := c.newTmp()
		rotated := c.newTmp()
		selected := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i32 %d\n", data, qwords, dataQwords, lane/8)
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", controlByte, byteWidth, controls, lane)
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", controlWide, controlByte)
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", control, controlWide)
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, %%%s\n", right, data, control)
		fmt.Fprintf(c.b, "  %%%s = sub i64 0, %%%s\n", negated, control)
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", wrappedLeftCount, negated)
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %%%s\n", left, data, wrappedLeftCount)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", rotated, right, left)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", selected, rotated)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i8> %s, i8 %%%s, i32 %d\n", inserted, byteWidth, result, selected, lane)
		result = "%" + inserted
	}
	return result
}
