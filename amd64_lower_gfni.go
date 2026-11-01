package plan9asm

import (
	"fmt"
	"strings"
)

type amd64GFNIMode uint8

const (
	amd64GFNIMultiply amd64GFNIMode = iota
	amd64GFNIAffine
	amd64GFNIAffineInverse
)

type amd64GFNISpec struct {
	mode      amd64GFNIMode
	immediate bool
	broadcast bool
}

// amd64GFNISpecs models the whole Go 1.27 GFNI family. VGF2P8MULB uses the
// eight _yvandnpd rows; both affine instructions use the eight
// _yvgf2p8affineinvqb rows, including qword broadcast for their matrix source.
var amd64GFNISpecs = map[Op]amd64GFNISpec{
	"VGF2P8MULB":        {mode: amd64GFNIMultiply},
	"VGF2P8AFFINEQB":    {mode: amd64GFNIAffine, immediate: true, broadcast: true},
	"VGF2P8AFFINEINVQB": {mode: amd64GFNIAffineInverse, immediate: true, broadcast: true},
}

func (c *amd64Ctx) lowerGFNI(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86GFNIProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	spec, byteWidth := form.spec, form.byteWidth
	first, second := ins.Args[form.first], ins.Args[form.second]
	destination := ins.Args[form.destination]
	var mask string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}

	firstBytes, err := c.loadGFNIFirstSource(first, byteWidth, form.broadcast)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadPackedCompareBytes(second, byteWidth)
	if err != nil {
		return true, false, err
	}
	computed := ""
	switch spec.mode {
	case amd64GFNIMultiply:
		computed = c.emitGF2P8Multiply(byteWidth, firstBytes, secondBytes)
	case amd64GFNIAffine, amd64GFNIAffineInverse:
		if spec.mode == amd64GFNIAffineInverse {
			secondBytes = c.emitGF2P8Inverse(byteWidth, secondBytes)
		}
		computed = c.emitGF2P8Affine(byteWidth, firstBytes, secondBytes, form.immediate)
	}
	if form.mask >= 0 {
		old, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		computed = amd64ApplyIntegerLaneMask(c, byteWidth, 8, computed, old, mask, form.zeroing)
	}
	return true, false, c.storePackedMoveOperand(destination, byteWidth, computed)
}

func (c *amd64Ctx) loadGFNIFirstSource(source Operand, byteWidth int, broadcast bool) (string, error) {
	if !broadcast {
		return c.loadX86PackedShiftBytes(source, byteWidth, true)
	}
	// GFNI is E4NF: masks never suppress this complete source/m64bcst read.
	qwords, err := c.loadX86PackedShiftLanes(source, byteWidth, 64, true, "")
	if err != nil {
		return "", err
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", bytes, byteWidth/8, qwords, byteWidth)
	return "%" + bytes, nil
}

// emitGF2P8Multiply performs lane-wise carry-less multiplication reduced by
// x^8+x^4+x^3+x+1 (0x11b). Generic IR keeps translated programs runnable on
// hosts without GFNI while preserving exactly the instruction's byte lanes.
func (c *amd64Ctx) emitGF2P8Multiply(lanes int, first, second string) string {
	vectorType := fmt.Sprintf("<%d x i8>", lanes)
	result := "zeroinitializer"
	multiplicand, multiplier := first, second
	for bit := 0; bit < 8; bit++ {
		lowBit := c.newTmp()
		active := c.newTmp()
		selected := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", lowBit, vectorType, multiplier, llvmSplatInteger(lanes, 8, 1))
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, zeroinitializer\n", active, vectorType, lowBit)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s zeroinitializer\n", selected, lanes, active, vectorType, multiplicand, vectorType)
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", combined, vectorType, result, selected)
		result = "%" + combined
		if bit == 7 {
			break
		}
		highBit := c.newTmp()
		reduce := c.newTmp()
		shifted := c.newTmp()
		reduced := c.newTmp()
		nextMultiplicand := c.newTmp()
		nextMultiplier := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", highBit, vectorType, multiplicand, llvmSplatInteger(lanes, 8, 0x80))
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, zeroinitializer\n", reduce, vectorType, highBit)
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", shifted, vectorType, multiplicand, llvmSplatInteger(lanes, 8, 1))
		fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, %s\n", reduced, vectorType, shifted, llvmSplatInteger(lanes, 8, 0x1b))
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %%%s\n", nextMultiplicand, lanes, reduce, vectorType, reduced, vectorType, shifted)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", nextMultiplier, vectorType, multiplier, llvmSplatInteger(lanes, 8, 1))
		multiplicand, multiplier = "%"+nextMultiplicand, "%"+nextMultiplier
	}
	return result
}

func (c *amd64Ctx) emitGF2P8Inverse(lanes int, source string) string {
	powers := make([]string, 7)
	powers[0] = c.emitGF2P8Multiply(lanes, source, source)
	for i := 1; i < len(powers); i++ {
		powers[i] = c.emitGF2P8Multiply(lanes, powers[i-1], powers[i-1])
	}
	result := powers[0]
	for i := 1; i < len(powers); i++ {
		result = c.emitGF2P8Multiply(lanes, result, powers[i])
	}
	return result
}

func (c *amd64Ctx) emitGF2P8Affine(lanes int, matrix, data string, immediate uint8) string {
	vectorType := fmt.Sprintf("<%d x i8>", lanes)
	result := "zeroinitializer"
	for bit := 0; bit < 8; bit++ {
		row := c.newTmp()
		masked := c.newTmp()
		parities := c.newTmp()
		oneBit := c.newTmp()
		positioned := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> %s\n", row, vectorType, matrix, vectorType, lanes, llvmGFNIMatrixRowMask(lanes, bit))
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", masked, vectorType, data, row)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctpop.v%di8(%s %%%s)\n", parities, vectorType, lanes, vectorType, masked)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", oneBit, vectorType, parities, llvmSplatInteger(lanes, 8, 1))
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", positioned, vectorType, oneBit, llvmSplatInteger(lanes, 8, uint64(bit)))
		fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", combined, vectorType, result, positioned)
		result = "%" + combined
	}
	withImmediate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", withImmediate, vectorType, result, llvmSplatInteger(lanes, 8, uint64(immediate)))
	return "%" + withImmediate
}

func llvmGFNIMatrixRowMask(lanes, bit int) string {
	var b strings.Builder
	b.WriteByte('<')
	for lane := 0; lane < lanes; lane++ {
		if lane != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "i32 %d", lane/8*8+7-bit)
	}
	b.WriteByte('>')
	return b.String()
}
