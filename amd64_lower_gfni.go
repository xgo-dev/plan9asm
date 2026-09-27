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
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64GFNISpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}

	broadcast, zeroing := false, false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	case "BCST":
		broadcast = true
	case "BCST.Z":
		broadcast, zeroing = true, true
	default:
		return true, false, fmt.Errorf("%s %s has a suffix absent from Go 1.27's GFNI table: %q", c.goarch, baseOp, ins.Raw)
	}
	if broadcast && !spec.broadcast {
		return true, false, fmt.Errorf("%s %s does not support broadcast: %q", c.goarch, baseOp, ins.Raw)
	}
	// The 386 assembler frontend can encode the three-operand multiply forms,
	// but cannot represent the affine family's four-operand minimum.
	if c.goarch == "386" && spec.immediate && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}

	minimumArgs := 3
	if spec.immediate {
		minimumArgs = 4
	}
	if len(ins.Args) != minimumArgs && len(ins.Args) != minimumArgs+1 {
		return true, false, fmt.Errorf("%s %s has the wrong operand count for Go 1.27's GFNI table: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == minimumArgs+1
	if c.goarch == "386" && masked && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s masked form exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s.Z requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}

	operandOffset := 0
	immediate := uint8(0)
	if spec.immediate {
		if !amd64UnsignedImmediate(ins.Args[0], 8) {
			return true, false, fmt.Errorf("%s %s expects an unsigned 8-bit immediate: %q", c.goarch, baseOp, ins.Raw)
		}
		immediate = uint8(ins.Args[0].Imm)
		operandOffset = 1
	}
	first := ins.Args[operandOffset]
	second := ins.Args[operandOffset+1]
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's vector-register class: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoPackedVectorMoveRegister(second, byteWidth) {
		return true, false, fmt.Errorf("%s %s second source must be a same-width vector register: %q", c.goarch, baseOp, ins.Raw)
	}
	if first.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(first, byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if broadcast && !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("%s %s.BCST requires a memory matrix source: %q", c.goarch, baseOp, ins.Raw)
	}

	var mask string
	if masked {
		maskArg := ins.Args[len(ins.Args)-2]
		if !amd64NonzeroKOperand(maskArg) {
			return true, false, fmt.Errorf("%s %s masked form requires K1-K7: %q", c.goarch, baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	firstBytes, err := c.loadGFNIFirstSource(first, byteWidth, broadcast)
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
		computed = c.emitGF2P8Affine(byteWidth, firstBytes, secondBytes, immediate)
	}
	if masked {
		old, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		computed = amd64ApplyIntegerLaneMask(c, byteWidth, 8, computed, old, mask, zeroing)
	}
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, computed)
}

func (c *amd64Ctx) loadGFNIFirstSource(source Operand, byteWidth int, broadcast bool) (string, error) {
	if !broadcast {
		return c.loadPackedCompareBytes(source, byteWidth)
	}
	qwords, err := c.loadPackedCompareLanes(source, byteWidth, 64, true)
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
