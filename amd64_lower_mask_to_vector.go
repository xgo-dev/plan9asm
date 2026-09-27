package plan9asm

import (
	"fmt"
	"strings"
)

var amd64MaskToVectorLaneBits = map[Op]int{
	"VPMOVM2B": 8,
	"VPMOVM2W": 16,
	"VPMOVM2D": 32,
	"VPMOVM2Q": 64,
}

var amd64VectorToMaskLaneBits = map[Op]int{
	"VPMOVB2M": 8,
	"VPMOVW2M": 16,
	"VPMOVD2M": 32,
	"VPMOVQ2M": 64,
}

// lowerMaskToVector implements the AVX-512 mask-to-vector family. Each mask
// bit becomes an all-zero or all-one element in the selected B/W/D/Q vector;
// the result is materialized in the same byte-backed register model as other
// packed operations.
func (c *amd64Ctx) lowerMaskToVector(op Op, ins Instr) (ok bool, terminated bool, err error) {
	laneBits, handled := amd64MaskToVectorLaneBits[op]
	if !handled {
		return false, false, nil
	}
	if len(ins.Args) != 2 || !amd64IsKOperand(ins.Args[0]) || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects K0-K7 and X/Y/Z destination operands: %q", op, ins.Raw)
	}
	destination := strings.ToUpper(string(ins.Args[1].Reg))
	vectorBits := 0
	store := func(string) error { return nil }
	var vectorType string
	switch {
	case strings.HasPrefix(destination, "X"):
		vectorBits = 128
		vectorType = fmt.Sprintf("<%d x i%d>", vectorBits/laneBits, laneBits)
		store = func(value string) error { return c.storeX(ins.Args[1].Reg, value) }
	case strings.HasPrefix(destination, "Y"):
		vectorBits = 256
		vectorType = fmt.Sprintf("<%d x i%d>", vectorBits/laneBits, laneBits)
		store = func(value string) error { return c.storeY(ins.Args[1].Reg, value) }
	case strings.HasPrefix(destination, "Z"):
		vectorBits = 512
		vectorType = fmt.Sprintf("<%d x i%d>", vectorBits/laneBits, laneBits)
		store = func(value string) error { return c.storeZ(ins.Args[1].Reg, value) }
	default:
		return true, false, fmt.Errorf("amd64 %s destination must be X, Y, or Z vector register: %q", op, ins.Raw)
	}
	mask, err := c.loadK(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := vectorBits / laneBits
	vector := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", shifted, mask, lane)
		bit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i1\n", bit, shifted)
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d -1, i%d 0\n", element, bit, laneBits, laneBits)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n", inserted, vectorType, vector, laneBits, element, lane)
		vector = "%" + inserted
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytes, vectorType, vector, vectorBits/8)
	return true, false, store("%" + bytes)
}

// lowerVectorToMask implements the reverse AVX-512 family. Each result mask
// bit is the most significant bit of its corresponding B/W/D/Q vector lane.
func (c *amd64Ctx) lowerVectorToMask(op Op, ins Instr) (ok bool, terminated bool, err error) {
	laneBits, handled := amd64VectorToMaskLaneBits[op]
	if !handled {
		return false, false, nil
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects X/Y/Z source and K0-K7 destination operands: %q", c.goarch, op, ins.Raw)
	}
	source := ins.Args[0]
	byteWidth, validWidth := amd64PackedCompareWidth(source)
	if !validWidth || !c.isGoPackedVectorMoveRegister(source, byteWidth) {
		return true, false, fmt.Errorf("%s %s source must be an in-range X, Y, or Z register: %q", c.goarch, op, ins.Raw)
	}
	destination := ins.Args[1]
	if !amd64IsKOperand(destination) {
		return true, false, fmt.Errorf("%s %s destination must be K0-K7: %q", c.goarch, op, ins.Raw)
	}
	bytes, err := c.loadPackedCompareBytes(source, byteWidth)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / laneBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	vector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", vector, byteWidth, bytes, vectorType)
	signBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, zeroinitializer\n", signBits, vectorType, vector)
	packedType := fmt.Sprintf("i%d", lanes)
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %%%s to %s\n", packed, lanes, signBits, packedType)
	result := "%" + packed
	if lanes < 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", wide, packedType, result)
		result = "%" + wide
	}
	return true, false, c.storeK(destination.Reg, result)
}
