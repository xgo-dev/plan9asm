package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerMaskVectorMove(op Op, ins Instr) (bool, bool, error) {
	if ins.Op == "" {
		ins.Op = op
	}
	form, recognized, err := x86MaskVectorProperties(ins, c.goarch)
	if err != nil || !recognized {
		return recognized, false, err
	}
	if !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("mask/vector dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	vectorOperand, maskOperand := ins.Args[form.vector], ins.Args[form.mask]
	lanes := form.byteWidth * 8 / form.spec.laneBits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, form.spec.laneBits)
	if !form.spec.maskToVector {
		bytes, err := c.loadPackedCompareBytes(vectorOperand, form.byteWidth)
		if err != nil {
			return true, false, err
		}
		vector := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", vector, form.byteWidth, bytes, vectorType)
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
		return true, false, c.storeK(maskOperand.Reg, result)
	}

	mask, err := c.loadK(maskOperand.Reg)
	if err != nil {
		return true, false, err
	}
	vector := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", shifted, mask, lane)
		bit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i1\n", bit, shifted)
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d -1, i%d 0\n", element, bit, form.spec.laneBits, form.spec.laneBits)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n", inserted, vectorType, vector, form.spec.laneBits, element, lane)
		vector = "%" + inserted
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytes, vectorType, vector, form.byteWidth)
	// All widths are EVEX writes. Legacy storeX would preserve wider aliases
	// and contradict the caller's complete defined-byte effect.
	return true, false, c.storePackedMoveOperand(vectorOperand, form.byteWidth, "%"+bytes)
}
