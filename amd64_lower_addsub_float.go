package plan9asm

import (
	"fmt"
	"strings"
)

// lowerAlternatingFloatingAddSubtract implements the complete Go 1.27 yxm
// and _yvaddsubpd families. Even lanes subtract the Plan 9 first source from
// the destination/base source; odd lanes add it.
func (c *amd64Ctx) lowerAlternatingFloatingAddSubtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	laneBits := 0
	vector := false
	switch baseOp {
	case "ADDSUBPS":
		laneBits = 32
	case "ADDSUBPD":
		laneBits = 64
	case "VADDSUBPS":
		laneBits, vector = 32, true
	case "VADDSUBPD":
		laneBits, vector = 64, true
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed forms in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if vector {
		return c.lowerVectorAlternatingFloatingAddSubtract(baseOp, laneBits, ins)
	}
	return c.lowerLegacyAlternatingFloatingAddSubtract(baseOp, laneBits, ins)
}

func (c *amd64Ctx) lowerLegacyAlternatingFloatingAddSubtract(baseOp string, laneBits int, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !c.isGoLegacyXReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("%s %s expects X/m128, X using Go 1.27's yxm table: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s %s source is outside the legacy X class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s source must be X or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	first, err := c.loadHorizontalFloatingOperand(ins.Args[0], 16, laneBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadHorizontalFloatingOperand(ins.Args[1], 16, laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitAlternatingFloatingAddSubtract(16, laneBits, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <16 x i8>\n", out, amd64FMA3LLVMType(128/laneBits, laneBits), result)
	return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerVectorAlternatingFloatingAddSubtract(baseOp string, laneBits int, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects src1, src2, destination: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(ins.Args[2].Reg)
	if byteWidth != 16 && byteWidth != 32 ||
		!amd64VEXVectorRegister(ins.Args[1], byteWidth) ||
		!amd64VEXVectorRegister(ins.Args[2], byteWidth) {
		return true, false, fmt.Errorf("%s %s second source and destination must be same-width VEX X/Y registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !amd64VEXVectorRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	first, err := c.loadHorizontalFloatingOperand(ins.Args[0], byteWidth, laneBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadHorizontalFloatingOperand(ins.Args[1], byteWidth, laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitAlternatingFloatingAddSubtract(byteWidth, laneBits, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, amd64FMA3LLVMType(byteWidth*8/laneBits, laneBits), result, byteWidth)
	return true, false, c.storeVectorBytes(ins.Args[2].Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitAlternatingFloatingAddSubtract(byteWidth, laneBits int, first, second string) string {
	lanes := byteWidth * 8 / laneBits
	typeName := amd64FMA3LLVMType(lanes, laneBits)
	elementType := amd64FMA3LLVMType(1, laneBits)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		left := c.newTmp()
		right := c.newTmp()
		value := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", left, typeName, second, lane)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", right, typeName, first, lane)
		operation := "fsub"
		if lane%2 == 1 {
			operation = "fadd"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %%%s\n", value, operation, elementType, left, right)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", inserted, typeName, result, elementType, value, lane)
		result = "%" + inserted
	}
	return result
}
