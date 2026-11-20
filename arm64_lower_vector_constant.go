package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARM64VectorConstant implements the complete Go assembler family for
// materializing 32-, 64-, and 128-bit constants in a vector register:
//
//	VMOVS $lo32, Vd
//	VMOVD $lo64, Vd
//	VMOVQ $lo64, $hi64, Vd
func (c *arm64Ctx) lowerARM64VectorConstant(op Op, ins Instr) (ok bool, terminated bool, err error) {
	var bits int
	switch op {
	case "VMOVS":
		bits = 32
	case "VMOVD":
		bits = 64
	case "VMOVQ":
		bits = 128
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	wantArgs := 2
	if bits == 128 {
		wantArgs = 3
	}
	if len(ins.Args) != wantArgs {
		return true, false, fmt.Errorf("arm64 %s expects %d operands: %q", op, wantArgs, ins.Raw)
	}
	for i := 0; i < wantArgs-1; i++ {
		if ins.Args[i].Kind != OpImm {
			return true, false, fmt.Errorf("arm64 %s operand %d must be an immediate: %q", op, i+1, ins.Raw)
		}
	}
	dst := ins.Args[wantArgs-1]
	if dst.Kind != OpReg || strings.Contains(string(dst.Reg), ".") {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}
	if _, valid := arm64ParseVReg(dst.Reg); !valid {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}

	var vector, vectorType string
	switch bits {
	case 32:
		vectorType = "<4 x i32>"
		vector = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> zeroinitializer, i32 %d, i32 0\n", vector, uint32(ins.Args[0].Imm))
	case 64:
		vectorType = "<2 x i64>"
		vector = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %d, i32 0\n", vector, uint64(ins.Args[0].Imm))
	case 128:
		vectorType = "<2 x i64>"
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %d, i32 0\n", low, uint64(ins.Args[0].Imm))
		vector = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %d, i32 1\n", vector, low, uint64(ins.Args[1].Imm))
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytes, vectorType, vector)
	return true, false, c.storeVReg(dst.Reg, "%"+bytes)
}
