package plan9asm

import (
	"fmt"
	"strings"
)

// lowerMoveHighLowPackedSingle implements all forms in Go 1.27's legacy yxr
// and AVX _yvmovhlps tables for the HLPS/LHPS register-only move family.
func (c *amd64Ctx) lowerMoveHighLowPackedSingle(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	vector := false
	switch baseOp {
	case "MOVHLPS", "MOVLHPS":
	case "VMOVHLPS", "VMOVLHPS":
		vector = true
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s has no instruction suffixes in Go 1.27's optab: %q", baseOp, ins.Raw)
	}

	wantOperands := 2
	if vector {
		wantOperands = 3
	}
	if len(ins.Args) != wantOperands {
		return true, false, fmt.Errorf("amd64 %s expects %d X-register operands: %q", baseOp, wantOperands, ins.Raw)
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s is register-only in Go 1.27's optab: %q", baseOp, ins.Raw)
		}
		index, ok := amd64ParseXReg(operand.Reg)
		if !ok || (!vector && index > 15) {
			return true, false, fmt.Errorf("amd64 %s operand is outside its Go 1.27 X-register class: %q", baseOp, ins.Raw)
		}
	}

	first, err := c.loadXAsI64x2(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	if !vector {
		destination, err := c.loadXAsI64x2(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		mask := "<i32 0, i32 2>"
		if baseOp == "MOVHLPS" {
			mask = "<i32 3, i32 1>"
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <2 x i32> %s\n", result, destination, first, mask)
		return true, false, c.storeXFromI64x2(ins.Args[1].Reg, "%"+result)
	}

	second, err := c.loadXAsI64x2(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	mask := "<i32 2, i32 0>"
	if baseOp == "VMOVHLPS" {
		mask = "<i32 1, i32 3>"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <2 x i32> %s\n", result, first, second, mask)
	return true, false, c.storeXFromI64x2(ins.Args[2].Reg, "%"+result)
}
