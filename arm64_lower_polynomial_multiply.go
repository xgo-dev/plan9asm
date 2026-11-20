package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARM64PolynomialMultiply implements the complete AVPMULL optab row.
// Go accepts the low/high halves of B8/B16 -> H8 and D1/D2 -> Q1. LLVM's
// AArch64 intrinsics preserve carry-less (GF(2)) multiplication semantics.
func (c *arm64Ctx) lowerARM64PolynomialMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VPMULL" && op != "VPMULL2" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects two polynomial vector sources and one widened destination, with no suffix: %q", op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
	}

	firstArrangement, firstOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	secondArrangement, secondOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	if !firstOK || !secondOK || firstArrangement != secondArrangement {
		return true, false, fmt.Errorf("arm64 %s requires matching B8/B16 or D1/D2 source arrangements: %q", op, ins.Raw)
	}
	highHalf := op == "VPMULL2"

	switch {
	case arm64VectorRegHasExactArrangement(ins.Args[2].Reg, "H8"):
		wantLanes := 8
		if highHalf {
			wantLanes = 16
		}
		if firstArrangement.elementBits != 8 || firstArrangement.lanes != wantLanes {
			return true, false, fmt.Errorf("arm64 %s H8 result requires B%d sources: %q", op, wantLanes, ins.Raw)
		}
		first, err := c.loadARM64VectorInteger(ins.Args[0].Reg, firstArrangement)
		if err != nil {
			return true, false, err
		}
		second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, secondArrangement)
		if err != nil {
			return true, false, err
		}
		if highHalf {
			destination := arm64VectorArrangement{elementBits: 16, lanes: 8}
			first = c.selectARM64VectorHighHalf(firstArrangement, destination.lanes, first)
			second = c.selectARM64VectorHighHalf(secondArrangement, destination.lanes, second)
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <8 x i16> @llvm.aarch64.neon.pmull.v8i16(<8 x i8> %s, <8 x i8> %s)\n", result, first, second)
		return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arm64VectorArrangement{elementBits: 16, lanes: 8}, "%"+result)

	case arm64VectorRegHasExactArrangement(ins.Args[2].Reg, "Q1"):
		wantLanes := 1
		if highHalf {
			wantLanes = 2
		}
		if firstArrangement.elementBits != 64 || firstArrangement.lanes != wantLanes {
			return true, false, fmt.Errorf("arm64 %s Q1 result requires D%d sources: %q", op, wantLanes, ins.Raw)
		}
		first, err := c.loadARM64VectorInteger(ins.Args[0].Reg, firstArrangement)
		if err != nil {
			return true, false, err
		}
		second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, secondArrangement)
		if err != nil {
			return true, false, err
		}
		lane := 0
		if highHalf {
			lane = 1
		}
		firstScalar := c.newTmp()
		secondScalar := c.newTmp()
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i32 %d\n", firstScalar, firstArrangement.lanes, first, lane)
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i32 %d\n", secondScalar, secondArrangement.lanes, second, lane)
		fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.aarch64.neon.pmull64(i64 %%%s, i64 %%%s)\n", result, firstScalar, secondScalar)
		return true, false, c.storeVReg(ins.Args[2].Reg, "%"+result)

	default:
		return true, false, fmt.Errorf("arm64 %s destination must be H8 or Q1: %q", op, ins.Raw)
	}
}

func arm64VectorRegHasExactArrangement(reg Reg, arrangement string) bool {
	if _, ok := arm64ParseVReg(reg); !ok {
		return false
	}
	s := strings.ToUpper(strings.TrimSpace(string(reg)))
	return strings.HasSuffix(s, "."+arrangement)
}
