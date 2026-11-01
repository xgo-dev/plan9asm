package plan9asm

import (
	"fmt"
	"strings"
)

var arm64VectorCountBitsOps = map[Op]struct{}{
	"VCNT": {},
	"VCLS": {},
	"VCLZ": {},
}

func (c *arm64Ctx) lowerARM64VectorCountBits(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, ok := arm64VectorCountBitsOps[op]; !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects two same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	validArrangement := sourceArrangement.elementBits == 8 && (sourceArrangement.lanes == 8 || sourceArrangement.lanes == 16)
	if op != "VCNT" {
		validArrangement = (sourceArrangement.elementBits == 8 || sourceArrangement.elementBits == 16 || sourceArrangement.elementBits == 32) &&
			(sourceArrangement.lanes*sourceArrangement.elementBits == 64 || sourceArrangement.lanes*sourceArrangement.elementBits == 128)
	}
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement || !validArrangement {
		return true, false, fmt.Errorf("arm64 %s requires matching Go assembler vector arrangements: %q", op, ins.Raw)
	}
	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	if op == "VCNT" {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <%d x i8> @llvm.ctpop.v%di8(<%d x i8> %s)\n", result, sourceArrangement.lanes, sourceArrangement.lanes, sourceArrangement.lanes, source)
		return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, "%"+result)
	}

	vectorType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, sourceArrangement.elementBits)
	countSource := source
	if op == "VCLS" {
		sign := c.newTmp()
		normalized := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %s\n", sign, vectorType, source, arm64VectorIntegerSplat(sourceArrangement, int64(sourceArrangement.elementBits-1)))
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", normalized, vectorType, source, sign)
		countSource = "%" + normalized
	}
	count := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.v%di%d(%s %s, i1 false)\n",
		count, vectorType, sourceArrangement.lanes, sourceArrangement.elementBits, vectorType, countSource)
	result := "%" + count
	if op == "VCLS" {
		adjusted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %s\n", adjusted, vectorType, count, arm64VectorIntegerSplat(sourceArrangement, 1))
		result = "%" + adjusted
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, result)
}
