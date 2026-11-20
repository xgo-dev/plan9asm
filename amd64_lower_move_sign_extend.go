package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedExtendMove implements all six signed and all six unsigned legacy
// and vector widening instructions exposed by Go 1.27. Ratio-two V forms use
// _yvcvtdq2pd; ratio-four and ratio-eight forms use _yvbroadcastss.
func (c *amd64Ctx) lowerPackedExtendMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	_, zero := x86PackedZeroExtendSpecs[Op(base)]
	_, signed := x86PackedSignExtendSpecs[Op(base)]
	if !zero && !signed {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("packed widening dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op // Keep the original helper's empty-op dispatch contract.
	form, known, err := x86PackedExtendProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return c.emitPackedExtendMove(ins, form)
}

func (c *amd64Ctx) loadPackedExtendInputs(src Operand, registerBytes, lanes, inputBits int) (string, error) {
	if src.Kind == OpReg {
		bytesValue, err := c.loadPackedCompareBytes(src, registerBytes)
		if err != nil {
			return "", err
		}
		fullLanes := registerBytes * 8 / inputBits
		full := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i%d>\n", full, registerBytes, bytesValue, fullLanes, inputBits)
		if fullLanes == lanes {
			return "%" + full, nil
		}
		result := "zeroinitializer"
		for lane := 0; lane < lanes; lane++ {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %%%s, i32 %d\n", value, fullLanes, inputBits, full, lane)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, inputBits, result, inputBits, value, lane)
			result = "%" + inserted
		}
		return result, nil
	}
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, inputBits)
	switch src.Kind {
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(src.Mem)
		if err != nil {
			return "", err
		}
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", loaded, vectorType, ptrType, ptr)
		return "%" + loaded, nil
	case OpSym:
		ptr, err := c.ptrFromSB(src.Sym)
		if err != nil {
			return "", err
		}
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", loaded, vectorType, ptr)
		return "%" + loaded, nil
	case OpFP:
		result := "zeroinitializer"
		for lane := 0; lane < lanes; lane++ {
			laneOperand := src
			laneOperand.FPOffset += int64(lane * inputBits / 8)
			value, err := c.evalIntSized(laneOperand, amd64IntegerTypeForBits(inputBits))
			if err != nil {
				return "", err
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %s, i32 %d\n", inserted, vectorType, result, inputBits, value, lane)
			result = "%" + inserted
		}
		return result, nil
	default:
		return "", fmt.Errorf("expected packed extension register or memory source, got %s", src.String())
	}
}
