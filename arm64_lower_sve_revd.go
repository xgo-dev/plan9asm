package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func decodeARM64RawSVERevd(word uint32) (Instr, bool) {
	mode := "M"
	switch word & 0xffffe000 {
	case 0x052e8000:
	case 0x052ea000:
		mode = "Z"
	default:
		return Instr{}, false
	}
	return Instr{Op: "ZREVD", Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.Q", word>>5&31))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", word>>10&7, mode))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.Q", word&31))},
	}}, true
}

func arm64ParseSVEZQReg(operand Operand) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	if !strings.HasPrefix(name, "Z") || !strings.HasSuffix(name, ".Q") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "Z"), ".Q"))
	return index, err == nil && index >= 0 && index <= 31
}

func arm64SVERevdNeedsSVE2P2(ins Instr) bool {
	return len(ins.Args) == 3 && func() bool {
		_, ok := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
		return ok
	}()
}

func (c *arm64Ctx) lowerARM64SVERevd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZREVD" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZREVD expects Zn.Q, Pg/M|Z, Zd.Q without a suffix: %q", ins.Raw)
	}
	source, sourceOK := arm64ParseSVEZQReg(ins.Args[0])
	destination, destinationOK := arm64ParseSVEZQReg(ins.Args[2])
	predicate, mergeOK := arm64ParseSVEPredicateMode(ins.Args[1], "M", 7)
	zeroing := false
	if !mergeOK {
		predicate, zeroing = arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	}
	if !sourceOK || !destinationOK || !mergeOK && !zeroing {
		return true, false, fmt.Errorf("arm64 ZREVD requires Q vectors and P0..P7/M or P0..P7/Z: %q", ins.Raw)
	}
	sourceValue, vectorType, err := c.loadZRegElements(source, 64)
	if err != nil {
		return true, false, err
	}
	mergeValue := "zeroinitializer"
	if !zeroing {
		mergeValue, _, err = c.loadZRegElements(destination, 64)
		if err != nil {
			return true, false, err
		}
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, 64)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.revd.nxv2i64(%s %s, %s %s, %s %s)\n", result, vectorType, vectorType, mergeValue, predicateType, predicateValue, vectorType, sourceValue)
	return true, false, c.storeZRegElements(destination, 64, "%"+result)
}
