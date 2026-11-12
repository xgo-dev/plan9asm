package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func arm64ParseSVEPMOVIndexedZReg(operand Operand, elementBits int) (index, lane int, ok bool) {
	if operand.Kind != OpReg {
		return 0, 0, false
	}
	text := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	open := strings.IndexByte(text, '[')
	if open <= 1 || !strings.HasPrefix(text, "Z") || !strings.HasSuffix(text, "]") || strings.Contains(text[:open], ".") {
		return 0, 0, false
	}
	index, indexErr := strconv.Atoi(text[1:open])
	lane, laneErr := strconv.Atoi(text[open+1 : len(text)-1])
	maximumLane, widthOK := map[int]int{16: 1, 32: 3, 64: 7}[elementBits]
	return index, lane, indexErr == nil && laneErr == nil && widthOK && index >= 0 && index <= 31 && lane >= 0 && lane <= maximumLane
}

func (c *arm64Ctx) lowerARM64SVEPMOV(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZPMOV" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 ZPMOV expects its two-operand Go 1.27 form without a suffix: %q", ins.Raw)
	}

	if predicate, elementBits, predicateOK := arm64ParseSVEPredicateElement(ins.Args[0]); predicateOK {
		if elementBits == 8 {
			vector, vectorOK := arm64ParseSVEBareZReg(ins.Args[1])
			if !vectorOK {
				return true, false, fmt.Errorf("arm64 ZPMOV Pn.B source requires a bare Z destination: %q", ins.Raw)
			}
			return true, false, c.lowerARM64SVEPMOVToVector(predicate, vector, elementBits, 0)
		}
		vector, lane, vectorOK := arm64ParseSVEPMOVIndexedZReg(ins.Args[1], elementBits)
		if !vectorOK {
			return true, false, fmt.Errorf("arm64 ZPMOV Pn.%s source requires a valid indexed Z destination: %q", arm64SVEElementLetter(elementBits), ins.Raw)
		}
		return true, false, c.lowerARM64SVEPMOVToVector(predicate, vector, elementBits, lane)
	}

	if predicate, elementBits, predicateOK := arm64ParseSVEPredicateElement(ins.Args[1]); predicateOK {
		if elementBits == 8 {
			vector, vectorOK := arm64ParseSVEBareZReg(ins.Args[0])
			if !vectorOK {
				return true, false, fmt.Errorf("arm64 ZPMOV Pn.B destination requires a bare Z source: %q", ins.Raw)
			}
			return true, false, c.lowerARM64SVEPMOVToPredicate(vector, predicate, elementBits, 0)
		}
		vector, lane, vectorOK := arm64ParseSVEPMOVIndexedZReg(ins.Args[0], elementBits)
		if !vectorOK {
			return true, false, fmt.Errorf("arm64 ZPMOV Pn.%s destination requires a valid indexed Z source: %q", arm64SVEElementLetter(elementBits), ins.Raw)
		}
		return true, false, c.lowerARM64SVEPMOVToPredicate(vector, predicate, elementBits, lane)
	}

	return true, false, fmt.Errorf("arm64 ZPMOV requires one P0..P15.B/H/S/D operand and one matching Go Z operand: %q", ins.Raw)
}

func (c *arm64Ctx) lowerARM64SVEPMOVToVector(predicate, vector, elementBits, lane int) error {
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return err
	}
	vectorType, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if lane == 0 {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmov.to.vector.lane.zeroing.nxv%di%d(%s %s)\n", result, vectorType, lanes, elementBits, predicateType, predicateValue)
	} else {
		oldVector, _, err := c.loadZRegElements(vector, elementBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmov.to.vector.lane.merging.nxv%di%d(%s %s, %s %s, i32 %d)\n", result, vectorType, lanes, elementBits, vectorType, oldVector, predicateType, predicateValue, lane)
	}
	return c.storeZRegElements(vector, elementBits, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEPMOVToPredicate(vector, predicate, elementBits, lane int) error {
	vectorValue, vectorType, err := c.loadZRegElements(vector, elementBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return err
	}
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	result := c.newTmp()
	if lane == 0 {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmov.to.pred.lane.zero.nxv%di%d(%s %s)\n", result, predicateType, lanes, elementBits, vectorType, vectorValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmov.to.pred.lane.nxv%di%d(%s %s, i32 %d)\n", result, predicateType, lanes, elementBits, vectorType, vectorValue, lane)
	}
	return c.storePRegElements(predicate, elementBits, "%"+result)
}

func arm64SVEElementLetter(elementBits int) string {
	return map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}[elementBits]
}
