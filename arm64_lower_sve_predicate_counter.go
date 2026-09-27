package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEPredicateCounterOps = map[Op]struct{}{
	"PPTRUE": {},
	"PCNTP":  {},
	"PPEXT":  {},
}

// PCNTP has both ordinary predicate and SVE2.1 predicate-as-counter forms.
// The latter adds one VLx2/VLx4 selector, not a governing predicate register.
func decodeARM64RawSVEPredicateCount(word uint32) (Instr, bool) {
	ordinary := word&^uint32(0x00c03dff) == 0x25208000
	counter := word&^uint32(0x00c005ff) == 0x25208200
	if !ordinary && !counter {
		return Instr{}, false
	}
	width := "BHSD"[word>>22&3]
	destination := Reg(fmt.Sprintf("R%d", word&31))
	if word&31 == 31 {
		destination = ZR
	}
	args := []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%c", word>>5&15, width))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d", word>>10&15))},
		{Kind: OpReg, Reg: destination},
	}
	if counter {
		args[0] = Operand{Kind: OpIdent, Ident: fmt.Sprintf("VLX%d", 2<<uint(word>>10&1))}
		args[1] = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("PN%d.%c", word>>5&15, width))}
	}
	return Instr{Op: "PCNTP", Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}

func arm64SVEPredicateCounterNeedsSVE2P1(op Op, ins Instr) bool {
	if op == "PPTRUE" || op == "PPEXT" {
		return true
	}
	return op == "PCNTP" && len(ins.Args) == 3 && ins.Args[1].Kind == OpReg && strings.HasPrefix(strings.ToUpper(string(ins.Args[1].Reg)), "PN")
}

func arm64ParseSVEPredicateCounterElement(operand Operand) (index, elementBits int, ok bool) {
	if operand.Kind != OpReg {
		return 0, 0, false
	}
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(string(operand.Reg))), ".")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "PN") {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(parts[0], "PN%d", &index); err != nil || index < 0 || index > 15 {
		return 0, 0, false
	}
	elementBits, ok = map[string]int{"B": 8, "H": 16, "S": 32, "D": 64}[parts[1]]
	return index, elementBits, ok
}

func arm64ParseSVEPredicateCounterIndexed(operand Operand) (index, lane int, ok bool) {
	if operand.Kind != OpReg {
		return 0, 0, false
	}
	text := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	open := strings.IndexByte(text, '[')
	if open < 0 || !strings.HasSuffix(text, "]") || !strings.HasPrefix(text, "PN") {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(text[:open], "PN%d", &index); err != nil || index < 8 || index > 15 {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(text[open:], "[%d]", &lane); err != nil || lane < 0 || lane > 3 {
		return 0, 0, false
	}
	return index, lane, true
}

func (c *arm64Ctx) lowerARM64SVEPredicateCounter(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, ok := arm64SVEPredicateCounterOps[op]; !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if op == "PCNTP" {
		return c.lowerARM64SVEPredicateCount(ins)
	}
	if op == "PPEXT" {
		return c.lowerARM64SVEPredicateExtract(ins)
	}
	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("arm64 PPTRUE expects PNd.T: %q", ins.Raw)
	}
	destination, elementBits, destinationOK := arm64ParseSVEPredicateCounterElement(ins.Args[0])
	if !destinationOK || destination < 8 {
		return true, false, fmt.Errorf("arm64 PPTRUE only accepts PN8..PN15.B/H/S/D: %q", ins.Raw)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call target(\"aarch64.svcount\") @llvm.aarch64.sve.ptrue.c%d()\n", result, elementBits)
	return true, false, c.storePNReg(destination, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEPredicateExtract(ins Instr) (ok bool, terminated bool, err error) {
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 PPEXT expects PNn[index], Pd.T or PNn[index], [Pd1.T, Pd2.T]: %q", ins.Raw)
	}
	counter, lane, counterOK := arm64ParseSVEPredicateCounterIndexed(ins.Args[0])
	if !counterOK {
		return true, false, fmt.Errorf("arm64 PPEXT source must be PN8..PN15[0..3]: %q", ins.Raw)
	}
	counterValue, err := c.loadPNReg(counter)
	if err != nil {
		return true, false, err
	}
	if ins.Args[1].Kind == OpReg {
		destination, elementBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[1])
		if !destinationOK {
			return true, false, fmt.Errorf("arm64 PPEXT destination must be P0..P15.B/H/S/D: %q", ins.Raw)
		}
		lanes := 128 / elementBits
		predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pext.nxv%di1(target(\"aarch64.svcount\") %s, i32 %d)\n", result, predicateType, lanes, counterValue, lane)
		return true, false, c.storePRegElements(destination, elementBits, "%"+result)
	}
	if ins.Args[1].Kind != OpRegList || len(ins.Args[1].RegList) != 2 || lane > 1 {
		return true, false, fmt.Errorf("arm64 PPEXT pair form requires lane 0..1 and exactly two predicate destinations: %q", ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEPredicateElement(Operand{Kind: OpReg, Reg: ins.Args[1].RegList[0]})
	second, secondBits, secondOK := arm64ParseSVEPredicateElement(Operand{Kind: OpReg, Reg: ins.Args[1].RegList[1]})
	if !firstOK || !secondOK || firstBits != secondBits || second != first+1 {
		return true, false, fmt.Errorf("arm64 PPEXT pair destinations must be two consecutive predicates with matching arrangements: %q", ins.Raw)
	}
	lanes := 128 / firstBits
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	aggregateType := fmt.Sprintf("{ %s, %s }", predicateType, predicateType)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pext.x2.nxv%di1(target(\"aarch64.svcount\") %s, i32 %d)\n", result, aggregateType, lanes, counterValue, lane)
	firstValue := c.newTmp()
	secondValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 0\n", firstValue, aggregateType, result)
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 1\n", secondValue, aggregateType, result)
	if err := c.storePRegElements(first, firstBits, "%"+firstValue); err != nil {
		return true, false, err
	}
	return true, false, c.storePRegElements(second, secondBits, "%"+secondValue)
}

func (c *arm64Ctx) lowerARM64SVEPredicateCount(ins Instr) (ok bool, terminated bool, err error) {
	if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[2].Reg) {
		return true, false, fmt.Errorf("arm64 PCNTP expects Pn.T, Pg, Xd or VLx2|VLx4, PNn.T, Xd: %q", ins.Raw)
	}
	if tested, elementBits, testedOK := arm64ParseSVEPredicateElement(ins.Args[0]); testedOK {
		governing, governingOK := arm64ParseSVEPredicateBare(ins.Args[1], 15)
		if !governingOK {
			return true, false, fmt.Errorf("arm64 PCNTP ordinary predicate form requires a bare P0..P15 governing predicate: %q", ins.Raw)
		}
		governingValue, predicateType, err := c.loadPRegElements(governing, elementBits)
		if err != nil {
			return true, false, err
		}
		testedValue, _, err := c.loadPRegElements(tested, elementBits)
		if err != nil {
			return true, false, err
		}
		lanes := 128 / elementBits
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.cntp.nxv%di1(%s %s, %s %s)\n", result, lanes, predicateType, governingValue, predicateType, testedValue)
		return true, false, c.storeReg(ins.Args[2].Reg, "%"+result)
	}

	multiplier := 0
	if ins.Args[0].Kind == OpIdent {
		switch strings.ToUpper(ins.Args[0].Ident) {
		case "VLX2":
			multiplier = 2
		case "VLX4":
			multiplier = 4
		}
	}
	counter, elementBits, counterOK := arm64ParseSVEPredicateCounterElement(ins.Args[1])
	if multiplier == 0 || !counterOK {
		return true, false, fmt.Errorf("arm64 PCNTP predicate-as-counter form requires VLx2|VLx4 and PN0..PN15.B/H/S/D: %q", ins.Raw)
	}
	counterValue, err := c.loadPNReg(counter)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.cntp.c%d(target(\"aarch64.svcount\") %s, i32 %d)\n", result, elementBits, counterValue, multiplier)
	return true, false, c.storeReg(ins.Args[2].Reg, "%"+result)
}
