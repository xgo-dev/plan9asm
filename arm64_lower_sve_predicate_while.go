package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEPredicateWhileSpec struct {
	condition string
	word      bool
	pointer   bool
}

var arm64SVEPredicateWhileSpecs = map[Op]arm64SVEPredicateWhileSpec{
	"PWHILEGE":  {condition: "whilege"},
	"PWHILEGT":  {condition: "whilegt"},
	"PWHILEHI":  {condition: "whilehi"},
	"PWHILEHS":  {condition: "whilehs"},
	"PWHILELE":  {condition: "whilele"},
	"PWHILELO":  {condition: "whilelo"},
	"PWHILELS":  {condition: "whilels"},
	"PWHILELT":  {condition: "whilelt"},
	"PWHILEGEW": {condition: "whilege", word: true},
	"PWHILEGTW": {condition: "whilegt", word: true},
	"PWHILEHIW": {condition: "whilehi", word: true},
	"PWHILEHSW": {condition: "whilehs", word: true},
	"PWHILELEW": {condition: "whilele", word: true},
	"PWHILELOW": {condition: "whilelo", word: true},
	"PWHILELSW": {condition: "whilels", word: true},
	"PWHILELTW": {condition: "whilelt", word: true},
	"PWHILERW":  {condition: "whilerw", pointer: true},
	"PWHILEWR":  {condition: "whilewr", pointer: true},
}

func arm64SVEPredicateWhileNeedsSVE2P1(ins Instr) bool {
	return len(ins.Args) >= 3 && (ins.Args[len(ins.Args)-1].Kind == OpRegList || ins.Args[0].Kind == OpIdent)
}

func (c *arm64Ctx) lowerARM64SVEPredicateWhile(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEPredicateWhileSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if spec.pointer {
		return c.lowerARM64SVEPredicateWhilePointer(spec, ins)
	}
	if spec.word {
		return c.lowerARM64SVEPredicateWhileSingle(spec, ins)
	}
	if len(ins.Args) == 4 && ins.Args[0].Kind == OpIdent {
		return c.lowerARM64SVEPredicateWhileCounter(spec, ins)
	}
	if len(ins.Args) == 3 && ins.Args[2].Kind == OpRegList {
		return c.lowerARM64SVEPredicateWhilePair(spec, ins)
	}
	return c.lowerARM64SVEPredicateWhileSingle(spec, ins)
}

func arm64SVEWhileScalarRegister(operand Operand, allowZero bool) (Reg, bool) {
	if operand.Kind != OpReg || !isARM64GeneralOrZeroReg(operand.Reg) {
		return "", false
	}
	if !allowZero && operand.Reg == ZR {
		return "", false
	}
	return operand.Reg, true
}

func (c *arm64Ctx) loadARM64SVEWhileScalars(firstOperand, secondOperand Operand, word, allowZero bool) (first, second, scalarType string, err error) {
	plan9First, firstOK := arm64SVEWhileScalarRegister(firstOperand, allowZero)
	plan9Second, secondOK := arm64SVEWhileScalarRegister(secondOperand, allowZero)
	if !firstOK || !secondOK {
		return "", "", "", fmt.Errorf("predicate while operands must be valid general registers")
	}
	first64, err := c.loadReg(plan9Second)
	if err != nil {
		return "", "", "", err
	}
	second64, err := c.loadReg(plan9First)
	if err != nil {
		return "", "", "", err
	}
	if !word {
		return first64, second64, "i64", nil
	}
	firstTmp := c.newTmp()
	secondTmp := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", firstTmp, first64)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", secondTmp, second64)
	return "%" + firstTmp, "%" + secondTmp, "i32", nil
}

func (c *arm64Ctx) lowerARM64SVEPredicateWhileSingle(spec arm64SVEPredicateWhileSpec, ins Instr) (ok bool, terminated bool, err error) {
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 predicate while expects Rm, Rn, Pd.T: %q", ins.Raw)
	}
	destination, elementBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[2])
	if !destinationOK {
		return true, false, fmt.Errorf("arm64 predicate while destination must be P0..P15.B/H/S/D: %q", ins.Raw)
	}
	first, second, scalarType, err := c.loadARM64SVEWhileScalars(ins.Args[0], ins.Args[1], spec.word, true)
	if err != nil {
		return true, false, fmt.Errorf("arm64 predicate while scalar form: %w: %q", err, ins.Raw)
	}
	lanes := 128 / elementBits
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di1.%s(%s %s, %s %s)\n", result, predicateType, spec.condition, lanes, scalarType, scalarType, first, scalarType, second)
	if err := c.storePRegElements(destination, elementBits, "%"+result); err != nil {
		return true, false, err
	}
	governing, _, err := c.allTruePRegElements(elementBits)
	if err != nil {
		return true, false, err
	}
	c.setSVEPredicateFlags(governing, "%"+result, predicateType, lanes)
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64SVEPredicateWhilePair(spec arm64SVEPredicateWhileSpec, ins Instr) (ok bool, terminated bool, err error) {
	if len(ins.Args) != 3 || ins.Args[2].Kind != OpRegList || len(ins.Args[2].RegList) != 2 {
		return true, false, fmt.Errorf("arm64 predicate while pair form expects Xm, Xn, [Pd1.T, Pd2.T]: %q", ins.Raw)
	}
	firstDestination, firstBits, firstOK := arm64ParseSVEPredicateElement(Operand{Kind: OpReg, Reg: ins.Args[2].RegList[0]})
	secondDestination, secondBits, secondOK := arm64ParseSVEPredicateElement(Operand{Kind: OpReg, Reg: ins.Args[2].RegList[1]})
	if !firstOK || !secondOK || firstBits != secondBits || firstDestination%2 != 0 || secondDestination != firstDestination+1 {
		return true, false, fmt.Errorf("arm64 predicate while pair requires an even/odd consecutive predicate pair with matching arrangements: %q", ins.Raw)
	}
	first, second, _, err := c.loadARM64SVEWhileScalars(ins.Args[0], ins.Args[1], false, false)
	if err != nil {
		return true, false, fmt.Errorf("arm64 predicate while pair scalar form: %w: %q", err, ins.Raw)
	}
	lanes := 128 / firstBits
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	aggregateType := fmt.Sprintf("{ %s, %s }", predicateType, predicateType)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.x2.nxv%di1(i64 %s, i64 %s)\n", result, aggregateType, spec.condition, lanes, first, second)
	firstValue := c.newTmp()
	secondValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 0\n", firstValue, aggregateType, result)
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 1\n", secondValue, aggregateType, result)
	if err := c.storePRegElements(firstDestination, firstBits, "%"+firstValue); err != nil {
		return true, false, err
	}
	if err := c.storePRegElements(secondDestination, secondBits, "%"+secondValue); err != nil {
		return true, false, err
	}
	governing, _, err := c.allTruePRegElements(firstBits)
	if err != nil {
		return true, false, err
	}
	c.setSVEPredicateSequenceFlags(governing, []string{"%" + firstValue, "%" + secondValue}, predicateType, lanes)
	return true, false, nil
}

func arm64SVEWhileMultiplier(operand Operand) int {
	if operand.Kind != OpIdent {
		return 0
	}
	switch strings.ToUpper(operand.Ident) {
	case "VLX2":
		return 2
	case "VLX4":
		return 4
	default:
		return 0
	}
}

func (c *arm64Ctx) lowerARM64SVEPredicateWhileCounter(spec arm64SVEPredicateWhileSpec, ins Instr) (ok bool, terminated bool, err error) {
	if len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 predicate while counter form expects VLx2|VLx4, Xm, Xn, PNd.T: %q", ins.Raw)
	}
	multiplier := arm64SVEWhileMultiplier(ins.Args[0])
	destination, elementBits, destinationOK := arm64ParseSVEPredicateCounterElement(ins.Args[3])
	if multiplier == 0 || !destinationOK || destination < 8 {
		return true, false, fmt.Errorf("arm64 predicate while counter requires VLx2|VLx4 and PN8..PN15.B/H/S/D: %q", ins.Raw)
	}
	first, second, _, err := c.loadARM64SVEWhileScalars(ins.Args[1], ins.Args[2], false, false)
	if err != nil {
		return true, false, fmt.Errorf("arm64 predicate while counter scalar form: %w: %q", err, ins.Raw)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call target(\"aarch64.svcount\") @llvm.aarch64.sve.%s.c%d(i64 %s, i64 %s, i32 %d)\n", result, spec.condition, elementBits, first, second, multiplier)
	if err := c.storePNReg(destination, "%"+result); err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	pieces := make([]string, 0, multiplier)
	for lane := 0; lane < multiplier; lane++ {
		piece := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pext.nxv%di1(target(\"aarch64.svcount\") %%%s, i32 %d)\n", piece, predicateType, lanes, result, lane)
		pieces = append(pieces, "%"+piece)
	}
	governing, _, err := c.allTruePRegElements(elementBits)
	if err != nil {
		return true, false, err
	}
	c.setSVEPredicateSequenceFlags(governing, pieces, predicateType, lanes)
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64SVEPredicateWhilePointer(spec arm64SVEPredicateWhileSpec, ins Instr) (ok bool, terminated bool, err error) {
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Xm, Xn, Pd.T: %q", ins.Op, ins.Raw)
	}
	destination, elementBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[2])
	if !destinationOK {
		return true, false, fmt.Errorf("arm64 %s destination must be P0..P15.B/H/S/D: %q", ins.Op, ins.Raw)
	}
	first, second, _, err := c.loadARM64SVEWhileScalars(ins.Args[0], ins.Args[1], false, false)
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s scalar form: %w: %q", ins.Op, err, ins.Raw)
	}
	firstPointer := c.newTmp()
	secondPointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", firstPointer, first)
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", secondPointer, second)
	lanes := 128 / elementBits
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	letter := strings.ToLower(map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}[elementBits])
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.%s.nxv%di1.p0(ptr %%%s, ptr %%%s)\n", result, predicateType, spec.condition, letter, lanes, firstPointer, secondPointer)
	if err := c.storePRegElements(destination, elementBits, "%"+result); err != nil {
		return true, false, err
	}
	governing, _, err := c.allTruePRegElements(elementBits)
	if err != nil {
		return true, false, err
	}
	c.setSVEPredicateFlags(governing, "%"+result, predicateType, lanes)
	return true, false, nil
}
