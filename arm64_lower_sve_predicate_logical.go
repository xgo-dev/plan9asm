package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEPredicateLogicalSpec struct {
	operation string
	flags     bool
}

var arm64SVEPredicateLogicalSpecs = map[Op]arm64SVEPredicateLogicalSpec{
	"PAND":   {operation: "and"},
	"PANDS":  {operation: "and", flags: true},
	"PBIC":   {operation: "bic"},
	"PBICS":  {operation: "bic", flags: true},
	"PEOR":   {operation: "xor"},
	"PEORS":  {operation: "xor", flags: true},
	"PNAND":  {operation: "nand"},
	"PNANDS": {operation: "nand", flags: true},
	"PNOR":   {operation: "nor"},
	"PNORS":  {operation: "nor", flags: true},
	"PORN":   {operation: "orn"},
	"PORNS":  {operation: "orn", flags: true},
	"PORR":   {operation: "or"},
	"PORRS":  {operation: "or", flags: true},
	"PSEL":   {operation: "select"},
}

// Logical and select rows share Pm/Pn/Pg/Pd fields and .B elements. Logical
// forms zero inactive lanes; PSEL chooses its first operand for those lanes.
func decodeARM64RawSVEPredicateLogical(word uint32) (Instr, bool) {
	const variableBits = uint32(0x000f3def)
	forms := [...]struct {
		op   Op
		base uint32
	}{
		{"PAND", 0x25004000}, {"PANDS", 0x25404000},
		{"PBIC", 0x25004010}, {"PBICS", 0x25404010},
		{"PEOR", 0x25004200}, {"PEORS", 0x25404200},
		{"PNAND", 0x25804210}, {"PNANDS", 0x25c04210},
		{"PNOR", 0x25804200}, {"PNORS", 0x25c04200},
		{"PORN", 0x25804010}, {"PORNS", 0x25c04010},
		{"PORR", 0x25804000}, {"PORRS", 0x25c04000},
		{"PSEL", 0x25004210},
	}
	for _, form := range forms {
		if word&^variableBits != form.base {
			continue
		}
		predicate := func(number uint32) Operand {
			return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.B", number))}
		}
		args := []Operand{
			predicate(word >> 16 & 15),
			predicate(word >> 5 & 15),
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", word>>10&15))},
			predicate(word & 15),
		}
		if form.op == "PSEL" {
			args[2].Reg = Reg(fmt.Sprintf("P%d", word>>10&15))
		}
		return Instr{Op: form.op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}

func (c *arm64Ctx) lowerARM64SVEPredicateLogical(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEPredicateLogicalSpecs[op]
	if !ok {
		return false, false, nil
	}
	governingSyntax := "Pg/Z"
	if spec.operation == "select" {
		governingSyntax = "Pg"
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Pm.B, Pn.B, %s, Pd.B: %q", op, governingSyntax, ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEPredicateElement(ins.Args[0])
	second, secondBits, secondOK := arm64ParseSVEPredicateElement(ins.Args[1])
	governing, governingOK := arm64ParseSVEPredicateMode(ins.Args[2], "Z", 15)
	if spec.operation == "select" {
		governing, governingOK = arm64ParseSVEPredicateBare(ins.Args[2], 15)
	}
	destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[3])
	if !firstOK || !secondOK || !governingOK || !destinationOK || firstBits != 8 || secondBits != 8 || destinationBits != 8 {
		return true, false, fmt.Errorf("arm64 %s only accepts the Go 1.27 Pm.B, Pn.B, %s, Pd.B form: %q", op, governingSyntax, ins.Raw)
	}
	return true, false, c.lowerARM64SVEPredicateLogicalForm(spec, first, second, governing, destination)
}

func (c *arm64Ctx) lowerARM64SVEPredicateLogicalForm(spec arm64SVEPredicateLogicalSpec, first, second, governing, destination int) error {
	firstValue, predicateType, err := c.loadPRegElements(first, 8)
	if err != nil {
		return err
	}
	secondValue, _, err := c.loadPRegElements(second, 8)
	if err != nil {
		return err
	}
	governingValue, _, err := c.loadPRegElements(governing, 8)
	if err != nil {
		return err
	}

	result := c.newTmp()
	switch spec.operation {
	case "select":
		fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", result, predicateType, governingValue, predicateType, secondValue, predicateType, firstValue)
		return c.storePReg(destination, "%"+result)
	case "and", "xor", "or":
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", result, spec.operation, predicateType, secondValue, firstValue)
	case "bic", "orn":
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, splat (i1 true)\n", inverted, predicateType, firstValue)
		operation := "and"
		if spec.operation == "orn" {
			operation = "or"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, operation, predicateType, secondValue, inverted)
	case "nand", "nor":
		combined := c.newTmp()
		operation := "and"
		if spec.operation == "nor" {
			operation = "or"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", combined, operation, predicateType, secondValue, firstValue)
		fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, splat (i1 true)\n", result, predicateType, combined)
	default:
		return fmt.Errorf("unsupported ARM64 SVE predicate logical operation %q", spec.operation)
	}

	active := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", active, predicateType, result, governingValue)
	if err := c.storePRegElements(destination, 8, "%"+active); err != nil {
		return err
	}
	if !spec.flags {
		return nil
	}
	c.setSVEPredicateFlags(governingValue, "%"+active, predicateType, 16)
	return nil
}
