package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEPredicateIncDecSpec struct {
	increment  bool
	saturating bool
	unsigned   bool
	word       bool
	splitWord  bool
}

var arm64SVEPredicateIncDecSpecs = map[Op]arm64SVEPredicateIncDecSpec{
	"PDECP":    {},
	"PINCP":    {increment: true},
	"PSQDECP":  {saturating: true},
	"PSQDECPW": {saturating: true, word: true, splitWord: true},
	"PSQINCP":  {increment: true, saturating: true},
	"PSQINCPW": {increment: true, saturating: true, word: true, splitWord: true},
	"PUQDECP":  {saturating: true, unsigned: true},
	"PUQDECPW": {saturating: true, unsigned: true, word: true},
	"PUQINCP":  {increment: true, saturating: true, unsigned: true},
	"PUQINCPW": {increment: true, saturating: true, unsigned: true, word: true},
}

// decodeARM64RawSVEPredicateIncDec covers the ten Go 1.27 predicate
// increment/decrement rows. Their only variable fields are element size,
// predicate register, and destination scalar register.
func decodeARM64RawSVEPredicateIncDec(word uint32) (Instr, bool) {
	const variableBits = uint32(0x00c001ff)
	forms := [...]struct {
		op   Op
		base uint32
	}{
		{"PDECP", 0x252d8800},
		{"PINCP", 0x252c8800},
		{"PSQDECP", 0x252a8c00},
		{"PSQDECPW", 0x252a8800},
		{"PSQINCP", 0x25288c00},
		{"PSQINCPW", 0x25288800},
		{"PUQDECP", 0x252b8c00},
		{"PUQDECPW", 0x252b8800},
		{"PUQINCP", 0x25298c00},
		{"PUQINCPW", 0x25298800},
	}
	for _, form := range forms {
		if word&^variableBits != form.base {
			continue
		}
		width := [...]string{"B", "H", "S", "D"}[word>>22&3]
		predicate := Operand{
			Kind: OpReg,
			Reg:  Reg(fmt.Sprintf("P%d.%s", word>>5&15, width)),
		}
		register := Reg(fmt.Sprintf("R%d", word&31))
		if word&31 == 31 {
			register = "ZR"
		}
		scalar := Operand{Kind: OpReg, Reg: register}
		args := []Operand{predicate, scalar}
		if arm64SVEPredicateIncDecSpecs[form.op].splitWord {
			args = []Operand{scalar, predicate, scalar}
		}
		return Instr{Op: form.op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}

func (c *arm64Ctx) lowerARM64SVEPredicateIncDec(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEPredicateIncDecSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	predicateOperand := 0
	registerOperand := 1
	if spec.splitWord {
		if len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects Wdn, Pm.T, Xdn: %q", op, ins.Raw)
		}
		predicateOperand = 1
		registerOperand = 2
		if ins.Args[0].Kind != OpReg || ins.Args[2].Kind != OpReg || ins.Args[0].Reg != ins.Args[2].Reg {
			return true, false, fmt.Errorf("arm64 %s requires matching Wdn and Xdn registers: %q", op, ins.Raw)
		}
	} else if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Pm.T, Xdn: %q", op, ins.Raw)
	}
	predicate, elementBits, predicateOK := arm64ParseSVEPredicateElement(ins.Args[predicateOperand])
	register, registerOK := arm64SVEIncDecRegister(ins.Args[registerOperand])
	if !predicateOK || !registerOK {
		return true, false, fmt.Errorf("arm64 %s requires P0..P15.B/H/S/D and a general register or ZR: %q", op, ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	scalar, err := c.loadReg(register)
	if err != nil {
		return true, false, err
	}
	if !spec.saturating {
		governing, _, err := c.allTruePRegElements(elementBits)
		if err != nil {
			return true, false, err
		}
		lanes := 128 / elementBits
		count := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.cntp.nxv%di1(%s %s, %s %s)\n", count, lanes, predicateType, governing, predicateType, predicateValue)
		result := c.newTmp()
		operation := "sub"
		if spec.increment {
			operation = "add"
		}
		fmt.Fprintf(c.b, "  %%%s = %s i64 %s, %%%s\n", result, operation, scalar, count)
		return true, false, c.storeReg(register, "%"+result)
	}
	scalarType := "i64"
	width := 64
	if spec.word {
		width = 32
		scalarType = "i32"
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", truncated, scalar)
		scalar = "%" + truncated
	}
	intrinsic := "sqdec"
	if spec.unsigned {
		intrinsic = "uqdec"
	}
	if spec.increment {
		intrinsic = strings.Replace(intrinsic, "dec", "inc", 1)
	}
	lanes := 128 / elementBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%sp.n%d.nxv%di1(%s %s, %s %s)\n", result, scalarType, intrinsic, width, lanes, scalarType, scalar, predicateType, predicateValue)
	value := "%" + result
	if spec.word {
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", extended, value)
		value = "%" + extended
	}
	return true, false, c.storeReg(register, value)
}

func arm64SVEIncDecRegister(operand Operand) (Reg, bool) {
	if operand.Kind != OpReg || !isARM64GeneralOrZeroReg(operand.Reg) {
		return "", false
	}
	return operand.Reg, true
}
