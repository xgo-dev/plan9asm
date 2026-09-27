package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVECompareSpec struct {
	predicate   string
	floating    bool
	absolute    bool
	allowReg    bool
	allowImm    bool
	unsignedImm bool
	wideOnly    bool
	rawBase     uint32
	rawImmBase  uint32
}

var arm64SVECompareSpecs = map[Op]arm64SVECompareSpec{
	"ZCMPEQ": {predicate: "eq", allowReg: true, allowImm: true},
	"ZCMPGE": {predicate: "sge", allowReg: true, allowImm: true},
	"ZCMPGT": {predicate: "sgt", allowReg: true, allowImm: true},
	"ZCMPHI": {predicate: "ugt", allowReg: true, allowImm: true, unsignedImm: true},
	"ZCMPHS": {predicate: "uge", allowReg: true, allowImm: true, unsignedImm: true},
	"ZCMPLE": {predicate: "sle", allowReg: true, allowImm: true, wideOnly: true},
	"ZCMPLO": {predicate: "ult", allowReg: true, allowImm: true, unsignedImm: true, wideOnly: true},
	"ZCMPLS": {predicate: "ule", allowReg: true, allowImm: true, unsignedImm: true, wideOnly: true},
	"ZCMPLT": {predicate: "slt", allowReg: true, allowImm: true, wideOnly: true},
	"ZCMPNE": {predicate: "ne", allowReg: true, allowImm: true},
	"ZFACGE": {predicate: "oge", floating: true, absolute: true, allowReg: true, rawBase: 0x6500c010},
	"ZFACGT": {predicate: "ogt", floating: true, absolute: true, allowReg: true, rawBase: 0x6500e010},
	"ZFCMEQ": {predicate: "oeq", floating: true, allowReg: true, allowImm: true, rawBase: 0x65006000, rawImmBase: 0x65122000},
	"ZFCMGE": {predicate: "oge", floating: true, allowReg: true, allowImm: true, rawBase: 0x65004000, rawImmBase: 0x65102000},
	"ZFCMGT": {predicate: "ogt", floating: true, allowReg: true, allowImm: true, rawBase: 0x65004010, rawImmBase: 0x65102010},
	"ZFCMLE": {predicate: "ole", floating: true, allowImm: true, rawImmBase: 0x65112010},
	"ZFCMLT": {predicate: "olt", floating: true, allowImm: true, rawImmBase: 0x65112000},
	"ZFCMNE": {predicate: "une", floating: true, allowReg: true, allowImm: true, rawBase: 0x65006010, rawImmBase: 0x65132000},
	"ZFCMUO": {predicate: "uno", floating: true, allowReg: true, rawBase: 0x6500c000},
}

func decodeARM64RawSVEFloatCompare(word uint32) (Instr, bool) {
	size := word >> 22 & 3
	if size == 0 {
		return Instr{}, false
	}
	for op, spec := range arm64SVECompareSpecs {
		if !spec.floating {
			continue
		}
		regular := spec.allowReg && word&^uint32(0x00df1fef) == spec.rawBase
		immediate := spec.allowImm && word&^uint32(0x00c01fef) == spec.rawImmBase
		if !regular && !immediate {
			continue
		}
		width := "BHSD"[size]
		second := Operand{Kind: OpImm, ImmIsFloat: true}
		if regular {
			second = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>16&31, width))}
		}
		return Instr{Op: op, Raw: fmt.Sprintf("WORD $%#08x", word), Args: []Operand{
			second,
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", word>>10&7))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%c", word&15, width))},
		}}, true
	}
	return Instr{}, false
}

// decodeARM64RawSVEIntegerCompare covers every Go 1.27 integer compare row.
// LE/LO/LS/LT have only immediate and wide-vector forms; the other six also
// have ordinary same-width vector forms.
func decodeARM64RawSVEIntegerCompare(word uint32) (Instr, bool) {
	const (
		wideBits        = uint32(0x00df1fef)
		unsignedImmBits = uint32(0x00dfdfef)
	)
	forms := [...]struct {
		op          Op
		wideBase    uint32
		regularBase uint32
		immBase     uint32
		unsigned    bool
		regular     bool
	}{
		{"ZCMPEQ", 0x24002000, 0x2400a000, 0x25008000, false, true},
		{"ZCMPGE", 0x24004000, 0x24008000, 0x25000000, false, true},
		{"ZCMPGT", 0x24004010, 0x24008010, 0x25000010, false, true},
		{"ZCMPHI", 0x2400c010, 0x24000010, 0x24200010, true, true},
		{"ZCMPHS", 0x2400c000, 0x24000000, 0x24200000, true, true},
		{"ZCMPLE", 0x24006010, 0, 0x25002010, false, false},
		{"ZCMPLO", 0x2400e000, 0, 0x24202000, true, false},
		{"ZCMPLS", 0x2400e010, 0, 0x24202010, true, false},
		{"ZCMPLT", 0x24006000, 0, 0x25002000, false, false},
		{"ZCMPNE", 0x24002010, 0x2400a010, 0x25008010, false, true},
	}
	for _, form := range forms {
		immediateBits := wideBits
		if form.unsigned {
			immediateBits = unsignedImmBits
		}
		wide := word&^wideBits == form.wideBase
		regular := form.regular && word&^wideBits == form.regularBase
		immediate := word&^immediateBits == form.immBase
		if !wide && !regular && !immediate {
			continue
		}
		size := int(word>>22) & 3
		if wide && size == 3 {
			return Instr{}, false
		}
		width := [...]string{"B", "H", "S", "D"}[size]
		first := int(word>>5) & 31
		governing := int(word>>10) & 7
		destination := int(word) & 15
		args := make([]Operand, 0, 4)
		if wide {
			second := int(word>>16) & 31
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.D", second))})
		} else if regular {
			second := int(word>>16) & 31
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", second, width))})
		} else {
			value := int64(word >> 16 & 31)
			if form.unsigned {
				value = int64(word >> 14 & 127)
			} else if value >= 16 {
				value -= 32
			}
			args = append(args, Operand{Kind: OpImm, Imm: value})
		}
		args = append(args,
			Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", first, width))},
			Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", governing))},
			Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", destination, width))},
		)
		return Instr{Op: form.op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}

func arm64ParseSVEPredicateMode(operand Operand, mode string, maximum int) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(string(operand.Reg))), ".")
	if len(parts) != 2 || parts[1] != mode || !strings.HasPrefix(parts[0], "P") {
		return 0, false
	}
	var index int
	if _, err := fmt.Sscanf(parts[0], "P%d", &index); err != nil || index < 0 || index > maximum {
		return 0, false
	}
	return index, true
}

func arm64ParseSVEPredicateBare(operand Operand, maximum int) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	text := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	if strings.Contains(text, ".") || !strings.HasPrefix(text, "P") {
		return 0, false
	}
	var index int
	if _, err := fmt.Sscanf(text, "P%d", &index); err != nil || index < 0 || index > maximum {
		return 0, false
	}
	return index, true
}

func arm64ParseSVEPredicateElement(operand Operand) (index, elementBits int, ok bool) {
	if operand.Kind != OpReg {
		return 0, 0, false
	}
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(string(operand.Reg))), ".")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "P") {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(parts[0], "P%d", &index); err != nil || index < 0 || index > 15 {
		return 0, 0, false
	}
	elementBits, ok = map[string]int{"B": 8, "H": 16, "S": 32, "D": 64}[parts[1]]
	return index, elementBits, ok
}

type arm64SVECompareForm struct {
	op           Op
	elementBits  int
	first        int
	second       int
	predicate    int
	destination  int
	immediate    int64
	hasImmediate bool
	wide         bool
}

func (c *arm64Ctx) lowerARM64SVECompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVECompareSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects one of its four-operand Go 1.27 SVE compare forms: %q", op, ins.Raw)
	}
	parseElement := arm64ParseSVEZElementReg
	if spec.floating {
		parseElement = arm64SVEFloatElementReg
	}
	first, firstBits, firstOK := parseElement(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "Z", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[3])
	if !firstOK || !predicateOK || !destinationOK || firstBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s compare data, governing predicate, and result widths do not match: %q", op, ins.Raw)
	}
	form := arm64SVECompareForm{op: op, elementBits: firstBits, first: first, predicate: predicate, destination: destination}
	if ins.Args[0].Kind == OpImm {
		if !spec.allowImm || ins.Args[0].ImmRaw != "" {
			return true, false, fmt.Errorf("arm64 %s does not accept this immediate compare form: %q", op, ins.Raw)
		}
		if spec.floating {
			if !ins.Args[0].ImmIsFloat || uint64(ins.Args[0].Imm) != 0 {
				return true, false, fmt.Errorf("arm64 %s floating immediate must be $(0.0): %q", op, ins.Raw)
			}
		} else if ins.Args[0].ImmIsFloat || (!spec.unsignedImm && (ins.Args[0].Imm < -16 || ins.Args[0].Imm > 15)) || (spec.unsignedImm && (ins.Args[0].Imm < 0 || ins.Args[0].Imm > 127)) {
			return true, false, fmt.Errorf("arm64 %s integer immediate is outside its Go 1.27 range: %q", op, ins.Raw)
		}
		form.hasImmediate = true
		form.immediate = ins.Args[0].Imm
	} else {
		if !spec.allowReg {
			return true, false, fmt.Errorf("arm64 %s does not accept a vector compare source: %q", op, ins.Raw)
		}
		second, secondBits, secondOK := parseElement(ins.Args[0])
		if !secondOK {
			return true, false, fmt.Errorf("arm64 %s compare source is not a valid scalable vector: %q", op, ins.Raw)
		}
		if spec.wideOnly && (firstBits == 64 || secondBits != 64) {
			return true, false, fmt.Errorf("arm64 %s only accepts a .D source over B/H/S vectors: %q", op, ins.Raw)
		}
		if secondBits == firstBits {
			form.second = second
		} else if !spec.floating && secondBits == 64 && firstBits < 64 {
			form.second = second
			form.wide = true
		} else {
			return true, false, fmt.Errorf("arm64 %s compare vector widths do not match a regular or wide form: %q", op, ins.Raw)
		}
	}
	return true, false, c.lowerARM64SVECompareForm(spec, form)
}

func (c *arm64Ctx) lowerARM64SVECompareForm(spec arm64SVECompareSpec, form arm64SVECompareForm) error {
	predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
	if err != nil {
		return err
	}
	if form.wide {
		first, vectorType, err := c.loadZRegElements(form.first, form.elementBits)
		if err != nil {
			return err
		}
		second, wideType, err := c.loadZRegElements(form.second, 64)
		if err != nil {
			return err
		}
		intrinsic := strings.ToLower(strings.TrimPrefix(string(form.op), "Z"))
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.wide.nxv%di%d(%s %s, %s %s, %s %s)\n", result, predicateType, intrinsic, 128/form.elementBits, form.elementBits, predicateType, predicate, vectorType, first, wideType, second)
		return c.storePRegElements(form.destination, form.elementBits, "%"+result)
	}

	var first, second, vectorType string
	if spec.floating {
		first, vectorType, err = c.loadRawSVEFloatVector(form.first, form.elementBits)
		if err != nil {
			return err
		}
		if form.hasImmediate {
			second = "zeroinitializer"
		} else {
			second, _, err = c.loadRawSVEFloatVector(form.second, form.elementBits)
			if err != nil {
				return err
			}
		}
		if spec.absolute {
			first, err = c.arm64SVEFloatAbsolute(first, form.elementBits)
			if err != nil {
				return err
			}
			second, err = c.arm64SVEFloatAbsolute(second, form.elementBits)
			if err != nil {
				return err
			}
		}
	} else {
		first, vectorType, err = c.loadZRegElements(form.first, form.elementBits)
		if err != nil {
			return err
		}
		if form.hasImmediate {
			second = fmt.Sprintf("splat (i%d %d)", form.elementBits, form.immediate)
		} else {
			second, _, err = c.loadZRegElements(form.second, form.elementBits)
			if err != nil {
				return err
			}
		}
	}
	compared := c.newTmp()
	operation := "icmp"
	if spec.floating {
		operation = "fcmp"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s %s, %s\n", compared, operation, spec.predicate, vectorType, first, second)
	active := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", active, predicateType, compared, predicate)
	return c.storePRegElements(form.destination, form.elementBits, "%"+active)
}

func (c *arm64Ctx) arm64SVEFloatAbsolute(value string, elementBits int) (string, error) {
	integerType, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return "", err
	}
	floatingType := fmt.Sprintf("<vscale x %d x %s>", lanes, map[int]string{16: "half", 32: "float", 64: "double"}[elementBits])
	bits := c.newTmp()
	cleared := c.newTmp()
	result := c.newTmp()
	mask := uint64(1)<<(elementBits-1) - 1
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bits, floatingType, value, integerType)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, splat (i%d %d)\n", cleared, integerType, bits, elementBits, mask)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", result, integerType, cleared, floatingType)
	return "%" + result, nil
}
