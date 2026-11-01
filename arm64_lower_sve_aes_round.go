package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

var arm64SVEAESRoundIntrinsics = map[Op]string{
	"ZAESD":    "aesd",
	"ZAESDIMC": "aesdimc",
	"ZAESE":    "aese",
	"ZAESEMC":  "aesemc",
}

func arm64SVEAESRoundIsMulti(ins Instr) bool {
	return len(ins.Args) == 3 && ins.Args[1].Kind == OpRegList
}

func arm64ParseSVEAESRoundKey(operand Operand) (register, lane int, ok bool) {
	if operand.Kind != OpReg {
		return 0, 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	dot := strings.IndexByte(name, '.')
	open := strings.IndexByte(name, '[')
	if dot <= 1 || open <= dot+1 || name[dot:open] != ".Q" || !strings.HasPrefix(name, "Z") || !strings.HasSuffix(name, "]") {
		return 0, 0, false
	}
	register, registerErr := strconv.Atoi(name[1:dot])
	lane, laneErr := strconv.Atoi(name[open+1 : len(name)-1])
	return register, lane, registerErr == nil && laneErr == nil && register >= 0 && register <= 31 && lane >= 0 && lane <= 3
}

func arm64ParseSVEAESRoundGroup(operand Operand) ([]int, bool) {
	if operand.Kind != OpRegList || !operand.RegListRange || len(operand.RegList) != 2 && len(operand.RegList) != 4 {
		return nil, false
	}
	registers := make([]int, len(operand.RegList))
	for i, register := range operand.RegList {
		index, bits, ok := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: register})
		if !ok || bits != 8 || i > 0 && index != registers[0]+i {
			return nil, false
		}
		registers[i] = index
	}
	return registers, registers[0]%len(registers) == 0
}

func (c *arm64Ctx) lowerARM64SVEAESRound(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEAESRoundIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one of the Go 1.27 single- or multi-vector AES forms without a suffix: %q", op, ins.Raw)
	}
	if source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0]); sourceOK {
		firstDestination, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		secondDestination, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[2])
		if op != "ZAESD" && op != "ZAESE" || sourceBits != 8 || !firstOK || !secondOK || firstBits != 8 || secondBits != 8 || firstDestination != secondDestination {
			return true, false, fmt.Errorf("arm64 %s single-vector form requires Zm.B, Zdn.B, Zdn.B: %q", op, ins.Raw)
		}
		oldDestination, vectorType, err := c.loadZRegElements(firstDestination, 8)
		if err != nil {
			return true, false, err
		}
		sourceValue, _, err := c.loadZRegElements(source, 8)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s(%s %s, %s %s)\n", result, vectorType, intrinsic, vectorType, oldDestination, vectorType, sourceValue)
		return true, false, c.storeZRegElements(firstDestination, 8, "%"+result)
	}
	key, lane, keyOK := arm64ParseSVEAESRoundKey(ins.Args[0])
	firstGroup, firstGroupOK := arm64ParseSVEAESRoundGroup(ins.Args[1])
	secondGroup, secondGroupOK := arm64ParseSVEAESRoundGroup(ins.Args[2])
	if !keyOK || !firstGroupOK || !secondGroupOK || len(firstGroup) != len(secondGroup) {
		return true, false, fmt.Errorf("arm64 %s multi-vector form requires a Q[0..3] key and matching aligned B ranges of two or four registers: %q", op, ins.Raw)
	}
	for i := range firstGroup {
		if firstGroup[i] != secondGroup[i] {
			return true, false, fmt.Errorf("arm64 %s multi-vector source/destination ranges must match: %q", op, ins.Raw)
		}
	}
	values := make([]string, len(firstGroup))
	vectorType := ""
	for i, register := range firstGroup {
		values[i], vectorType, err = c.loadZRegElements(register, 8)
		if err != nil {
			return true, false, err
		}
	}
	keyValue, _, err := c.loadZRegElements(key, 8)
	if err != nil {
		return true, false, err
	}
	types := make([]string, len(values))
	arguments := make([]string, 0, len(values)+2)
	for i, value := range values {
		types[i] = vectorType
		arguments = append(arguments, vectorType+" "+value)
	}
	arguments = append(arguments, vectorType+" "+keyValue, fmt.Sprintf("i32 %d", lane))
	aggregateType := "{ " + strings.Join(types, ", ") + " }"
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.x%d(%s)\n", result, aggregateType, intrinsic, len(values), strings.Join(arguments, ", "))
	for i, register := range firstGroup {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", value, aggregateType, result, i)
		if err := c.storeZRegElements(register, 8, "%"+value); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}
