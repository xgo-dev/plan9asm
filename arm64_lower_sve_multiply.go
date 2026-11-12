package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64SVEMultiplyMode uint8

const (
	arm64SVEMultiplyPredicated arm64SVEMultiplyMode = iota
	arm64SVEMultiplyUnpredicated
	arm64SVEMultiplyLane
	arm64SVEMultiplyImmediate
)

type arm64RawSVEMultiply struct {
	mode        arm64SVEMultiplyMode
	elementBits int
	first       int
	second      int
	predicate   int
	laneVector  int
	lane        int
	immediate   int
	destination int
}

func decodeARM64RawSVEMultiply(word uint32) (arm64RawSVEMultiply, bool) {
	form := arm64RawSVEMultiply{}
	switch {
	case word&0xff3fe000 == 0x04100000:
		form.mode = arm64SVEMultiplyPredicated
		form.elementBits = 8 << (int(word>>22) & 3)
		form.destination = int(word) & 31
		form.first = form.destination
		form.second = int(word>>5) & 31
		form.predicate = int(word>>10) & 7
	case word&0xff20fc00 == 0x04206000:
		form.mode = arm64SVEMultiplyUnpredicated
		form.elementBits = 8 << (int(word>>22) & 3)
		form.destination = int(word) & 31
		form.first = int(word>>5) & 31
		form.second = int(word>>16) & 31
	case word&0xffa0fc00 == 0x4420f800:
		form.mode = arm64SVEMultiplyLane
		form.elementBits = 16
		form.laneVector = int(word>>16) & 7
		form.lane = int(word>>19)&3 | (int(word>>22)&1)<<2
		form.first = int(word>>5) & 31
		form.destination = int(word) & 31
	case word&0xffe0fc00 == 0x44a0f800:
		form.mode = arm64SVEMultiplyLane
		form.elementBits = 32
		form.laneVector = int(word>>16) & 7
		form.lane = int(word>>19) & 3
		form.first = int(word>>5) & 31
		form.destination = int(word) & 31
	case word&0xffe0fc00 == 0x44e0f800:
		form.mode = arm64SVEMultiplyLane
		form.elementBits = 64
		form.laneVector = int(word>>16) & 15
		form.lane = int(word>>20) & 1
		form.first = int(word>>5) & 31
		form.destination = int(word) & 31
	case word&0xff3fe000 == 0x2530c000:
		form.mode = arm64SVEMultiplyImmediate
		form.elementBits = 8 << (int(word>>22) & 3)
		form.destination = int(word) & 31
		form.first = form.destination
		form.immediate = int(int8(word >> 5))
	default:
		return arm64RawSVEMultiply{}, false
	}
	return form, true
}

func arm64ParseSVEZIndexedElementReg(operand Operand) (index, elementBits, lane int, ok bool) {
	index, elementBits, lane, ok = arm64ParseSVEZIndexedElementRegUnbounded(operand)
	if !ok {
		return 0, 0, 0, false
	}
	maxVector, vectorOK := map[int]int{16: 7, 32: 7, 64: 15}[elementBits]
	maxLane, laneOK := map[int]int{16: 7, 32: 3, 64: 1}[elementBits]
	return index, elementBits, lane, vectorOK && laneOK && index <= maxVector && lane <= maxLane
}

func arm64ParseSVEZIndexedElementRegUnbounded(operand Operand) (index, elementBits, lane int, ok bool) {
	if operand.Kind != OpReg {
		return 0, 0, 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	dot := strings.IndexByte(name, '.')
	open := strings.IndexByte(name, '[')
	if dot <= 1 || open <= dot+1 || !strings.HasSuffix(name, "]") || !strings.HasPrefix(name, "Z") {
		return 0, 0, 0, false
	}
	index, err := strconv.Atoi(name[1:dot])
	if err != nil {
		return 0, 0, 0, false
	}
	elementBits, bitsOK := map[string]int{"B": 8, "H": 16, "S": 32, "D": 64}[name[dot+1:open]]
	lane, err = strconv.Atoi(name[open+1 : len(name)-1])
	if err != nil || !bitsOK {
		return 0, 0, 0, false
	}
	return index, elementBits, lane, index >= 0 && index <= 31 && lane >= 0
}

func arm64SVEMultiplyNeedsSVE2(ins Instr) bool {
	return len(ins.Args) == 3 && len(ins.Args) > 0 && ins.Args[0].Kind != OpImm
}

func (c *arm64Ctx) lowerARM64SVEMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZMUL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 ZMUL does not accept an instruction suffix: %q", ins.Raw)
	}

	form := arm64RawSVEMultiply{}
	if len(ins.Args) == 4 {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
			return true, false, fmt.Errorf("arm64 ZMUL predicated expects Zm.T, Zdn.T, Pg.M, Zdn.T with identical destructive operands: %q", ins.Raw)
		}
		form = arm64RawSVEMultiply{mode: arm64SVEMultiplyPredicated, elementBits: firstBits, first: first, second: second, predicate: predicate, destination: destination}
	} else if len(ins.Args) == 3 && ins.Args[0].Kind == OpImm {
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		immediate := ins.Args[0].Imm
		if ins.Args[0].ImmRaw != "" || !firstOK || !destinationOK || first != destination || firstBits != destinationBits || immediate < -128 || immediate > 127 {
			return true, false, fmt.Errorf("arm64 ZMUL immediate expects a signed 8-bit value and identical Zdn.T operands: %q", ins.Raw)
		}
		form = arm64RawSVEMultiply{mode: arm64SVEMultiplyImmediate, elementBits: firstBits, first: first, immediate: int(immediate), destination: destination}
	} else if len(ins.Args) == 3 {
		if laneVector, laneBits, lane, laneOK := arm64ParseSVEZIndexedElementReg(ins.Args[0]); laneOK {
			first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
			destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
			if !firstOK || !destinationOK || laneBits != firstBits || firstBits != destinationBits {
				return true, false, fmt.Errorf("arm64 ZMUL lane operands must share H, S, or D width: %q", ins.Raw)
			}
			form = arm64RawSVEMultiply{mode: arm64SVEMultiplyLane, elementBits: firstBits, first: first, laneVector: laneVector, lane: lane, destination: destination}
		} else {
			second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
			first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
			destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
			if !secondOK || !firstOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits {
				return true, false, fmt.Errorf("arm64 ZMUL vector operands must share one element width: %q", ins.Raw)
			}
			form = arm64RawSVEMultiply{mode: arm64SVEMultiplyUnpredicated, elementBits: firstBits, first: first, second: second, destination: destination}
		}
	} else {
		return true, false, fmt.Errorf("arm64 ZMUL expects one of the six Go 1.27 SVE forms: %q", ins.Raw)
	}
	return true, false, c.lowerRawSVEMultiply(form)
}

func (c *arm64Ctx) lowerRawSVEMultiply(form arm64RawSVEMultiply) error {
	first, vectorType, err := c.loadZRegElements(form.first, form.elementBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(form.elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	switch form.mode {
	case arm64SVEMultiplyPredicated:
		second, _, err := c.loadZRegElements(form.second, form.elementBits)
		if err != nil {
			return err
		}
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.mul.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, lanes, form.elementBits, predicateType, predicate, vectorType, first, vectorType, second)
	case arm64SVEMultiplyUnpredicated:
		second, _, err := c.loadZRegElements(form.second, form.elementBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", result, vectorType, first, second)
	case arm64SVEMultiplyLane:
		laneVector, _, err := c.loadZRegElements(form.laneVector, form.elementBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.mul.lane.nxv%di%d(%s %s, %s %s, i32 %d)\n", result, vectorType, lanes, form.elementBits, vectorType, first, vectorType, laneVector, form.lane)
	case arm64SVEMultiplyImmediate:
		fmt.Fprintf(c.b, "  %%%s = mul %s %s, splat (i%d %d)\n", result, vectorType, first, form.elementBits, form.immediate)
	default:
		return fmt.Errorf("unknown ARM64 SVE MUL mode %d", form.mode)
	}
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
