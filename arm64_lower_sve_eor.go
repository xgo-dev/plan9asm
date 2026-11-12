package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
)

type arm64SVEEORMode uint8

const (
	arm64SVEEORUnpredicated arm64SVEEORMode = iota
	arm64SVEEORPredicated
	arm64SVEEORImmediate
)

type arm64RawSVEEOR struct {
	op          Op
	mode        arm64SVEEORMode
	elementBits int
	first       int
	second      int
	predicate   int
	immediate   uint64
	destination int
}

func decodeARM64SVELogicalImmediate(imm13 int) (elementBits int, immediate uint64, ok bool) {
	n := (imm13 >> 12) & 1
	immr := (imm13 >> 6) & 63
	imms := imm13 & 63
	lengthSource := n<<6 | (^imms & 63)
	length := bits.Len(uint(lengthSource)) - 1
	if length < 1 {
		return 0, 0, false
	}
	esize := 1 << length
	levels := esize - 1
	s := imms & levels
	if s == levels {
		return 0, 0, false
	}
	r := immr & levels
	ones := s + 1
	pattern := (uint64(1) << ones) - 1
	mask := ^uint64(0)
	if esize < 64 {
		mask = (uint64(1) << esize) - 1
	}
	pattern = ((pattern >> r) | (pattern << (esize - r))) & mask
	elementBits = esize
	if elementBits < 8 {
		elementBits = 8
	}
	for offset := esize; offset < elementBits; offset += esize {
		immediate |= pattern << offset
	}
	immediate |= pattern
	return elementBits, immediate, true
}

func decodeARM64RawSVEEOR(word uint32) (arm64RawSVEEOR, bool) {
	form := arm64RawSVEEOR{}
	switch {
	case word&0xffe0fc00 == 0x04203000:
		form.op = "ZAND"
		form.mode = arm64SVEEORUnpredicated
		form.elementBits = 64
		form.second = int(word>>16) & 31
		form.first = int(word>>5) & 31
		form.destination = int(word) & 31
	case word&0xffe0fc00 == 0x04603000:
		form.op = "ZORR"
		form.mode = arm64SVEEORUnpredicated
		form.elementBits = 64
		form.second = int(word>>16) & 31
		form.first = int(word>>5) & 31
		form.destination = int(word) & 31
	case word&0xffe0fc00 == 0x04a03000:
		form.op = "ZEOR"
		form.mode = arm64SVEEORUnpredicated
		form.elementBits = 64
		form.second = int(word>>16) & 31
		form.first = int(word>>5) & 31
		form.destination = int(word) & 31
	case word&0xffe0fc00 == 0x04e03000:
		form.op = "ZBIC"
		form.mode = arm64SVEEORUnpredicated
		form.elementBits = 64
		form.second = int(word>>16) & 31
		form.first = int(word>>5) & 31
		form.destination = int(word) & 31
	case word&0xff3fe000 == 0x04180000:
		form.op = "ZORR"
		form.mode = arm64SVEEORPredicated
		form.elementBits = 8 << (int(word>>22) & 3)
		form.destination = int(word) & 31
		form.first = form.destination
		form.second = int(word>>5) & 31
		form.predicate = int(word>>10) & 7
	case word&0xff3fe000 == 0x04190000:
		form.op = "ZEOR"
		form.mode = arm64SVEEORPredicated
		form.elementBits = 8 << (int(word>>22) & 3)
		form.destination = int(word) & 31
		form.first = form.destination
		form.second = int(word>>5) & 31
		form.predicate = int(word>>10) & 7
	case word&0xff3fe000 == 0x041a0000:
		form.op = "ZAND"
		form.mode = arm64SVEEORPredicated
		form.elementBits = 8 << (int(word>>22) & 3)
		form.destination = int(word) & 31
		form.first = form.destination
		form.second = int(word>>5) & 31
		form.predicate = int(word>>10) & 7
	case word&0xff3fe000 == 0x041b0000:
		form.op = "ZBIC"
		form.mode = arm64SVEEORPredicated
		form.elementBits = 8 << (int(word>>22) & 3)
		form.destination = int(word) & 31
		form.first = form.destination
		form.second = int(word>>5) & 31
		form.predicate = int(word>>10) & 7
	case word&0xfffc0000 == 0x05000000:
		form.op = "ZORR"
		form.mode = arm64SVEEORImmediate
		var ok bool
		form.elementBits, form.immediate, ok = decodeARM64SVELogicalImmediate(int(word>>5) & 0x1fff)
		if !ok {
			return arm64RawSVEEOR{}, false
		}
		form.destination = int(word) & 31
		form.first = form.destination
	case word&0xfffc0000 == 0x05400000:
		form.op = "ZEOR"
		form.mode = arm64SVEEORImmediate
		var ok bool
		form.elementBits, form.immediate, ok = decodeARM64SVELogicalImmediate(int(word>>5) & 0x1fff)
		if !ok {
			return arm64RawSVEEOR{}, false
		}
		form.destination = int(word) & 31
		form.first = form.destination
	case word&0xfffc0000 == 0x05800000:
		form.op = "ZAND"
		form.mode = arm64SVEEORImmediate
		var ok bool
		form.elementBits, form.immediate, ok = decodeARM64SVELogicalImmediate(int(word>>5) & 0x1fff)
		if !ok {
			return arm64RawSVEEOR{}, false
		}
		form.destination = int(word) & 31
		form.first = form.destination
	default:
		return arm64RawSVEEOR{}, false
	}
	return form, true
}

func arm64SVEMaskForBits(elementBits int) uint64 {
	if elementBits == 64 {
		return ^uint64(0)
	}
	return (uint64(1) << elementBits) - 1
}

func arm64SVEReplicateImmediate(value uint64, fromBits, toBits int) uint64 {
	value &= arm64SVEMaskForBits(fromBits)
	result := uint64(0)
	for offset := 0; offset < toBits; offset += fromBits {
		result |= value << offset
	}
	return result & arm64SVEMaskForBits(toBits)
}

func arm64SVELogicalImmediateRepresentable(elementBits int, value uint64) bool {
	value &= arm64SVEMaskForBits(elementBits)
	if value == 0 || value == arm64SVEMaskForBits(elementBits) {
		return false
	}
	for imm13 := 0; imm13 < 1<<13; imm13++ {
		encodedBits, encodedValue, ok := decodeARM64SVELogicalImmediate(imm13)
		if ok && encodedBits <= elementBits && arm64SVEReplicateImmediate(encodedValue, encodedBits, elementBits) == value {
			return true
		}
	}
	return false
}

func (c *arm64Ctx) lowerARM64SVEEOR(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZAND" && op != "ZBIC" && op != "ZEOR" && op != "ZORR" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	form := arm64RawSVEEOR{}
	if len(ins.Args) == 3 && ins.Args[0].Kind == OpImm {
		if op == "ZBIC" {
			return true, false, fmt.Errorf("arm64 ZBIC has no immediate form in Go 1.27: %q", ins.Raw)
		}
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		immediate := uint64(ins.Args[0].Imm)
		if ins.Args[0].ImmRaw != "" || !firstOK || !destinationOK || first != destination || firstBits != destinationBits || !arm64SVELogicalImmediateRepresentable(firstBits, immediate) {
			return true, false, fmt.Errorf("arm64 %s immediate expects a Go logical bitmask and identical Zdn.T operands: %q", op, ins.Raw)
		}
		form = arm64RawSVEEOR{op: op, mode: arm64SVEEORImmediate, elementBits: firstBits, first: first, immediate: immediate & arm64SVEMaskForBits(firstBits), destination: destination}
	} else if len(ins.Args) == 3 {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !secondOK || !firstOK || !destinationOK || secondBits != 64 || firstBits != 64 || destinationBits != 64 {
			return true, false, fmt.Errorf("arm64 %s unpredicated form requires three .D vectors: %q", op, ins.Raw)
		}
		form = arm64RawSVEEOR{op: op, mode: arm64SVEEORUnpredicated, elementBits: 64, first: first, second: second, destination: destination}
	} else if len(ins.Args) == 4 {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
			return true, false, fmt.Errorf("arm64 %s predicated form requires one width and identical destructive operands: %q", op, ins.Raw)
		}
		form = arm64RawSVEEOR{op: op, mode: arm64SVEEORPredicated, elementBits: firstBits, first: first, second: second, predicate: predicate, destination: destination}
	} else {
		return true, false, fmt.Errorf("arm64 %s expects a Go 1.27 SVE logical form: %q", op, ins.Raw)
	}
	return true, false, c.lowerRawSVEEOR(form)
}

func (c *arm64Ctx) lowerRawSVEEOR(form arm64RawSVEEOR) error {
	first, vectorType, err := c.loadZRegElements(form.first, form.elementBits)
	if err != nil {
		return err
	}
	second := fmt.Sprintf("splat (i%d %d)", form.elementBits, form.immediate)
	if form.mode != arm64SVEEORImmediate {
		second, _, err = c.loadZRegElements(form.second, form.elementBits)
		if err != nil {
			return err
		}
	}
	llvmOp := "xor"
	if form.op == "ZAND" || form.op == "ZBIC" {
		llvmOp = "and"
	} else if form.op == "ZORR" {
		llvmOp = "or"
	}
	if form.op == "ZBIC" {
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, splat (i%d -1)\n", inverted, vectorType, second, form.elementBits)
		second = "%" + inverted
	}
	calculated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", calculated, llvmOp, vectorType, first, second)
	result := "%" + calculated
	if form.mode == arm64SVEEORPredicated {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", selected, predicateType, predicate, vectorType, result, vectorType, first)
		result = "%" + selected
	}
	return c.storeZRegElements(form.destination, form.elementBits, result)
}
