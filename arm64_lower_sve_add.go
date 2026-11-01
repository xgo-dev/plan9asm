package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64SVEAddMode uint8

const (
	arm64SVEAddUnpredicated arm64SVEAddMode = iota
	arm64SVEAddPredicated
	arm64SVEAddImmediate
)

type arm64RawSVEAdd struct {
	mode        arm64SVEAddMode
	elementBits int
	first       int
	second      int
	predicate   int
	immediate   int
	destination int
}

func decodeARM64RawSVEAdd(word uint32) (arm64RawSVEAdd, bool) {
	form := arm64RawSVEAdd{elementBits: 8 << (int(word>>22) & 3)}
	switch {
	case word&0xff3fe000 == 0x04000000:
		form.mode = arm64SVEAddPredicated
		form.destination = int(word) & 31
		form.first = form.destination
		form.second = int(word>>5) & 31
		form.predicate = int(word>>10) & 7
	case word&0xff20fc00 == 0x04200000:
		form.mode = arm64SVEAddUnpredicated
		form.destination = int(word) & 31
		form.first = int(word>>5) & 31
		form.second = int(word>>16) & 31
	case word&0xff3fc000 == 0x2520c000:
		form.mode = arm64SVEAddImmediate
		form.destination = int(word) & 31
		form.first = form.destination
		shift := 0
		if word&(1<<13) != 0 {
			shift = 8
		}
		if form.elementBits == 8 && shift != 0 {
			return arm64RawSVEAdd{}, false
		}
		form.immediate = (int(word>>5) & 255) << shift
	default:
		return arm64RawSVEAdd{}, false
	}
	return form, true
}

func arm64ParseSVEPredicateMerge(operand Operand) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(string(operand.Reg))), ".")
	if len(parts) != 2 || parts[1] != "M" || !strings.HasPrefix(parts[0], "P") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(parts[0], "P"))
	return index, err == nil && index >= 0 && index < 8
}

func arm64SVEAddImmediateRepresentable(elementBits int, immediate int64) bool {
	if immediate >= 0 && immediate <= 255 {
		return true
	}
	if elementBits == 8 || immediate%256 != 0 {
		return false
	}
	unshifted := immediate / 256
	return unshifted >= 0 && unshifted <= 255
}

func (c *arm64Ctx) lowerARM64SVEAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZADD" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 ZADD does not accept an instruction suffix: %q", ins.Raw)
	}

	form := arm64RawSVEAdd{}
	if len(ins.Args) == 3 && ins.Args[0].Kind == OpImm {
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if ins.Args[0].ImmRaw != "" || !firstOK || !destinationOK || first != destination || firstBits != destinationBits || !arm64SVEAddImmediateRepresentable(firstBits, ins.Args[0].Imm) {
			return true, false, fmt.Errorf("arm64 ZADD immediate expects $imm, Zdn.T, Zdn.T with identical destructive registers: %q", ins.Raw)
		}
		form = arm64RawSVEAdd{mode: arm64SVEAddImmediate, elementBits: firstBits, first: first, destination: destination, immediate: int(ins.Args[0].Imm)}
	} else if len(ins.Args) == 3 {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !secondOK || !firstOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits {
			return true, false, fmt.Errorf("arm64 ZADD vector expects Zm.T, Zn.T, Zd.T with one element width: %q", ins.Raw)
		}
		form = arm64RawSVEAdd{mode: arm64SVEAddUnpredicated, elementBits: firstBits, first: first, second: second, destination: destination}
	} else if len(ins.Args) == 4 {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
			return true, false, fmt.Errorf("arm64 ZADD predicated expects Zm.T, Zdn.T, Pg.M, Zdn.T with identical destructive registers: %q", ins.Raw)
		}
		form = arm64RawSVEAdd{mode: arm64SVEAddPredicated, elementBits: firstBits, first: first, second: second, predicate: predicate, destination: destination}
	} else {
		return true, false, fmt.Errorf("arm64 ZADD expects a Go 1.27 SVE vector, predicated, or immediate form: %q", ins.Raw)
	}
	return true, false, c.lowerRawSVEAdd(form)
}

func (c *arm64Ctx) lowerRawSVEAdd(form arm64RawSVEAdd) error {
	first, vectorType, err := c.loadZRegElements(form.first, form.elementBits)
	if err != nil {
		return err
	}
	second := fmt.Sprintf("splat (i%d %d)", form.elementBits, form.immediate)
	if form.mode != arm64SVEAddImmediate {
		second, _, err = c.loadZRegElements(form.second, form.elementBits)
		if err != nil {
			return err
		}
	}
	added := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", added, vectorType, first, second)
	result := "%" + added
	if form.mode == arm64SVEAddPredicated {
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
