package plan9asm

import (
	"fmt"
	"strings"
)

type arm64RawSVEMultiplyAccumulateLong struct {
	op          Op
	mode        arm64SVEUMULLBMode
	sourceBits  int
	first       int
	second      int
	laneVector  int
	lane        int
	destination int
}

var arm64SVEMultiplyAccumulateLongIntrinsics = map[Op]string{
	"ZSMLALB": "smlalb",
	"ZSMLALT": "smlalt",
	"ZUMLALB": "umlalb",
	"ZUMLALT": "umlalt",
	"ZSMLSLB": "smlslb",
	"ZSMLSLT": "smlslt",
	"ZUMLSLB": "umlslb",
	"ZUMLSLT": "umlslt",
}

var arm64SVEMultiplyAccumulateLongOpsBySelector = [...]Op{
	"ZSMLALB", "ZSMLALT", "ZUMLALB", "ZUMLALT",
	"ZSMLSLB", "ZSMLSLT", "ZUMLSLB", "ZUMLSLT",
}

// decodeARM64RawSVEMultiplyAccumulateLong covers all SVE2 signed/unsigned
// multiply-add/subtract-long bottom/top vector and indexed forms emitted by the
// Go 1.27 ARM64 assembler.
func decodeARM64RawSVEMultiplyAccumulateLong(word uint32) (arm64RawSVEMultiplyAccumulateLong, bool) {
	form := arm64RawSVEMultiplyAccumulateLong{}
	switch {
	case word&0xff20e000 == 0x44004000:
		size := int(word>>22) & 3
		if size == 0 {
			return arm64RawSVEMultiplyAccumulateLong{}, false
		}
		form.mode = arm64SVEUMULLBVector
		form.sourceBits = 4 << size
		form.second = int(word>>16) & 31
		form.op = arm64SVEMultiplyAccumulateLongOpsBySelector[int(word>>10)&7]
	case word&0xffe0c000 == 0x44a08000:
		form.mode = arm64SVEUMULLBLane
		form.sourceBits = 16
		form.laneVector = int(word>>16) & 7
		form.lane = int(word>>11)&1 | (int(word>>19)&3)<<1
		selector := int(word>>10)&1 | (int(word>>12)&3)<<1
		form.op = arm64SVEMultiplyAccumulateLongOpsBySelector[selector]
	case word&0xffe0c000 == 0x44e08000:
		form.mode = arm64SVEUMULLBLane
		form.sourceBits = 32
		form.laneVector = int(word>>16) & 15
		form.lane = int(word>>11)&1 | (int(word>>20)&1)<<1
		selector := int(word>>10)&1 | (int(word>>12)&3)<<1
		form.op = arm64SVEMultiplyAccumulateLongOpsBySelector[selector]
	default:
		return arm64RawSVEMultiplyAccumulateLong{}, false
	}
	form.first = int(word>>5) & 31
	form.destination = int(word) & 31
	return form, true
}

func (c *arm64Ctx) lowerARM64SVEMultiplyAccumulateLong(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, ok := arm64SVEMultiplyAccumulateLongIntrinsics[op]; !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one of the five Go 1.27 SVE2 forms: %q", op, ins.Raw)
	}
	form := arm64RawSVEMultiplyAccumulateLong{op: op}
	if laneVector, laneBits, lane, laneOK := arm64ParseSVEUMULLBIndexedReg(ins.Args[0]); laneOK {
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !firstOK || !destinationOK || firstBits != laneBits || destinationBits != 2*laneBits {
			return true, false, fmt.Errorf("arm64 %s indexed operands must widen H to S or S to D: %q", op, ins.Raw)
		}
		form.mode = arm64SVEUMULLBLane
		form.sourceBits = firstBits
		form.first = first
		form.laneVector = laneVector
		form.lane = lane
		form.destination = destination
	} else {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !secondOK || !firstOK || !destinationOK || secondBits != firstBits || firstBits == 64 || destinationBits != 2*firstBits {
			return true, false, fmt.Errorf("arm64 %s vector operands must widen B/H/S to H/S/D: %q", op, ins.Raw)
		}
		form.mode = arm64SVEUMULLBVector
		form.sourceBits = firstBits
		form.first = first
		form.second = second
		form.destination = destination
	}
	return true, false, c.lowerRawSVEMultiplyAccumulateLong(form)
}

func (c *arm64Ctx) lowerRawSVEMultiplyAccumulateLong(form arm64RawSVEMultiplyAccumulateLong) error {
	intrinsic, ok := arm64SVEMultiplyAccumulateLongIntrinsics[form.op]
	if !ok {
		return fmt.Errorf("unsupported ARM64 SVE2 multiply-accumulate-long operation %s", form.op)
	}
	destinationBits := form.sourceBits * 2
	accumulator, destinationType, err := c.loadZRegElements(form.destination, destinationBits)
	if err != nil {
		return err
	}
	first, sourceType, err := c.loadZRegElements(form.first, form.sourceBits)
	if err != nil {
		return err
	}
	secondIndex := form.second
	if form.mode == arm64SVEUMULLBLane {
		secondIndex = form.laneVector
	}
	second, _, err := c.loadZRegElements(secondIndex, form.sourceBits)
	if err != nil {
		return err
	}
	_, destinationLanes, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.mode == arm64SVEUMULLBVector {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, destinationType, intrinsic, destinationLanes, destinationBits, destinationType, accumulator, sourceType, first, sourceType, second)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n", result, destinationType, intrinsic, destinationLanes, destinationBits, destinationType, accumulator, sourceType, first, sourceType, second, form.lane)
	}
	return c.storeZRegElements(form.destination, destinationBits, "%"+result)
}
