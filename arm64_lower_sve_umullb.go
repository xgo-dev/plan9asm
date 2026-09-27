package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64SVEUMULLBMode uint8

const (
	arm64SVEUMULLBVector arm64SVEUMULLBMode = iota
	arm64SVEUMULLBLane
)

type arm64RawSVEUMULLB struct {
	op          Op
	mode        arm64SVEUMULLBMode
	sourceBits  int
	first       int
	second      int
	laneVector  int
	lane        int
	destination int
}

type arm64SVEMultiplyLongSpec struct {
	intrinsic  string
	accumulate bool
	vectorBase uint32
	laneHBase  uint32
	laneSBase  uint32
}

var arm64SVEMultiplyLongSpecs = map[Op]arm64SVEMultiplyLongSpec{
	"ZSMULLB":    {intrinsic: "smullb", vectorBase: 0x45007000, laneHBase: 0x44a0c000, laneSBase: 0x44e0c000},
	"ZSMULLT":    {intrinsic: "smullt", vectorBase: 0x45007400, laneHBase: 0x44a0c400, laneSBase: 0x44e0c400},
	"ZUMULLB":    {intrinsic: "umullb", vectorBase: 0x45007800, laneHBase: 0x44a0d000, laneSBase: 0x44e0d000},
	"ZUMULLT":    {intrinsic: "umullt", vectorBase: 0x45007c00, laneHBase: 0x44a0d400, laneSBase: 0x44e0d400},
	"ZSQDMULLB":  {intrinsic: "sqdmullb", vectorBase: 0x45006000, laneHBase: 0x44a0e000, laneSBase: 0x44e0e000},
	"ZSQDMULLT":  {intrinsic: "sqdmullt", vectorBase: 0x45006400, laneHBase: 0x44a0e400, laneSBase: 0x44e0e400},
	"ZSQDMLALB":  {intrinsic: "sqdmlalb", accumulate: true, vectorBase: 0x44006000, laneHBase: 0x44a02000, laneSBase: 0x44e02000},
	"ZSQDMLALT":  {intrinsic: "sqdmlalt", accumulate: true, vectorBase: 0x44006400, laneHBase: 0x44a02400, laneSBase: 0x44e02400},
	"ZSQDMLALBT": {intrinsic: "sqdmlalbt", accumulate: true, vectorBase: 0x44000800},
	"ZSQDMLSLB":  {intrinsic: "sqdmlslb", accumulate: true, vectorBase: 0x44006800, laneHBase: 0x44a03000, laneSBase: 0x44e03000},
	"ZSQDMLSLT":  {intrinsic: "sqdmlslt", accumulate: true, vectorBase: 0x44006c00, laneHBase: 0x44a03400, laneSBase: 0x44e03400},
	"ZSQDMLSLBT": {intrinsic: "sqdmlslbt", accumulate: true, vectorBase: 0x44000c00},
}

var arm64SVEMultiplyLongOps = [...]Op{
	"ZSMULLB", "ZSMULLT", "ZUMULLB", "ZUMULLT",
	"ZSQDMULLB", "ZSQDMULLT",
	"ZSQDMLALB", "ZSQDMLALT", "ZSQDMLALBT",
	"ZSQDMLSLB", "ZSQDMLSLT", "ZSQDMLSLBT",
}

func decodeARM64RawSVEUMULLB(word uint32) (arm64RawSVEUMULLB, bool) {
	for _, op := range arm64SVEMultiplyLongOps {
		spec := arm64SVEMultiplyLongSpecs[op]
		form := arm64RawSVEUMULLB{op: op}
		switch {
		case word&0xff20fc00 == spec.vectorBase:
			size := int(word>>22) & 3
			if size == 0 {
				continue
			}
			form.mode = arm64SVEUMULLBVector
			form.sourceBits = 4 << size
			form.second = int(word>>16) & 31
		case spec.laneHBase != 0 && word&0xffe0f400 == spec.laneHBase:
			form.mode = arm64SVEUMULLBLane
			form.sourceBits = 16
			form.laneVector = int(word>>16) & 7
			form.lane = int(word>>11)&1 | (int(word>>19)&3)<<1
		case spec.laneSBase != 0 && word&0xffe0f400 == spec.laneSBase:
			form.mode = arm64SVEUMULLBLane
			form.sourceBits = 32
			form.laneVector = int(word>>16) & 15
			form.lane = int(word>>11)&1 | (int(word>>20)&1)<<1
		default:
			continue
		}
		form.first = int(word>>5) & 31
		form.destination = int(word) & 31
		return form, true
	}
	return arm64RawSVEUMULLB{}, false
}

func arm64ParseSVEUMULLBIndexedReg(operand Operand) (index, elementBits, lane int, ok bool) {
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
	elementBits, bitsOK := map[string]int{"H": 16, "S": 32}[name[dot+1:open]]
	lane, err = strconv.Atoi(name[open+1 : len(name)-1])
	if err != nil || !bitsOK {
		return 0, 0, 0, false
	}
	maxVector := map[int]int{16: 7, 32: 15}[elementBits]
	maxLane := map[int]int{16: 7, 32: 3}[elementBits]
	return index, elementBits, lane, index >= 0 && index <= maxVector && lane >= 0 && lane <= maxLane
}

func (c *arm64Ctx) lowerARM64SVEUMULLB(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEMultiplyLongSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one of its Go 1.27 SVE2 multiply-long forms: %q", op, ins.Raw)
	}
	form := arm64RawSVEUMULLB{op: op}
	if laneVector, laneBits, lane, laneOK := arm64ParseSVEUMULLBIndexedReg(ins.Args[0]); laneOK {
		if spec.laneHBase == 0 {
			return true, false, fmt.Errorf("arm64 %s has no indexed Go 1.27 form: %q", op, ins.Raw)
		}
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !firstOK || !destinationOK || firstBits != laneBits || destinationBits != 2*laneBits {
			return true, false, fmt.Errorf("arm64 %s indexed operands must widen H to S or S to D: %q", op, ins.Raw)
		}
		form = arm64RawSVEUMULLB{op: op, mode: arm64SVEUMULLBLane, sourceBits: firstBits, first: first, laneVector: laneVector, lane: lane, destination: destination}
	} else {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !secondOK || !firstOK || !destinationOK || secondBits != firstBits || firstBits == 64 || destinationBits != 2*firstBits {
			return true, false, fmt.Errorf("arm64 %s vector operands must widen B/H/S to H/S/D: %q", op, ins.Raw)
		}
		form = arm64RawSVEUMULLB{op: op, mode: arm64SVEUMULLBVector, sourceBits: firstBits, first: first, second: second, destination: destination}
	}
	return true, false, c.lowerRawSVEUMULLB(form)
}

func (c *arm64Ctx) lowerRawSVEUMULLB(form arm64RawSVEUMULLB) error {
	spec, ok := arm64SVEMultiplyLongSpecs[form.op]
	if !ok {
		return fmt.Errorf("unsupported ARM64 SVE2 multiply-long operation %s", form.op)
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
	destinationBits := form.sourceBits * 2
	destinationType, destinationLanes, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return err
	}
	var accumulator string
	if spec.accumulate {
		accumulator, _, err = c.loadZRegElements(form.destination, destinationBits)
		if err != nil {
			return err
		}
	}
	result := c.newTmp()
	if spec.accumulate {
		if form.mode == arm64SVEUMULLBVector {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, destinationType, spec.intrinsic, destinationLanes, destinationBits, destinationType, accumulator, sourceType, first, sourceType, second)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n", result, destinationType, spec.intrinsic, destinationLanes, destinationBits, destinationType, accumulator, sourceType, first, sourceType, second, form.lane)
		}
	} else if form.mode == arm64SVEUMULLBVector {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, destinationType, spec.intrinsic, destinationLanes, destinationBits, sourceType, first, sourceType, second)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%di%d(%s %s, %s %s, i32 %d)\n", result, destinationType, spec.intrinsic, destinationLanes, destinationBits, sourceType, first, sourceType, second, form.lane)
	}
	return c.storeZRegElements(form.destination, destinationBits, "%"+result)
}
