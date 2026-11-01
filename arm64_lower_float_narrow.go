package plan9asm

import (
	"fmt"
	"strings"
)

type arm64RawVectorFloatNarrow struct {
	sourceBits  int
	upper       bool
	source      int
	destination int
}

func decodeARM64RawVectorFloatNarrow(word uint32) (arm64RawVectorFloatNarrow, bool) {
	if word&0xbfbffc00 != 0x0e216800 {
		return arm64RawVectorFloatNarrow{}, false
	}
	sourceBits := 32
	if word&(1<<22) != 0 {
		sourceBits = 64
	}
	return arm64RawVectorFloatNarrow{
		sourceBits:  sourceBits,
		upper:       word&(1<<30) != 0,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawVectorFloatNarrow(form arm64RawVectorFloatNarrow) error {
	return c.lowerARM64VectorFloatNarrowForm(form.sourceBits, form.upper,
		Reg(fmt.Sprintf("V%d", form.source)), Reg(fmt.Sprintf("V%d", form.destination)))
}

func (c *arm64Ctx) lowerARM64VectorFloatNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VFCVTN" && op != "VFCVTN2" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects Vsrc.S4/D2 and the corresponding narrow destination and no suffix: %q", op, ins.Raw)
	}
	source, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destination, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	wantDestinationLanes := source.lanes
	if op == "VFCVTN2" {
		wantDestinationLanes *= 2
	}
	validSource := sourceOK && ((source.elementBits == 32 && source.lanes == 4) || (source.elementBits == 64 && source.lanes == 2))
	if !validSource || !destinationOK || destination != (arm64VectorArrangement{elementBits: source.elementBits / 2, lanes: wantDestinationLanes}) {
		return true, false, fmt.Errorf("arm64 %s operand arrangements are outside Go 1.27's narrowing optab: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64VectorFloatNarrowForm(source.elementBits, op == "VFCVTN2", ins.Args[0].Reg, ins.Args[1].Reg)
}

func (c *arm64Ctx) lowerARM64VectorFloatNarrowForm(sourceBits int, upper bool, sourceReg, destinationReg Reg) error {
	destinationBits := sourceBits / 2
	sourceLanes := 128 / sourceBits
	sourceArrangement := arm64VectorArrangement{elementBits: sourceBits, lanes: sourceLanes}
	source, err := c.loadARM64VectorFloat(sourceReg, sourceArrangement)
	if err != nil {
		return err
	}
	sourceType, destinationType := "float", "half"
	if sourceBits == 64 {
		sourceType, destinationType = "double", "float"
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fptrunc <%d x %s> %s to <%d x %s>\n",
		converted, sourceLanes, sourceType, source, sourceLanes, destinationType)
	if !upper {
		return c.storeARM64VectorFloat(destinationReg,
			arm64VectorArrangement{elementBits: destinationBits, lanes: sourceLanes}, "%"+converted)
	}

	destinationArrangement := arm64VectorArrangement{elementBits: destinationBits, lanes: sourceLanes * 2}
	result, err := c.loadARM64VectorFloat(destinationReg, destinationArrangement)
	if err != nil {
		return err
	}
	for lane := 0; lane < sourceLanes; lane++ {
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %%%s, i32 %d\n", element, sourceLanes, destinationType, converted, lane)
		updated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> %s, %s %%%s, i32 %d\n",
			updated, sourceLanes*2, destinationType, result, destinationType, element, sourceLanes+lane)
		result = "%" + updated
	}
	return c.storeARM64VectorFloat(destinationReg, destinationArrangement, result)
}
