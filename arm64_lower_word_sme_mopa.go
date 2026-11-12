package plan9asm

import "fmt"

type arm64RawSMEOuterProduct struct {
	op         string
	tile       int
	first      int
	second     int
	firstPred  int
	secondPred int
	sourceBits int
}

// These ZA.S and ZA.D forms share one register grammar. The fixed encodings come from
// LLVM 22's AArch64 SME assembler; only tile, Z, and governing P fields vary.
var arm64RawSMEOuterProductBases = map[uint32]struct {
	op         string
	sourceBits int
}{
	0x80800000: {"fmopa", 32},
	0x80c00000: {"fmopa", 64},
	0x81800000: {"bfmopa", 16},
	0xa0800000: {"smopa", 8},
	0xa0a00000: {"sumopa", 8},
	0xa1a00000: {"umopa", 8},
}

func decodeARM64RawSMEOuterProduct(word uint32) (arm64RawSMEOuterProduct, bool) {
	const variableFields = uint32(0x001fffe3)
	spec, ok := arm64RawSMEOuterProductBases[word&^variableFields]
	if !ok {
		return arm64RawSMEOuterProduct{}, false
	}
	return arm64RawSMEOuterProduct{
		op:         spec.op,
		tile:       int(word) & 3,
		first:      int(word>>5) & 31,
		second:     int(word>>16) & 31,
		firstPred:  int(word>>10) & 7,
		secondPred: int(word>>13) & 7,
		sourceBits: spec.sourceBits,
	}, true
}

func (c *arm64Ctx) lowerRawSMEOuterProduct(form arm64RawSMEOuterProduct) error {
	firstPred, _, err := c.loadPRegElements(form.firstPred, form.sourceBits)
	if err != nil {
		return err
	}
	secondPred, _, err := c.loadPRegElements(form.secondPred, form.sourceBits)
	if err != nil {
		return err
	}
	firstType := "<vscale x 16 x i8>"
	firstValue := ""
	secondValue := ""
	if form.sourceBits == 8 {
		firstValue, err = c.loadZReg(form.first)
		if err != nil {
			return err
		}
		secondValue, err = c.loadZReg(form.second)
		if err != nil {
			return err
		}
	} else if form.sourceBits == 16 {
		firstValue, firstType, err = c.loadZRegElements(form.first, 16)
		if err != nil {
			return err
		}
		secondValue, _, err = c.loadZRegElements(form.second, 16)
		if err != nil {
			return err
		}
	} else {
		firstValue, firstType, err = c.loadRawSVEFloatVector(form.first, form.sourceBits)
		if err != nil {
			return err
		}
		secondValue, _, err = c.loadRawSVEFloatVector(form.second, form.sourceBits)
		if err != nil {
			return err
		}
	}
	width := "b"
	outputWidth := "s"
	if form.sourceBits == 16 {
		width = "h"
	} else if form.sourceBits == 32 {
		width = "s"
	} else if form.sourceBits == 64 {
		width = "d"
		outputWidth = "d"
	}
	assembly := fmt.Sprintf("%s za%d.%s, $0/m, $1/m, $2.%s, $3.%s",
		form.op, form.tile, outputWidth, width, width)
	predicateType := fmt.Sprintf("<vscale x %d x i1>", 128/form.sourceBits)
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s, %s %s, %s %s, %s %s)\n",
		assembly, "@3Upl,@3Upl,w,w,~{memory}",
		predicateType, firstPred, predicateType, secondPred,
		firstType, firstValue, firstType, secondValue)
	return nil
}

type arm64RawSMETileRead struct {
	bits        int
	destination int
	predicate   int
	row         int
	tile        int
	index       int
	vertical    bool
}

func decodeARM64RawSMETileRead(word uint32) (arm64RawSMETileRead, bool) {
	const variableFields = uint32(0x00c0fdff)
	if word&^variableFields != 0xc0020000 {
		return arm64RawSMETileRead{}, false
	}
	return decodeARM64RawSMETileFields(word, false), true
}

func decodeARM64RawSMETileWrite(word uint32) (arm64RawSMETileRead, bool) {
	const variableFields = uint32(0x00c0ffef)
	if word&^variableFields != 0xc0000000 {
		return arm64RawSMETileRead{}, false
	}
	return decodeARM64RawSMETileFields(word, true), true
}

func decodeARM64RawSMETileFields(word uint32, write bool) arm64RawSMETileRead {
	bits := 8 << (word >> 22 & 3)
	indexBits := 0
	for count := 128 / bits; count > 1; count >>= 1 {
		indexBits++
	}
	indexMask := (1 << indexBits) - 1
	indexAndTile := int(word>>5) & 15
	vector := int(word) & 31
	if write {
		indexAndTile = int(word) & 15
		vector = int(word>>5) & 31
	}
	return arm64RawSMETileRead{
		bits:        int(bits),
		destination: vector,
		predicate:   int(word>>10) & 7,
		row:         12 + int(word>>13&3),
		tile:        indexAndTile >> indexBits,
		index:       indexAndTile & indexMask,
		vertical:    word&(1<<15) != 0,
	}
}

func (c *arm64Ctx) lowerRawSMETileRead(form arm64RawSMETileRead) error {
	old, vectorType, err := c.loadZRegElements(form.destination, form.bits)
	if err != nil {
		return err
	}
	predicate, err := c.loadPReg(form.predicate)
	if err != nil {
		return err
	}
	row, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.row)))
	if err != nil {
		return err
	}
	width := map[int]string{8: "b", 16: "h", 32: "s", 64: "d"}[form.bits]
	direction := "h"
	if form.vertical {
		direction = "v"
	}
	assembly := fmt.Sprintf("mov w12, ${3:w}; mov $0.%s, $2/m, za%d%s.%s[w12, %d]",
		width, form.tile, direction, width, form.index)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, <vscale x 16 x i1> %s, i64 %s)\n",
		result, vectorType, assembly, "=w,0,@3Upl,r,~{memory},~{x12}",
		vectorType, old, predicate, row)
	return c.storeZRegElements(form.destination, form.bits, "%"+result)
}

func (c *arm64Ctx) lowerRawSMETileWrite(form arm64RawSMETileRead) error {
	vector, vectorType, err := c.loadZRegElements(form.destination, form.bits)
	if err != nil {
		return err
	}
	predicate, err := c.loadPReg(form.predicate)
	if err != nil {
		return err
	}
	row, err := c.loadReg(Reg(fmt.Sprintf("R%d", form.row)))
	if err != nil {
		return err
	}
	width := map[int]string{8: "b", 16: "h", 32: "s", 64: "d"}[form.bits]
	direction := "h"
	if form.vertical {
		direction = "v"
	}
	assembly := fmt.Sprintf("mov w12, ${2:w}; mov za%d%s.%s[w12, %d], $0/m, $1.%s",
		form.tile, direction, width, form.index, width)
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(<vscale x 16 x i1> %s, %s %s, i64 %s)\n",
		assembly, "@3Upl,w,r,~{memory},~{x12}", predicate, vectorType, vector, row)
	return nil
}
