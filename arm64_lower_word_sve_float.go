package plan9asm

import "fmt"

type arm64RawSVEFloatKind uint8

const (
	arm64RawSVEFloatAdd arm64RawSVEFloatKind = iota
	arm64RawSVEFloatSub
	arm64RawSVEFloatMul
	arm64RawSVEFloatFADDV
	arm64RawSVEFloatFADDA
	arm64RawSVEFloatSubReverse
)

type arm64RawSVEFloat struct {
	kind         arm64RawSVEFloatKind
	elementBits  int
	destination  int
	first        int
	second       int
	predicate    int
	predicated   bool
	immediate    float64
	hasImmediate bool
	lane         int
	hasLane      bool
}

func (c *arm64Ctx) loadRawSVEFloatVector(index, elementBits int) (string, string, error) {
	bytes, err := c.loadZReg(index)
	if err != nil {
		return "", "", err
	}
	floatingType := map[int]string{16: "half", 32: "float", 64: "double"}[elementBits]
	if floatingType == "" {
		return "", "", fmt.Errorf("unsupported ARM64 SVE floating element width %d", elementBits)
	}
	vectorType := fmt.Sprintf("<vscale x %d x %s>", 128/elementBits, floatingType)
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", converted, bytes, vectorType)
	return "%" + converted, vectorType, nil
}

func (c *arm64Ctx) storeRawSVEFloatVector(index, elementBits int, value string, vectorType string) error {
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 16 x i8>\n", bytes, vectorType, value)
	return c.storeZReg(index, "%"+bytes)
}

// decodeARM64RawSVEFloat covers the scalar-vector SVE floating arithmetic
// encodings emitted by Go's generated assembly. The destructive predicated
// forms keep Zd as their first operand. FMA has its own complete decoder;
// never let a relaxed arithmetic mask consume a neighboring opcode family.
func decodeARM64RawSVEFloat(word uint32) (arm64RawSVEFloat, bool) {
	if form, ok := decodeARM64RawSVEFloatArithmetic(word); ok {
		return form, true
	}
	form := arm64RawSVEFloat{elementBits: 8 << (int(word>>22) & 3)}
	if form.elementBits == 8 {
		return arm64RawSVEFloat{}, false
	}
	switch {
	case word&0xff20e000 == 0x65002000:
		form.destination = int(word) & 31
		form.predicate = int(word>>10) & 7
		if word&0x001f0000 == 0 {
			form.kind = arm64RawSVEFloatFADDV
			form.first = int(word>>5) & 31
		} else if word&0x001f0000 == 0x00180000 {
			form.kind = arm64RawSVEFloatFADDA
			form.first = int(word>>5) & 31
		} else {
			return arm64RawSVEFloat{}, false
		}
	default:
		return arm64RawSVEFloat{}, false
	}
	return form, true
}

func (c *arm64Ctx) lowerRawSVEFloat(form arm64RawSVEFloat) error {
	// Raw bytes and named syntax must share semantics, including predicate
	// merging, exact reduction order, and scalar destination lane clearing.
	if form.kind == arm64RawSVEFloatFADDV || form.kind == arm64RawSVEFloatFADDA {
		kind := arm64SVEFloatAddReduce
		if form.kind == arm64RawSVEFloatFADDA {
			kind = arm64SVEFloatAddAccumulate
		}
		return c.lowerARM64SVEAddReductionForm(
			arm64SVEAddReductionSpec{kind: kind, elementBits: form.elementBits},
			arm64SVEAddReductionForm{elementBits: form.elementBits, source: form.first,
				predicate: form.predicate, destination: form.destination},
			Reg(fmt.Sprintf("V%d", form.destination)))
	}

	first, second := form.first, form.second
	if form.predicated {
		first, second = form.destination, form.first
	}
	if form.kind == arm64RawSVEFloatMul {
		return c.lowerARM64SVEFloatMultiplyForm(arm64SVEFloatMultiplyForm{
			elementBits: form.elementBits, first: first, second: second,
			predicate: form.predicate, destination: form.destination, predicated: form.predicated,
			immediate: form.immediate, hasImmediate: form.hasImmediate,
			laneVector: second, lane: form.lane, hasLane: form.hasLane,
		})
	}
	op := Op("ZFADD")
	if form.kind == arm64RawSVEFloatSub {
		op = "ZFSUB"
	} else if form.kind == arm64RawSVEFloatSubReverse {
		op = "ZFSUBR"
	}
	return c.lowerARM64SVEFloatAddSubForm(arm64SVEFloatAddSubSpecs[op], arm64SVEFloatAddSubForm{
		elementBits: form.elementBits, first: first, second: second,
		predicate: form.predicate, destination: form.destination, predicated: form.predicated,
		immediate: form.immediate, hasImmediate: form.hasImmediate,
	})
}
