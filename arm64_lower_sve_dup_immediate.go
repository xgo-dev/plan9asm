package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64RawSVEDupImmediate struct {
	elementBits int
	immediate   int
	destination int
}

type arm64RawSVEDupElement struct {
	elementBits int
	lane        int
	source      int
	destination int
}

func decodeARM64RawSVEDupElement(word uint32) (arm64RawSVEDupElement, bool) {
	if word&0xffa0fc00 != 0x05202000 {
		return arm64RawSVEDupElement{}, false
	}
	imm5 := int(word>>16) & 31
	if imm5 == 0 {
		return arm64RawSVEDupElement{}, false
	}
	size := 0
	for imm5&(1<<size) == 0 {
		size++
	}
	if size > 4 {
		return arm64RawSVEDupElement{}, false
	}
	form := arm64RawSVEDupElement{
		elementBits: 8 << size,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}
	if size == 4 {
		if imm5 != 16 {
			return arm64RawSVEDupElement{}, false
		}
		form.lane = int(word>>22) & 1
	} else {
		if word&(1<<22) != 0 {
			return arm64RawSVEDupElement{}, false
		}
		form.lane = imm5 >> (size + 1)
	}
	return form, true
}

func decodeARM64RawSVEDupImmediate(word uint32) (arm64RawSVEDupImmediate, bool) {
	if word&0xff3fc000 != 0x2538c000 {
		return arm64RawSVEDupImmediate{}, false
	}
	elementBits := 8 << (int(word>>22) & 3)
	shift := 0
	if word&(1<<13) != 0 {
		shift = 8
	}
	// The byte element has no room for an LSL #8 immediate. LLVM and the Arm
	// architecture reject this encoding even though Go 1.27's generated
	// encoder does not correlate the shift bit with the element size.
	if elementBits == 8 && shift != 0 {
		return arm64RawSVEDupImmediate{}, false
	}
	immediate := int(int8(word >> 5))
	immediate <<= shift
	return arm64RawSVEDupImmediate{
		elementBits: elementBits,
		immediate:   immediate,
		destination: int(word) & 31,
	}, true
}

func arm64ParseSVEZElementReg(operand Operand) (index, elementBits int, ok bool) {
	if operand.Kind != OpReg {
		return 0, 0, false
	}
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(string(operand.Reg))), ".")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "Z") {
		return 0, 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(parts[0], "Z"))
	if err != nil || index < 0 || index > 31 {
		return 0, 0, false
	}
	elementBits, ok = map[string]int{"B": 8, "H": 16, "S": 32, "D": 64}[parts[1]]
	return index, elementBits, ok
}

func arm64SVEDupImmediateRepresentable(elementBits int, immediate int64) bool {
	if immediate >= -128 && immediate <= 127 {
		return true
	}
	if elementBits == 8 || immediate%256 != 0 {
		return false
	}
	unshifted := immediate / 256
	return unshifted >= -128 && unshifted <= 127
}

func arm64ParseSVEDupElementReg(operand Operand) (index, elementBits, lane int, ok bool) {
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
	if err != nil || index < 0 || index > 31 {
		return 0, 0, 0, false
	}
	elementBits, ok = map[string]int{"B": 8, "H": 16, "S": 32, "D": 64, "Q": 128}[name[dot+1:open]]
	lane, err = strconv.Atoi(name[open+1 : len(name)-1])
	if err != nil || !ok || lane < 0 || lane >= 256/elementBits {
		return 0, 0, 0, false
	}
	return index, elementBits, lane, true
}

func arm64ParseSVEDupDestination(operand Operand, allowQ bool) (index, elementBits int, ok bool) {
	if index, elementBits, ok = arm64ParseSVEZElementReg(operand); ok {
		return index, elementBits, true
	}
	if !allowQ || operand.Kind != OpReg {
		return 0, 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	if !strings.HasPrefix(name, "Z") || !strings.HasSuffix(name, ".Q") {
		return 0, 0, false
	}
	index, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "Z"), ".Q"))
	return index, 128, err == nil && index >= 0 && index <= 31
}

func arm64ParseSVEDupGeneralSource(operand Operand) (int, bool) {
	if operand.Kind != OpReg {
		return 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	if name == "SP" || name == "RSP" {
		return 31, true
	}
	if !strings.HasPrefix(name, "R") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(name, "R"))
	return index, err == nil && index >= 0 && index <= 30
}

func (c *arm64Ctx) lowerARM64SVEDupImmediate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZDUP" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 ZDUP expects one of Go 1.27's general, indexed-element, or immediate forms: %q", ins.Raw)
	}
	if source, validSource := arm64ParseSVEDupGeneralSource(ins.Args[0]); validSource {
		destination, elementBits, validDestination := arm64ParseSVEDupDestination(ins.Args[1], false)
		if !validDestination {
			return true, false, fmt.Errorf("arm64 ZDUP general expects Rn|RSP, Zd.B|H|S|D: %q", ins.Raw)
		}
		return true, false, c.lowerRawSVEDupGeneral(arm64RawSVEDupGeneral{elementBits: elementBits, source: source, destination: destination})
	}
	if source, elementBits, lane, validSource := arm64ParseSVEDupElementReg(ins.Args[0]); validSource {
		destination, destinationBits, validDestination := arm64ParseSVEDupDestination(ins.Args[1], true)
		if !validDestination || elementBits != destinationBits {
			return true, false, fmt.Errorf("arm64 ZDUP element expects Zn.T[index], Zd.T with matching B/H/S/D/Q: %q", ins.Raw)
		}
		return true, false, c.lowerRawSVEDupElement(arm64RawSVEDupElement{elementBits: elementBits, lane: lane, source: source, destination: destination})
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 ZDUP expects one of Go 1.27's general, indexed-element, or immediate forms: %q", ins.Raw)
	}
	destination, elementBits, valid := arm64ParseSVEZElementReg(ins.Args[1])
	if !valid || !arm64SVEDupImmediateRepresentable(elementBits, ins.Args[0].Imm) {
		return true, false, fmt.Errorf("arm64 ZDUP immediate is outside Go 1.27's SVE form: %q", ins.Raw)
	}
	return true, false, c.lowerRawSVEDupImmediate(arm64RawSVEDupImmediate{
		elementBits: elementBits,
		immediate:   int(ins.Args[0].Imm),
		destination: destination,
	})
}

func (c *arm64Ctx) lowerRawSVEDupElement(form arm64RawSVEDupElement) error {
	source, err := c.loadZReg(form.source)
	if err != nil {
		return err
	}
	if form.elementBits == 128 {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i8> @llvm.aarch64.sve.dupq.lane.nxv16i8(<vscale x 16 x i8> %s, i64 %d)\n", result, source, form.lane)
		return c.storeZReg(form.destination, "%"+result)
	}
	lanes := 128 / form.elementBits
	vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, form.elementBits)
	typedSource := source
	if form.elementBits != 8 {
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", converted, source, vectorType)
		typedSource = "%" + converted
	}
	element := c.newTmp()
	inserted := c.newTmp()
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i64 %d\n", element, vectorType, typedSource, form.lane)
	fmt.Fprintf(c.b, "  %%%s = insertelement %s poison, i%d %%%s, i64 0\n", inserted, vectorType, form.elementBits, element)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <vscale x %d x i32> zeroinitializer\n", splat, vectorType, inserted, vectorType, lanes)
	result := "%" + splat
	if form.elementBits != 8 {
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 16 x i8>\n", bytes, vectorType, result)
		result = "%" + bytes
	}
	return c.storeZReg(form.destination, result)
}

func (c *arm64Ctx) lowerRawSVEDupImmediate(form arm64RawSVEDupImmediate) error {
	lanes := 128 / form.elementBits
	vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, form.elementBits)
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s splat (i%d %d) to <vscale x 16 x i8>\n",
		bytes, vectorType, form.elementBits, form.immediate)
	return c.storeZReg(form.destination, "%"+bytes)
}
