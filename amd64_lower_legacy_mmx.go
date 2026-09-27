package plan9asm

import (
	"fmt"
	"strings"
)

type amd64LegacyMMXOperandClass uint8

const (
	amd64LegacyMMXMMX amd64LegacyMMXOperandClass = 1 << iota
	amd64LegacyMMXXMM
	amd64LegacyMMXMemory
)

type amd64LegacyMMXMoveSpec struct {
	source       amd64LegacyMMXOperandClass
	destination  amd64LegacyMMXOperandClass
	transferBits int
	zeroExtend   bool
	nonTemporal  bool
}

// amd64LegacyMMXMoveSpecs describes the complete Go 1.27 legacy cross-domain
// and non-temporal MMX move grammar. Operand classes and transfer semantics are
// data; one parser validates all four opcode spellings.
var amd64LegacyMMXMoveSpecs = map[Op]amd64LegacyMMXMoveSpec{
	"MOVQOZX": {source: amd64LegacyMMXMMX | amd64LegacyMMXXMM | amd64LegacyMMXMemory, destination: amd64LegacyMMXXMM, transferBits: 64, zeroExtend: true},
	"MOVDQ2Q": {source: amd64LegacyMMXXMM, destination: amd64LegacyMMXMMX, transferBits: 64},
	"MOVNTQ":  {source: amd64LegacyMMXMMX, destination: amd64LegacyMMXMemory, transferBits: 64, nonTemporal: true},
	"MOVNTDQ": {source: amd64LegacyMMXXMM, destination: amd64LegacyMMXMemory, transferBits: 128, nonTemporal: true},
}

type amd64LegacyMMXMoveForm struct {
	source      Operand
	destination Operand
}

func (c *amd64Ctx) lowerLegacyMMXMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64LegacyMMXMoveSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	form, err := c.parseLegacyMMXMoveForm(baseOp, spec, ins)
	if err != nil {
		return true, false, err
	}
	return c.emitLegacyMMXMove(spec, form)
}

func (c *amd64Ctx) parseLegacyMMXMoveForm(op string, spec amd64LegacyMMXMoveSpec, ins Instr) (amd64LegacyMMXMoveForm, error) {
	var form amd64LegacyMMXMoveForm
	if len(ins.Args) != 2 {
		return form, fmt.Errorf("%s %s expects exactly two operands: %q", c.goarch, op, ins.Raw)
	}
	sourceClass := c.legacyMMXOperandClass(ins.Args[0])
	destinationClass := c.legacyMMXOperandClass(ins.Args[1])
	if sourceClass&spec.source == 0 || destinationClass&spec.destination == 0 {
		return form, fmt.Errorf("%s %s operands are outside its Go 1.27 legacy MMX table: %q", c.goarch, op, ins.Raw)
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpMem && !x86MemoryRegistersValidForArch(operand.Mem, c.goarch) {
			return form, fmt.Errorf("%s %s memory address uses an out-of-range register: %q", c.goarch, op, ins.Raw)
		}
	}
	return amd64LegacyMMXMoveForm{source: ins.Args[0], destination: ins.Args[1]}, nil
}

func (c *amd64Ctx) legacyMMXOperandClass(operand Operand) amd64LegacyMMXOperandClass {
	if operand.Kind == OpReg {
		if _, ok := amd64ParseMReg(operand.Reg); ok {
			return amd64LegacyMMXMMX
		}
		if c.isGoLegacyXReg(operand.Reg) {
			return amd64LegacyMMXXMM
		}
		return 0
	}
	if isAMD64MemoryOperand(operand) {
		return amd64LegacyMMXMemory
	}
	return 0
}

func (c *amd64Ctx) emitLegacyMMXMove(spec amd64LegacyMMXMoveSpec, form amd64LegacyMMXMoveForm) (bool, bool, error) {
	if spec.destination == amd64LegacyMMXXMM {
		bits, err := c.loadLegacyMMXMoveLow64(form.source)
		if err != nil {
			return true, false, err
		}
		words := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %s, i32 0\n", words, bits)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytes, words)
		return true, false, c.storeX(form.destination.Reg, "%"+bytes)
	}

	if spec.destination == amd64LegacyMMXMMX {
		bits, err := c.loadLegacyMMXMoveLow64(form.source)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(form.destination.Reg, bits)
	}

	if spec.transferBits == 64 {
		bits, err := c.evalIntSized(form.source, I64)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeMOVNTIMemory(form.destination, I64, bits)
	}
	bytes, err := c.loadX(form.source.Reg)
	if err != nil {
		return true, false, err
	}
	return true, false, c.storeVectorBytesOperandWithMetadata(form.destination, 16, bytes, x86NonTemporalMetadata)
}

func (c *amd64Ctx) loadLegacyMMXMoveLow64(source Operand) (string, error) {
	if source.Kind == OpReg {
		if _, ok := amd64ParseMReg(source.Reg); ok {
			return c.loadReg(source.Reg)
		}
		if c.isGoLegacyXReg(source.Reg) {
			value, err := c.loadX(source.Reg)
			if err != nil {
				return "", err
			}
			words := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", words, value)
			low := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", low, words)
			return "%" + low, nil
		}
	}
	return c.evalIntSized(source, I64)
}
