package plan9asm

import (
	"fmt"
	"strings"
)

type amd64SegmentBaseDirection uint8

const (
	amd64SegmentBaseRead amd64SegmentBaseDirection = iota
	amd64SegmentBaseWrite
)

type amd64SegmentBaseSpec struct {
	segment   Reg
	direction amd64SegmentBaseDirection
	bits      int
}

// amd64SegmentBaseSpecs is the complete Go 1.27 FSGSBASE grammar. Segment,
// transfer direction, and width are data; all eight opcodes share one Yrl
// register parser and one exact inline-assembly emitter.
var amd64SegmentBaseSpecs = map[Op]amd64SegmentBaseSpec{
	"RDFSBASEL": {segment: FS, direction: amd64SegmentBaseRead, bits: 32},
	"RDFSBASEQ": {segment: FS, direction: amd64SegmentBaseRead, bits: 64},
	"RDGSBASEL": {segment: GS, direction: amd64SegmentBaseRead, bits: 32},
	"RDGSBASEQ": {segment: GS, direction: amd64SegmentBaseRead, bits: 64},
	"WRFSBASEL": {segment: FS, direction: amd64SegmentBaseWrite, bits: 32},
	"WRFSBASEQ": {segment: FS, direction: amd64SegmentBaseWrite, bits: 64},
	"WRGSBASEL": {segment: GS, direction: amd64SegmentBaseWrite, bits: 32},
	"WRGSBASEQ": {segment: GS, direction: amd64SegmentBaseWrite, bits: 64},
}

type amd64SegmentBaseForm struct {
	register Reg
}

func (c *amd64Ctx) lowerSegmentBase(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64SegmentBaseSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.bits == 64 {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's 32-bit encoding table: %q", baseOp, ins.Raw)
	}
	form, err := c.parseSegmentBaseForm(baseOp, ins)
	if err != nil {
		return true, false, err
	}
	return c.emitSegmentBase(spec, form)
}

func (c *amd64Ctx) parseSegmentBaseForm(op string, ins Instr) (amd64SegmentBaseForm, error) {
	var form amd64SegmentBaseForm
	if len(ins.Args) != 1 {
		return form, fmt.Errorf("%s %s expects one Go 1.27 Yrl register: %q", c.goarch, op, ins.Raw)
	}
	operand := ins.Args[0]
	if operand.Kind != OpReg || !isX86YrlRegisterForArch(operand.Reg, c.goarch) {
		return form, fmt.Errorf("%s %s expects a Go 1.27 Yrl register: %q", c.goarch, op, ins.Raw)
	}
	return amd64SegmentBaseForm{register: operand.Reg}, nil
}

func (spec amd64SegmentBaseSpec) mnemonic() string {
	prefix := "rd"
	if spec.direction == amd64SegmentBaseWrite {
		prefix = "wr"
	}
	width := "l"
	if spec.bits == 64 {
		width = "q"
	}
	return prefix + strings.ToLower(string(spec.segment)) + "base" + width
}

func (c *amd64Ctx) emitSegmentBase(spec amd64SegmentBaseSpec, form amd64SegmentBaseForm) (bool, bool, error) {
	typ := amd64IntegerTypeForBits(spec.bits)
	constraints := "~{dirflag},~{fpsr},~{flags}"
	assembly := spec.mnemonic() + " $0"
	registerConstraint := "r"
	if c.goarch == "386" {
		// Intel defines FSGSBASE only in 64-bit mode, but Go 1.27's 386
		// assembler accepts the L spellings and emits their F3 0F AE /r
		// encodings. LLVM intentionally rejects the mnemonic for i386. Emit
		// Go's exact EAX encoding and use a fixed-register constraint so the
		// object remains byte-compatible without claiming runtime viability.
		modRM := byte(0xc0)
		if spec.segment == GS {
			modRM += 8
		}
		if spec.direction == amd64SegmentBaseWrite {
			modRM += 16
		}
		assembly = fmt.Sprintf(".byte 0xf3, 0x0f, 0xae, 0x%02x", modRM)
		registerConstraint = "{ax}"
	}
	if spec.direction == amd64SegmentBaseRead {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q()\n",
			result, typ, assembly, "="+registerConstraint+","+constraints)
		if err := c.storeRegSized(form.register, typ, "%"+result); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: form.register}, typ)
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s)\n",
		assembly, registerConstraint+","+constraints, typ, value)
	return true, false, nil
}
