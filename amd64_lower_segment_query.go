package plan9asm

import (
	"fmt"
	"strings"
)

type amd64SegmentQueryKind uint8

const (
	amd64SegmentQueryAccessRights amd64SegmentQueryKind = iota
	amd64SegmentQueryLimit
	amd64SegmentQueryReadable
	amd64SegmentQueryWritable
)

type amd64SegmentQuerySpec struct {
	kind amd64SegmentQueryKind
	bits int
}

// amd64SegmentQuerySpecs is the complete Go 1.27 LAR/LSL/VERR/VERW grammar.
// The table records only query kind and optional destination width; all four
// families share one selector-source parser and one exact lowering mechanism.
var amd64SegmentQuerySpecs = map[Op]amd64SegmentQuerySpec{
	"LARW": {kind: amd64SegmentQueryAccessRights, bits: 16},
	"LARL": {kind: amd64SegmentQueryAccessRights, bits: 32},
	"LARQ": {kind: amd64SegmentQueryAccessRights, bits: 64},
	"LSLW": {kind: amd64SegmentQueryLimit, bits: 16},
	"LSLL": {kind: amd64SegmentQueryLimit, bits: 32},
	"LSLQ": {kind: amd64SegmentQueryLimit, bits: 64},
	"VERR": {kind: amd64SegmentQueryReadable},
	"VERW": {kind: amd64SegmentQueryWritable},
}

type amd64SegmentQueryForm struct {
	selector    Operand
	destination Reg
}

func (c *amd64Ctx) lowerSegmentQuery(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64SegmentQuerySpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.bits == 64 {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's 32-bit encoding table: %q", baseOp, ins.Raw)
	}
	form, err := c.parseSegmentQueryForm(baseOp, spec, ins)
	if err != nil {
		return true, false, err
	}
	return c.emitSegmentQuery(spec, form)
}

func (c *amd64Ctx) parseSegmentQueryForm(op string, spec amd64SegmentQuerySpec, ins Instr) (amd64SegmentQueryForm, error) {
	var form amd64SegmentQueryForm
	wantArgs := 2
	if spec.bits == 0 {
		wantArgs = 1
	}
	if len(ins.Args) != wantArgs {
		if wantArgs == 1 {
			return form, fmt.Errorf("%s %s expects one selector source: %q", c.goarch, op, ins.Raw)
		}
		return form, fmt.Errorf("%s %s expects selector source and GP destination: %q", c.goarch, op, ins.Raw)
	}
	selector := ins.Args[0]
	if selector.Kind == OpReg {
		if !isX86YrlRegisterForArch(selector.Reg, c.goarch) {
			return form, fmt.Errorf("%s %s selector register is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(selector) {
		return form, fmt.Errorf("%s %s selector must be a GP register or memory: %q", c.goarch, op, ins.Raw)
	}
	if selector.Kind == OpMem && !x86MemoryRegistersValidForArch(selector.Mem, c.goarch) {
		return form, fmt.Errorf("%s %s selector address uses an out-of-range register: %q", c.goarch, op, ins.Raw)
	}
	form.selector = selector
	if wantArgs == 1 {
		return form, nil
	}
	destination := ins.Args[1]
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
		return form, fmt.Errorf("%s %s destination must be a Go 1.27 Yrl register: %q", c.goarch, op, ins.Raw)
	}
	form.destination = destination.Reg
	return form, nil
}

func (c *amd64Ctx) emitSegmentQuery(spec amd64SegmentQuerySpec, form amd64SegmentQueryForm) (bool, bool, error) {
	selector, err := c.evalIntSized(form.selector, I16)
	if err != nil {
		return true, false, err
	}
	if spec.bits == 0 {
		mnemonic := "verr"
		if spec.kind == amd64SegmentQueryWritable {
			mnemonic = "verw"
		}
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i8 asm sideeffect %q, %q(i16 %s)\n",
			status, mnemonic+" $1; sete $0", "=q,r,~{dirflag},~{fpsr},~{flags}", selector)
		c.storeSegmentQueryZF("%" + status)
		return true, false, nil
	}

	typ := amd64IntegerTypeForBits(spec.bits)
	previousDestination, err := c.evalIntSized(Operand{Kind: OpReg, Reg: form.destination}, typ)
	if err != nil {
		return true, false, err
	}

	// Intel specifies that a failed descriptor check clears ZF but leaves the
	// destination unchanged. Constraint 0 therefore ties the old destination
	// value to the result instead of declaring a write-only output. SETE does
	// not alter flags, so the second result captures the instruction's ZF while
	// the translator's other virtual flag slots remain unchanged.
	result := c.newTmp()
	mnemonic := "lar"
	if spec.kind == amd64SegmentQueryLimit {
		mnemonic = "lsl"
	}
	width := map[int]string{16: "w", 32: "l", 64: "q"}[spec.bits]
	assembly := mnemonic + width + " $3, $0; sete $1"
	fmt.Fprintf(c.b, "  %%%s = call { %s, i8 } asm sideeffect %q, %q(%s %s, i16 %s)\n",
		result, typ, assembly, "=r,=q,0,r,~{dirflag},~{fpsr},~{flags}", typ, previousDestination, selector)
	value := c.newTmp()
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i8 } %%%s, 0\n", value, typ, result)
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i8 } %%%s, 1\n", status, typ, result)
	c.storeSegmentQueryZF("%" + status)
	if err := c.storeRegSized(form.destination, typ, "%"+value); err != nil {
		return true, false, err
	}
	return true, false, nil
}

func (c *amd64Ctx) storeSegmentQueryZF(status string) {
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i8 %s, 0\n", zero, status)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
}
