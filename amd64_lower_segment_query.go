package plan9asm

import "fmt"

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
	spec        amd64SegmentQuerySpec
	selector    Operand
	destination Reg
}

func (c *amd64Ctx) lowerSegmentQuery(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86SegmentQueryProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return c.emitSegmentQuery(ins, form)
}

func (c *amd64Ctx) emitSegmentQuery(ins Instr, form amd64SegmentQueryForm) (bool, bool, error) {
	spec := form.spec
	selector, err := c.evalSegmentQuerySelector(ins, form.selector)
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

	// A query can fail without writing its destination. Retain the whole
	// native GP carrier in the tied operand, rather than unconditionally
	// zero-extending an i32 result after a failed LARL/LSLL. The actual opcode
	// determines the physical upper-half behavior on this processor.
	typ, destination := I64, "$0"
	if c.goarch == "386" {
		typ = I32
	}
	if spec.bits == 16 {
		destination = "${0:w}"
	} else if spec.bits == 32 {
		destination = "${0:k}"
	}
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
	assembly := mnemonic + width + " $3, " + destination + "; sete $1"
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

func (c *amd64Ctx) evalSegmentQuerySelector(ins Instr, selector Operand) (string, error) {
	if selector.Kind == OpFP && x86ResultNamedPredicateInstruction(ins) {
		if value, handled, err := c.loadIntegerFPBytesMode(selector.FPOffset, I16, true); handled || err != nil {
			return value, err
		}
	}
	// Share the exact unaligned volatile scalar emitter. This is a two-byte
	// read even for Q spellings and dead results; it creates no backing fact.
	return c.evalSizedNativeGPSource(selector, I16, ins.x86AddressBits)
}

func (c *amd64Ctx) storeSegmentQueryZF(status string) {
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i8 %s, 0\n", zero, status)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
}
