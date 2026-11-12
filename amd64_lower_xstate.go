package plan9asm

import (
	"fmt"
	"strings"
)

type amd64XStateFamily uint8

const (
	amd64XStateFX amd64XStateFamily = iota
	amd64XStateXSAVE
	amd64XStateXSAVEOPT
	amd64XStateXSAVEC
	amd64XStateXSAVES
	amd64XStateXRSTOR
	amd64XStateXRSTORS
)

type amd64XStateDirection uint8

const (
	amd64XStateSave amd64XStateDirection = iota
	amd64XStateRestore
)

type amd64XStateSpec struct {
	family       amd64XStateFamily
	direction    amd64XStateDirection
	mode64       bool
	implicitMask bool
	memoryBytes  int
}

// amd64XStateSpecs is the complete Go 1.27 extended-state memory grammar.
// Opcode spelling selects only the state family, transfer direction, and
// encoding mode; one parser owns the shared Ym memory operand rule.
var amd64XStateSpecs = map[Op]amd64XStateSpec{
	"FXSAVE":     {family: amd64XStateFX, direction: amd64XStateSave, memoryBytes: 512},
	"FXSAVE64":   {family: amd64XStateFX, direction: amd64XStateSave, mode64: true, memoryBytes: 512},
	"FXRSTOR":    {family: amd64XStateFX, direction: amd64XStateRestore, memoryBytes: 512},
	"FXRSTOR64":  {family: amd64XStateFX, direction: amd64XStateRestore, mode64: true, memoryBytes: 512},
	"XSAVE":      {family: amd64XStateXSAVE, direction: amd64XStateSave, implicitMask: true, memoryBytes: 1},
	"XSAVE64":    {family: amd64XStateXSAVE, direction: amd64XStateSave, mode64: true, implicitMask: true, memoryBytes: 1},
	"XSAVEOPT":   {family: amd64XStateXSAVEOPT, direction: amd64XStateSave, implicitMask: true, memoryBytes: 1},
	"XSAVEOPT64": {family: amd64XStateXSAVEOPT, direction: amd64XStateSave, mode64: true, implicitMask: true, memoryBytes: 1},
	"XSAVEC":     {family: amd64XStateXSAVEC, direction: amd64XStateSave, implicitMask: true, memoryBytes: 1},
	"XSAVEC64":   {family: amd64XStateXSAVEC, direction: amd64XStateSave, mode64: true, implicitMask: true, memoryBytes: 1},
	"XSAVES":     {family: amd64XStateXSAVES, direction: amd64XStateSave, implicitMask: true, memoryBytes: 1},
	"XSAVES64":   {family: amd64XStateXSAVES, direction: amd64XStateSave, mode64: true, implicitMask: true, memoryBytes: 1},
	"XRSTOR":     {family: amd64XStateXRSTOR, direction: amd64XStateRestore, implicitMask: true, memoryBytes: 1},
	"XRSTOR64":   {family: amd64XStateXRSTOR, direction: amd64XStateRestore, mode64: true, implicitMask: true, memoryBytes: 1},
	"XRSTORS":    {family: amd64XStateXRSTORS, direction: amd64XStateRestore, implicitMask: true, memoryBytes: 1},
	"XRSTORS64":  {family: amd64XStateXRSTORS, direction: amd64XStateRestore, mode64: true, implicitMask: true, memoryBytes: 1},
}

type amd64XStateForm struct {
	memory Operand
}

func (c *amd64Ctx) lowerXState(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64XStateSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.mode64 {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's 32-bit encoding table: %q", baseOp, ins.Raw)
	}
	form, err := c.parseXStateForm(baseOp, ins)
	if err != nil {
		return true, false, err
	}
	return c.emitXState(spec, form)
}

func (c *amd64Ctx) parseXStateForm(op string, ins Instr) (amd64XStateForm, error) {
	var form amd64XStateForm
	if len(ins.Args) != 1 {
		return form, fmt.Errorf("%s %s expects one Go 1.27 Ym memory operand: %q", c.goarch, op, ins.Raw)
	}
	memory := ins.Args[0]
	if !isAMD64MemoryOperand(memory) {
		return form, fmt.Errorf("%s %s expects Go 1.27 Ym memory: %q", c.goarch, op, ins.Raw)
	}
	if memory.Kind == OpMem && !x86MemoryRegistersValidForArch(memory.Mem, c.goarch) {
		return form, fmt.Errorf("%s %s address uses an out-of-range register: %q", c.goarch, op, ins.Raw)
	}
	return amd64XStateForm{memory: memory}, nil
}

func (spec amd64XStateSpec) mnemonic() string {
	var mnemonic string
	switch spec.family {
	case amd64XStateFX:
		mnemonic = "fxsave"
		if spec.direction == amd64XStateRestore {
			mnemonic = "fxrstor"
		}
	case amd64XStateXSAVE:
		mnemonic = "xsave"
	case amd64XStateXSAVEOPT:
		mnemonic = "xsaveopt"
	case amd64XStateXSAVEC:
		mnemonic = "xsavec"
	case amd64XStateXSAVES:
		mnemonic = "xsaves"
	case amd64XStateXRSTOR:
		mnemonic = "xrstor"
	case amd64XStateXRSTORS:
		mnemonic = "xrstors"
	default:
		panic("unknown amd64 xstate family")
	}
	if spec.mode64 {
		mnemonic += "64"
	}
	return mnemonic
}

func (c *amd64Ctx) emitXState(spec amd64XStateSpec, form amd64XStateForm) (bool, bool, error) {
	pointer, pointerType, err := c.x86DescriptorMemoryPointer(form.memory)
	if err != nil {
		return true, false, err
	}
	memoryConstraint := "=*m"
	if spec.direction == amd64XStateRestore {
		memoryConstraint = "*m"
	}
	constraints := memoryConstraint
	arguments := fmt.Sprintf("%s elementtype([%d x i8]) %s", pointerType, spec.memoryBytes, pointer)
	if spec.implicitMask {
		ax, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, I32)
		if err != nil {
			return true, false, err
		}
		dx, err := c.evalIntSized(Operand{Kind: OpReg, Reg: DX}, I32)
		if err != nil {
			return true, false, err
		}
		constraints += ",{ax},{dx}"
		arguments += fmt.Sprintf(", i32 %s, i32 %s", ax, dx)
	}
	constraints += ",~{memory},~{dirflag},~{fpsr},~{flags}"
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s)\n",
		spec.mnemonic()+" $0", constraints, arguments)
	return true, false, nil
}
