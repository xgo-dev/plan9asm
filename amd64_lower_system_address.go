package plan9asm

import (
	"fmt"
	"strings"
)

type amd64SystemAddressKind uint8

const (
	amd64SystemAddressInvalidatePage amd64SystemAddressKind = iota
	amd64SystemAddressInvalidatePCID
	amd64SystemAddressDemoteCacheLine
)

type amd64SystemAddressSpec struct {
	kind        amd64SystemAddressKind
	memoryBytes int
	register    bool
}

// amd64SystemAddressSpecs is the complete Go 1.27 address-shaped system
// instruction grammar. The single-memory and memory-plus-register rows share
// memory/address validation; register compatibility closures are represented
// explicitly and trap just as their architecturally invalid ModRM encodings do.
var amd64SystemAddressSpecs = map[Op]amd64SystemAddressSpec{
	"INVLPG":   {kind: amd64SystemAddressInvalidatePage, memoryBytes: 1},
	"INVPCID":  {kind: amd64SystemAddressInvalidatePCID, memoryBytes: 16, register: true},
	"CLDEMOTE": {kind: amd64SystemAddressDemoteCacheLine, memoryBytes: 1},
}

type amd64SystemAddressForm struct {
	memory       Operand
	register     Reg
	invalidModRM bool
}

func (c *amd64Ctx) lowerSystemAddress(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64SystemAddressSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	form, err := c.parseSystemAddressForm(baseOp, spec, ins)
	if err != nil {
		return true, false, err
	}
	return c.emitSystemAddress(baseOp, spec, form)
}

func (c *amd64Ctx) parseSystemAddressForm(op string, spec amd64SystemAddressSpec, ins Instr) (amd64SystemAddressForm, error) {
	var form amd64SystemAddressForm
	wantArgs := 1
	if spec.register {
		wantArgs = 2
	}
	if len(ins.Args) != wantArgs {
		return form, fmt.Errorf("%s %s expects %d operand(s): %q", c.goarch, op, wantArgs, ins.Raw)
	}
	address := ins.Args[0]
	if isAMD64MemoryOperand(address) {
		if address.Kind == OpMem && !x86MemoryRegistersValidForArch(address.Mem, c.goarch) {
			return form, fmt.Errorf("%s %s address uses an out-of-range register: %q", c.goarch, op, ins.Raw)
		}
		form.memory = address
	} else if address.Kind == OpReg && spec.kind != amd64SystemAddressDemoteCacheLine {
		valid := isX86YrlRegisterForArch(address.Reg, c.goarch)
		if spec.kind == amd64SystemAddressInvalidatePage {
			valid = isGoYmbRegisterForArch(address.Reg, c.goarch)
		}
		if !valid {
			return form, fmt.Errorf("%s %s first operand is outside Go 1.27's compatibility class: %q", c.goarch, op, ins.Raw)
		}
		form.invalidModRM = true
	} else {
		return form, fmt.Errorf("%s %s expects Go 1.27 memory/address form: %q", c.goarch, op, ins.Raw)
	}
	if spec.register {
		typeOperand := ins.Args[1]
		if typeOperand.Kind != OpReg || !isX86YrlRegisterForArch(typeOperand.Reg, c.goarch) {
			return form, fmt.Errorf("%s %s type operand must be a Go 1.27 Yrl register: %q", c.goarch, op, ins.Raw)
		}
		form.register = typeOperand.Reg
	}
	return form, nil
}

func (c *amd64Ctx) emitSystemAddress(op string, spec amd64SystemAddressSpec, form amd64SystemAddressForm) (bool, bool, error) {
	if form.invalidModRM {
		c.b.WriteString("  call void asm sideeffect \"ud2\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	}
	pointer, pointerType, err := c.x86DescriptorMemoryPointer(form.memory)
	if err != nil {
		return true, false, err
	}
	clobbers := "~{memory},~{dirflag},~{fpsr},~{flags}"
	if spec.kind != amd64SystemAddressInvalidatePCID {
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype([%d x i8]) %s)\n",
			strings.ToLower(op)+" $0", "*m,"+clobbers, pointerType, spec.memoryBytes, pointer)
		return true, false, nil
	}

	if c.goarch == "386" {
		// INVPCID is a 64-bit-mode instruction, but Go 1.27 accepts it for
		// 386. Reproduce Go's 66 0F 38 82 /r encoding with the calculated
		// address fixed in EBX and the type fixed in EAX. In 32-bit mode the
		// bytes fault architecturally, but remain object-level compatible.
		address := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint %s %s to i32\n", address, pointerType, pointer)
		typeValue, err := c.evalIntSized(Operand{Kind: OpReg, Reg: form.register}, I32)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %%%s, i32 %s)\n",
			".byte 0x66, 0x0f, 0x38, 0x82, 0x03", "{bx},{ax},"+clobbers, address, typeValue)
		return true, false, nil
	}
	typeValue, err := c.evalIntSized(Operand{Kind: OpReg, Reg: form.register}, I64)
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype([16 x i8]) %s, i64 %s)\n",
		"invpcid $0, $1", "*m,r,"+clobbers, pointerType, pointer, typeValue)
	return true, false, nil
}
