package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type x86MachineRegisterForm struct {
	class      string
	register   int
	descriptor string
	effect     x86TypedByteOperand
}

var x86DescriptorAliases = map[string]struct {
	load, store Op
	word        bool
}{
	"gdtr": {"LGDT", "SGDT", false},
	"idtr": {"LIDT", "SIDT", false},
	"ldtr": {"LLDT", "SLDTL", true},
	"msw":  {"LMSW", "SMSWL", true},
	"task": {"LTR", "STRL", true},
}

// The Go MOV suffix selects a source row. It does not necessarily select
// the native operand width, for instance MOVL and MOVQ on CR/DR.
func x86MachineRegisterProperties(op Op, ins Instr, arch string) (x86MachineRegisterForm, bool, error) {
	base, _, suffix := strings.Cut(strings.ToUpper(string(op)), ".")
	if len(ins.Args) != 2 || base != "MOVW" && base != "MOVL" && base != "MOVQ" {
		return x86MachineRegisterForm{}, false, nil
	}
	leftClass, leftIndex, leftSpecial := x86MachineRegisterOperand(ins.Args[0])
	rightClass, rightIndex, rightSpecial := x86MachineRegisterOperand(ins.Args[1])
	if !leftSpecial && !rightSpecial {
		return x86MachineRegisterForm{}, false, nil
	}
	fail := func(reason string) (x86MachineRegisterForm, bool, error) {
		return x86MachineRegisterForm{}, true, fmt.Errorf("%s %s %s: %q", arch, base, reason, ins.Raw)
	}
	if suffix || leftSpecial == rightSpecial {
		return fail("requires exactly one special register and no suffix")
	}

	class, register, index := rightClass, rightIndex, 0
	if leftSpecial {
		class, register, index = leftClass, leftIndex, 1
	}
	operand := ins.Args[index]
	effect := x86TypedByteOperand{index: index, operand: operand, read: !leftSpecial, write: leftSpecial}
	form := x86MachineRegisterForm{class: class, register: register}
	if alias, known := x86DescriptorAliases[class]; known {
		if (base == "MOVW") != alias.word {
			return fail("is absent from Go's descriptor-register MOV rows")
		}
		direct := alias.load
		if effect.write {
			direct = alias.store
		}
		projected := Instr{Op: direct, Args: ins.Args[index : index+1], Raw: ins.Raw}
		descriptor, _, err := x86DescriptorProperties(direct, projected, arch)
		if err != nil {
			return x86MachineRegisterForm{}, true, err
		}
		effect.width = descriptor.effect.width
		form.descriptor, form.effect = descriptor.mnemonic, effect
		return form, true, nil
	}

	allowed := false
	switch class {
	case "cr":
		allowed = base != "MOVW" && (register == 0 || register == 2 || register == 3 ||
			register == 4 || register == 8 && arch == "amd64")
	case "dr":
		allowed = base != "MOVW" && (register == 0 || register == 6 || register == 7 ||
			base == "MOVQ" && (register == 2 || register == 3))
	case "tr":
		allowed = base == "MOVL" && (register == 6 || register == 7)
		if allowed && isAMD64MemoryOperand(operand) {
			// Go's Yml table emits bytes for these forms. The actual
			// special-register opcode has only a GP register operand.
			return x86MachineRegisterForm{}, true, fmt.Errorf("%w: %s has no architectural test-register memory form: %q",
				ErrProbeNeedsContext, arch, ins.Raw)
		}
	}
	if !allowed || operand.Kind != OpReg || !isX86YrlRegisterForArch(operand.Reg, arch) {
		return fail("is outside Go's machine-register GP rows")
	}
	effect.width = x86ResultPointerWord(arch)
	if class == "tr" {
		effect.width = 4
	}
	form.effect = effect
	return form, true, nil
}

func (c *amd64Ctx) lowerMachineRegisterMove(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86MachineRegisterProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if form.descriptor != "" {
		return true, false, c.emitDescriptor(x86DescriptorForm{mnemonic: form.descriptor, effect: form.effect})
	}
	return true, false, c.emitMachineRegisterMove(form)
}

func (c *amd64Ctx) emitMachineRegisterMove(form x86MachineRegisterForm) error {
	effect := form.effect
	typ := amd64IntegerTypeForBits(int(effect.width * 8))
	special := fmt.Sprintf("%%%s%d", form.class, form.register)
	assembly, constraint := "mov $0, "+special, "r"
	if effect.write {
		assembly, constraint = "mov "+special+", $0", "=r"
	}
	if form.class == "tr" {
		// LLVM has no assembler mnemonic for the legacy TR register rows.
		opcode := 0x26
		constraint = "{ax}"
		if effect.write {
			opcode, constraint = 0x24, "={ax}"
		}
		assembly = fmt.Sprintf(".byte 0x0f, 0x%02x, 0x%02x", opcode, 0xc0|form.register<<3)
	}
	constraint += "," + x86SystemAsmClobbers
	if effect.write {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q()\n", result, typ, assembly, constraint)
		return c.storeRegSized(effect.operand.Reg, typ, "%"+result)
	}
	value, err := c.evalIntSized(effect.operand, typ)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s)\n", assembly, constraint, typ, value)
	return nil
}

func x86MachineRegisterOperand(operand Operand) (class string, index int, ok bool) {
	if operand.Kind != OpReg {
		return "", 0, false
	}
	return x86MachineRegister(operand.Reg)
}

func x86MachineRegister(reg Reg) (class string, index int, ok bool) {
	name := strings.ToUpper(string(reg))
	switch name {
	case "GDTR", "IDTR", "LDTR", "MSW", "TASK":
		return strings.ToLower(name), 0, true
	}
	if len(name) < 3 {
		return "", 0, false
	}
	prefix := name[:2]
	if prefix != "CR" && prefix != "DR" && prefix != "TR" {
		return "", 0, false
	}
	index, err := strconv.Atoi(name[2:])
	if err != nil {
		return "", 0, false
	}
	return strings.ToLower(prefix), index, true
}
