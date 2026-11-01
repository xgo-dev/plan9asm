package plan9asm

import (
	"fmt"
	"strings"
)

const x86NonTemporalMetadata = ", !nontemporal !0"

func (c *amd64Ctx) lowerMOVNTI(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86MOVNTIProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if form.trap {
		c.b.WriteString("  call void asm sideeffect \"ud2\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) ||
		!x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return true, false, fmt.Errorf("%w: MOVNTI needs its original named x86 target and address size", ErrProbeNeedsContext)
	}
	if !x86OrdinaryNativeMemoryOperand(form.destination, c.goarch) {
		return true, false, fmt.Errorf("%w: MOVNTI needs native storage, not logical FP/AUTO bytes", ErrProbeNeedsContext)
	}
	return true, false, c.emitMOVNTI(form)
}

// Intel SDM MOVNTI retains its actual WC/cache policy, dead write and faults.
// LLVM nontemporal metadata on an ordinary store makes none of those effects
// mandatory. Pass only the exact integer and opaque address to the native
// opcode, without asserting alignment, extent, aliasing or pointee validity.
func (c *amd64Ctx) emitMOVNTI(form x86MOVNTIForm) error {
	typ := amd64IntegerTypeForBits(form.bits)
	value, err := c.evalIntSized(form.source, typ)
	if err != nil {
		return err
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.destination)
	if err != nil {
		return err
	}
	segment, modifier := "", "k"
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	if form.bits == 64 {
		modifier = "q"
	}
	assembly := "movnti ${0:" + modifier + "}, " + segment + "($1)"
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s, %s %s)\n", assembly,
		"r,r,~{memory}", typ, value, pointerType, pointer)
	return nil
}

func x86MemoryRegistersValidForArch(memory MemRef, goarch string) bool {
	for _, register := range []Reg{memory.Base, memory.Index} {
		if register != "" && !isX86YrlRegisterForArch(register, goarch) {
			return false
		}
	}
	return true
}

func (c *amd64Ctx) storeMOVNTIMemory(destination Operand, typ LLVMType, value string) error {
	switch destination.Kind {
	case OpMem:
		pointer, pointerType, err := c.ptrFromMem(destination.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1%s\n", typ, value, pointerType, pointer, x86NonTemporalMetadata)
		return nil
	case OpFP:
		return c.storeFPResultWithMetadata(destination.FPOffset, typ, value, x86NonTemporalMetadata)
	case OpSym:
		pointer, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1%s\n", typ, value, pointer, x86NonTemporalMetadata)
		return nil
	default:
		return fmt.Errorf("MOVNTI destination is not memory: %s", destination.String())
	}
}

func fileUsesX86NonTemporalMetadata(file *File) bool {
	if file == nil || file.Arch != ArchAMD64 {
		return false
	}
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			op := strings.ToUpper(string(instruction.Op))
			switch op {
			case "MOVNTQ", "MOVNTDQ", "MOVNTO", "MOVNTPD", "MOVNTPS", "VMOVNTDQ", "VMOVNTPD", "VMOVNTPS":
				return true
			}
		}
	}
	return false
}
