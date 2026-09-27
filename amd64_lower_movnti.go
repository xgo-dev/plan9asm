package plan9asm

import (
	"fmt"
	"strings"
)

const x86NonTemporalMetadata = ", !nontemporal !0"

// lowerMOVNTI implements Go 1.27's complete yrl_ml row for MOVNTIL/Q. Yrl is
// a general-register source and Yml accepts ordinary, symbol, and FP memory.
// Go's compatibility closure also accepts a general-register destination;
// Intel defines only a memory destination for that ModRM encoding, so model
// the Go-accepted register form as an explicit undefined-instruction trap
// rather than silently treating it as an ordinary register move.
func (c *amd64Ctx) lowerMOVNTI(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	typ := LLVMType("")
	switch baseOp {
	case "MOVNTIL":
		typ = I32
	case "MOVNTIQ":
		if c.goarch == "386" {
			return true, false, fmt.Errorf("386 MOVNTIQ is illegal in 32-bit mode: %q", ins.Raw)
		}
		typ = I64
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed forms in Go 1.27's yrl_ml table: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects exactly two operands: %q", c.goarch, baseOp, ins.Raw)
	}
	source, destination := ins.Args[0], ins.Args[1]
	if source.Kind != OpReg || !isX86YrlRegisterForArch(source.Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s source must be an in-range general register: %q", c.goarch, baseOp, ins.Raw)
	}
	if destination.Kind == OpReg {
		if !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Yml compatibility closure: %q", c.goarch, baseOp, ins.Raw)
		}
		c.b.WriteString("  call void asm sideeffect \"ud2\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	}
	if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("%s %s destination must be Yml memory or a Go-compatible general register: %q", c.goarch, baseOp, ins.Raw)
	}
	if destination.Kind == OpMem && !x86MemoryRegistersValidForArch(destination.Mem, c.goarch) {
		return true, false, fmt.Errorf("%s %s destination uses an out-of-range address register: %q", c.goarch, baseOp, ins.Raw)
	}
	value, err := c.evalIntSized(source, typ)
	if err != nil {
		return true, false, err
	}
	return true, false, c.storeMOVNTIMemory(destination, typ, value)
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
			case "MOVNTIL", "MOVNTIQ", "MOVNTQ", "MOVNTDQ", "MOVNTO", "MOVNTPD", "MOVNTPS", "VMOVNTDQ", "VMOVNTPD", "VMOVNTPS":
				return true
			}
		}
	}
	return false
}
