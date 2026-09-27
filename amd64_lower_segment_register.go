package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerSegmentRegisterMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	if (baseOp != "MOVW" && baseOp != "MOVL" && baseOp != "MOVQ") || len(ins.Args) != 2 {
		return false, false, nil
	}
	sourceSegment := x86SegmentRegisterOperand(ins.Args[0])
	destinationSegment := x86SegmentRegisterOperand(ins.Args[1])
	if !sourceSegment && !destinationSegment {
		return false, false, nil
	}
	if baseOp != "MOVW" {
		return true, false, fmt.Errorf("%s segment-register moves use MOVW in Go 1.27's ymovtab: %q", c.goarch, ins.Raw)
	}
	if !x86SegmentMoveSuffixAccepted(rawOp) {
		return true, false, fmt.Errorf("%s segment-register MOVW has an invalid x86 suffix: %q", c.goarch, ins.Raw)
	}
	if sourceSegment == destinationSegment {
		return true, false, fmt.Errorf("%s MOVW segment-register form expects exactly one segment register: %q", c.goarch, ins.Raw)
	}
	if destinationSegment {
		source := ins.Args[0]
		if source.Kind == OpReg {
			if !isX86YrlRegisterForArch(source.Reg, c.goarch) {
				return true, false, fmt.Errorf("%s MOVW to a segment register expects a Yml source: %q", c.goarch, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("%s MOVW to a segment register expects a Yml source: %q", c.goarch, ins.Raw)
		}
		value, err := c.evalIntSized(source, I16)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeX86SegmentSelector(ins.Args[1].Reg, value)
	}

	destination := ins.Args[1]
	if destination.Kind == OpReg {
		if !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s MOVW from a segment register expects a Yml destination: %q", c.goarch, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("%s MOVW from a segment register expects a Yml destination: %q", c.goarch, ins.Raw)
	}
	call := c.loadX86SegmentSelector(ins.Args[0].Reg)
	if destination.Kind == OpReg {
		return true, false, c.storeRegSized(destination.Reg, I32, call)
	}
	selector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", selector, call)
	return true, false, c.storeScalarIntegerOperand(destination, I16, "%"+selector)
}

func (c *amd64Ctx) loadX86SegmentSelector(segment Reg) string {
	call := c.newTmp()
	assembly := fmt.Sprintf("movl %%%s, ${0:k}", strings.ToLower(string(segment)))
	fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n",
		call, assembly, "=r,~{memory},~{dirflag},~{fpsr},~{flags}")
	return "%" + call
}

func (c *amd64Ctx) storeX86SegmentSelector(segment Reg, selector string) error {
	assembly := fmt.Sprintf("movw $0, %%%s", strings.ToLower(string(segment)))
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i16 %s)\n",
		assembly, "r,~{memory},~{dirflag},~{fpsr},~{flags}", selector)
	return nil
}

func x86SegmentMoveSuffixAccepted(rawOp string) bool {
	if rawOp == "MOVW" {
		return true
	}
	suffix := strings.TrimPrefix(rawOp, "MOVW.")
	switch suffix {
	case "Z", "SAE", "SAE.Z",
		"RN_SAE", "RZ_SAE", "RD_SAE", "RU_SAE",
		"RN_SAE.Z", "RZ_SAE.Z", "RD_SAE.Z", "RU_SAE.Z",
		"BCST", "BCST.Z":
		// Go 1.27's ymovtab path accepts every syntactically valid x86 suffix
		// here and emits the same 8C/8E bytes. Preserve that compatibility.
		return true
	default:
		return false
	}
}

func x86SegmentRegisterOperand(operand Operand) bool {
	if operand.Kind != OpReg {
		return false
	}
	switch operand.Reg {
	case ES, CS, SS, DS, FS, GS:
		return true
	default:
		return false
	}
}
