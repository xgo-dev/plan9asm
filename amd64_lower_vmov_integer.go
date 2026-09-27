package plan9asm

import (
	"fmt"
	"strings"
)

// lowerVectorScalarIntegerMove implements the complete Go 1.27 _yvmovd and
// _yvmovq tables. Both instructions transfer between X registers and scalar
// GP/memory operands; VMOVQ additionally permits X-to-X transfers.
// Raw VMOVW shares this grammar with a 16-bit transfer and GP zero-extension.
func (c *amd64Ctx) lowerVectorScalarIntegerMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	bits := 0
	switch rawOp {
	case "VMOVW":
		if !ins.x86Encoded {
			return true, false, fmt.Errorf("%s VMOVW is absent from Go's named assembler table: %q", c.goarch, ins.Raw)
		}
		bits = 16
	case "VMOVD":
		bits = 32
	case "VMOVQ":
		bits = 64
	default:
		if strings.HasPrefix(rawOp, "VMOVW.") || strings.HasPrefix(rawOp, "VMOVD.") || strings.HasPrefix(rawOp, "VMOVQ.") {
			return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's scalar integer move tables: %q", c.goarch, strings.SplitN(rawOp, ".", 2)[0], ins.Raw)
		}
		return false, false, nil
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects exactly two operands: %q", c.goarch, rawOp, ins.Raw)
	}

	src, dst := ins.Args[0], ins.Args[1]
	srcX := isAMD64GoXRegister(src)
	dstX := isAMD64GoXRegister(dst)
	if srcX && dstX {
		if rawOp != "VMOVQ" {
			return true, false, fmt.Errorf("%s %s has no X-to-X form: %q", c.goarch, rawOp, ins.Raw)
		}
		low, err := c.loadXLowInteger(src.Reg, 64)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeVMOVIntegerX(dst.Reg, 64, low)
	}
	if srcX {
		transferBits := bits
		if c.goarch == "386" && dst.Kind == OpReg && transferBits > 32 {
			transferBits = 32
		}
		if !c.isGoVMOVScalarOperand(dst) {
			return true, false, fmt.Errorf("%s %s destination must be a GP register, memory, or X register: %q", c.goarch, rawOp, ins.Raw)
		}
		low, err := c.loadXLowInteger(src.Reg, transferBits)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeVMOVIntegerScalar(dst, transferBits, low)
	}
	if dstX {
		transferBits := bits
		if c.goarch == "386" && src.Kind == OpReg && transferBits > 32 {
			transferBits = 32
		}
		if !c.isGoVMOVScalarOperand(src) && !(src.Kind == OpImm && ins.x86RIPLiteral) {
			return true, false, fmt.Errorf("%s %s source must be a GP register, memory, or X register: %q", c.goarch, rawOp, ins.Raw)
		}
		low, err := c.evalIntSized(src, amd64IntegerTypeForBits(transferBits))
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeVMOVIntegerX(dst.Reg, transferBits, low)
	}
	return true, false, fmt.Errorf("%s %s requires one X-register operand: %q", c.goarch, rawOp, ins.Raw)
}

func isAMD64GoXRegister(operand Operand) bool {
	if operand.Kind != OpReg {
		return false
	}
	_, ok := amd64ParseXReg(operand.Reg)
	return ok
}

func (c *amd64Ctx) isGoVMOVScalarOperand(operand Operand) bool {
	if isAMD64MemoryOperand(operand) {
		return true
	}
	return operand.Kind == OpReg && isX86YrlRegisterForArch(operand.Reg, c.goarch)
}

func (c *amd64Ctx) storeVMOVIntegerX(dst Reg, bits int, low string) error {
	lanes := 128 / bits
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %s, i32 0\n", inserted, lanes, bits, bits, low)
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", bytes, lanes, bits, inserted)
	return c.storePackedMoveOperand(Operand{Kind: OpReg, Reg: dst}, 16, "%"+bytes)
}

func (c *amd64Ctx) storeVMOVIntegerScalar(dst Operand, bits int, value string) error {
	typ := amd64IntegerTypeForBits(bits)
	if dst.Kind != OpReg {
		return c.storeScalarIntegerOperand(dst, typ, value)
	}
	if bits == 64 {
		return c.storeRegUnchecked(dst.Reg, value)
	}
	widened := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i64\n", widened, bits, value)
	return c.storeRegUnchecked(dst.Reg, "%"+widened)
}
