package plan9asm

import "fmt"

// lowerVectorLaneExtract implements all Go 1.27 forms in _yvextractf128,
// _yvextractf32x4, and _yvextractf32x8 for their F/I lane-extract mnemonics.
func (c *amd64Ctx) lowerVectorLaneExtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerInsertExtractFamily(op, ins)
}

func (c *amd64Ctx) storeVectorBytesOperand(dst Operand, byteWidth int, value string) error {
	return c.storeVectorBytesOperandWithMetadata(dst, byteWidth, value, "")
}

func (c *amd64Ctx) storeVectorBytesOperandWithMetadata(dst Operand, byteWidth int, value, metadata string) error {
	if dst.Kind == OpReg {
		if metadata != "" {
			return fmt.Errorf("vector register destination cannot carry store metadata: %s", dst.String())
		}
		if !amd64VectorRegisterHasWidth(dst, byteWidth) {
			return fmt.Errorf("expected %d-byte vector register, got %s", byteWidth, dst.String())
		}
		return c.storeVectorBytes(dst.Reg, byteWidth, value)
	}
	switch dst.Kind {
	case OpMem:
		addr, err := c.addrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <%d x i8> %s, ptr %s, align 1%s\n", byteWidth, value, c.ptrFromAddrI64(addr), metadata)
		return nil
	case OpSym:
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <%d x i8> %s, ptr %s, align 1%s\n", byteWidth, value, p, metadata)
		return nil
	case OpFP:
		return c.storeFPVectorBytes(dst.FPOffset, byteWidth, value, metadata)
	default:
		return fmt.Errorf("expected vector register or memory destination, got %s", dst.String())
	}
}
