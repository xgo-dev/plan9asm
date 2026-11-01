package plan9asm

import (
	"fmt"
	"strings"
)

// Go's C_ADDR forms load/store the symbol's bytes. They are distinct from
// C_VCONADDR ($symbol(SB)), which materializes an address without dereferencing
// it. Keep all scalar widths together so a MOVD load cannot become an address
// and a store cannot silently disappear.
func (c *arm64Ctx) lowerARM64SymbolScalarMove(op Op, ins Instr) (bool, bool, error) {
	bits, signed := 0, false
	switch op {
	case "MOVD":
		bits = 64
	case "MOVW", "MOVWU":
		bits, signed = 32, op == "MOVW"
	case "MOVH", "MOVHU":
		bits, signed = 16, op == "MOVH"
	case "MOVB", "MOVBU":
		bits, signed = 8, op == "MOVB"
	default:
		return false, false, nil
	}
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpSym && ins.Args[1].Kind != OpSym {
		return false, false, nil
	}
	src, dst := ins.Args[0], ins.Args[1]
	if src.Kind == OpSym {
		if dst.Kind != OpReg || !isARM64GeneralOrZeroReg(dst.Reg) {
			return true, false, fmt.Errorf("arm64 %s symbolic source requires a general or zero destination register: %q", op, ins.Raw)
		}
		if strings.HasPrefix(strings.TrimSpace(src.Sym), "$") {
			// asm7's type 68 rejects MOVW, but MOVWU uses the same full
			// address materialization as MOVD. It is not a 32-bit load.
			if op != "MOVD" && (op != "MOVWU" || !strings.HasSuffix(strings.TrimSpace(src.Sym), "(SB)")) {
				return true, false, fmt.Errorf("arm64 %s does not accept this address source: %q", op, ins.Raw)
			}
			if string(ins.Op) != string(op) || !arm64ScalarMemoryGoRegisterSpelling(ins) {
				return true, false, fmt.Errorf("arm64 %s symbol address requires an original Go register spelling and no suffix: %q", op, ins.Raw)
			}
			if sourceSymbolOffsetNeedsContext(src.Sym) {
				return true, false, fmt.Errorf("%w: arm64 %s symbol address requires generated assembler constants: %q", ErrProbeNeedsContext, op, ins.Raw)
			}
			value, err := c.eval64(src, false)
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeReg(dst.Reg, value)
		}
		ptr, err := c.ptrFromSB(src.Sym)
		if err != nil {
			return true, false, err
		}
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s, align 1\n", loaded, bits, ptr)
		value := "%" + loaded
		if bits != 64 {
			wide := c.newTmp()
			extension := "zext"
			if signed {
				extension = "sext"
			}
			fmt.Fprintf(c.b, "  %%%s = %s i%d %s to i64\n", wide, extension, bits, value)
			value = "%" + wide
		}
		return true, false, c.storeReg(dst.Reg, value)
	}
	// obj7.progedit canonicalizes a resolved From literal $0 to ZR for all
	// seven scalar moves, including C_ADDR stores. An unresolved expression
	// with a placeholder zero value is not this alias.
	if src.Kind == OpImm && src.Imm == 0 && src.ImmRaw == "" {
		src = Operand{Kind: OpReg, Reg: ZR}
	}
	if strings.HasPrefix(strings.TrimSpace(dst.Sym), "$") || src.Kind != OpReg || !isARM64GeneralOrZeroReg(src.Reg) {
		return true, false, fmt.Errorf("arm64 %s symbolic destination requires a general or zero source register: %q", op, ins.Raw)
	}
	ptr, err := c.ptrFromSB(dst.Sym)
	if err != nil {
		return true, false, err
	}
	value, err := c.loadReg(src.Reg)
	if err != nil {
		return true, false, err
	}
	if bits != 64 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, value, bits)
		value = "%" + narrow
	}
	fmt.Fprintf(c.b, "  store i%d %s, ptr %s, align 1\n", bits, value, ptr)
	return true, false, nil
}
