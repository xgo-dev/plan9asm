package plan9asm

import (
	"fmt"
	"strings"
)

// Every named GP/X consumer shares exact width and encoding writeback rules.
// Raw VMOVW retains its separate, decoder-bound 16-bit role.
func (c *amd64Ctx) lowerVectorScalarIntegerMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("contradictory GP/X transfer dispatch %s/%s", op, ins.Op)
	}
	f, known, err := x86GPSIMDTransferProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if f.mmx && (ins.x86Encoded || ins.x86SourceRaw != nil) {
		// A physical X-to-MMX destination remains native x87/MMX state;
		// no source-compatible spelling grants a virtual GP register slot.
		return true, false, fmt.Errorf("%w: raw Intel MOVDQ2Q requires its physical MMX/x87 entry and caller-state contract: %q", ErrProbeNeedsContext, ins.Raw)
	}
	src, dst := ins.Args[0], ins.Args[1]
	if f.memory >= 0 && ins.Args[f.memory].Kind == OpFP {
		if _, err := c.scalarFPSpan(ins.Args[f.memory].FPOffset, f.bits); err != nil {
			return true, false, err
		}
	}
	var low string
	if f.sourceX {
		low, err = c.loadXLowInteger(src.Reg, f.bits)
	} else {
		low, err = c.loadGPSIMDTransferSource(src, f.bits)
	}
	if err != nil {
		return true, false, err
	}
	if f.destinationX {
		lanes := 128 / f.bits
		inserted, bytes := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %s, i32 0\n", inserted, lanes, f.bits, f.bits, low)
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", bytes, lanes, f.bits, inserted)
		if f.spec.legacy {
			return true, false, c.storeX(dst.Reg, "%"+bytes)
		}
		return true, false, c.storePackedMoveOperand(dst, 16, "%"+bytes)
	}
	if f.mmx {
		return true, false, c.storeReg(dst.Reg, low)
	}
	if dst.Kind == OpFP {
		return true, false, c.storeScalarFPBits(dst.FPOffset, f.bits, low)
	}
	return true, false, c.storeVMOVIntegerScalar(dst, f.bits, low)
}

func (c *amd64Ctx) loadGPSIMDTransferSource(source Operand, bits int) (string, error) {
	if source.Kind == OpFP {
		return c.loadScalarFPBits(source.FPOffset, bits)
	}
	var pointer, pointerType string
	var err error
	switch source.Kind {
	case OpMem:
		pointer, pointerType, err = c.ptrFromMem(source.Mem)
	case OpSym:
		pointer, err = c.ptrFromSB(source.Sym)
		pointerType = "ptr"
	default:
		return c.evalIntSized(source, amd64IntegerTypeForBits(bits))
	}
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	// Unmasked MOVD/Q reads are observable at their original width even
	// when the destination is dead. They have no alignment or MXCSR effect.
	fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %s, align 1\n", value, bits, pointerType, pointer)
	return "%" + value, nil
}

func isAMD64GoXRegister(operand Operand) bool {
	if operand.Kind != OpReg {
		return false
	}
	_, ok := amd64ParseXReg(operand.Reg)
	return ok
}

func (c *amd64Ctx) storeVMOVIntegerScalar(dst Operand, bits int, value string) error {
	typ := amd64IntegerTypeForBits(bits)
	if dst.Kind == OpMem || dst.Kind == OpSym {
		var pointer, pointerType string
		var err error
		if dst.Kind == OpMem {
			pointer, pointerType, err = c.ptrFromMem(dst.Mem)
		} else {
			pointer, err = c.ptrFromSB(dst.Sym)
			pointerType = "ptr"
		}
		if err != nil {
			return err
		}
		// Keep each original unmasked native store, including overwritten
		// stores or private symbols whose value becomes otherwise dead.
		fmt.Fprintf(c.b, "  store volatile %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
		return nil
	}
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
