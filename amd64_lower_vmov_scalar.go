package plan9asm

import (
	"fmt"
	"strings"
)

// lowerVectorScalarMove implements all Go 1.27 _yvmovsd forms shared by
// VMOVSD and VMOVSS: scalar loads/stores, three-register upper merges, and
// their EVEX masked variants.
func (c *amd64Ctx) lowerVectorScalarMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	elemBits := 0
	switch baseOp {
	case "VMOVSD":
		elemBits = 64
	case "VMOVSS":
		elemBits = 32
	case "VMOVSH":
		if !ins.x86Encoded {
			return true, false, fmt.Errorf("amd64 %s is not in Go's named assembler; use an encoded raw instruction: %q", baseOp, ins.Raw)
		}
		elemBits = 16
	default:
		return false, false, nil
	}
	if c.goarch == "386" && len(ins.Args) > 3 && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s exceeds Go's three-operand frontend limit: %q", baseOp, ins.Raw)
	}
	if suffix != "" && suffix != "Z" {
		return true, false, fmt.Errorf("amd64 %s suffix is absent from Go 1.27's _yvmovsd table: %q", baseOp, ins.Raw)
	}
	zeroing := suffix == "Z"
	switch len(ins.Args) {
	case 2:
		if zeroing {
			return true, false, fmt.Errorf("amd64 %s zeroing requires a K1-K7 mask and register destination: %q", baseOp, ins.Raw)
		}
		return c.lowerVectorScalarMoveTwoOperand(baseOp, elemBits, ins)
	case 3:
		if amd64ScalarXOperand(ins.Args[0]) && amd64ScalarXOperand(ins.Args[1]) && amd64ScalarXOperand(ins.Args[2]) {
			if zeroing {
				return true, false, fmt.Errorf("amd64 %s zeroing requires a K1-K7 mask: %q", baseOp, ins.Raw)
			}
			return c.lowerVectorScalarMoveRegisterMerge(elemBits, ins.Args[0], ins.Args[1], Operand{}, ins.Args[2], false)
		}
		return c.lowerVectorScalarMoveMaskedMemory(baseOp, elemBits, zeroing, ins)
	case 4:
		if !amd64ScalarXOperand(ins.Args[0]) || !amd64ScalarXOperand(ins.Args[1]) || !amd64ScalarXOperand(ins.Args[3]) {
			return true, false, fmt.Errorf("amd64 %s four-operand form expects X, X, K1-K7, X: %q", baseOp, ins.Raw)
		}
		if !amd64NonzeroKOperand(ins.Args[2]) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		return c.lowerVectorScalarMoveRegisterMerge(elemBits, ins.Args[0], ins.Args[1], ins.Args[2], ins.Args[3], zeroing)
	default:
		return true, false, fmt.Errorf("amd64 %s operand list is absent from Go 1.27's _yvmovsd table: %q", baseOp, ins.Raw)
	}
}

func (c *amd64Ctx) lowerVectorScalarMoveTwoOperand(baseOp string, elemBits int, ins Instr) (bool, bool, error) {
	src, dst := ins.Args[0], ins.Args[1]
	if amd64ScalarXOperand(src) && isAMD64MemoryOperand(dst) {
		value, err := c.loadXLowInteger(src.Reg, elemBits)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeVectorScalarMemory(dst, elemBits, value, "")
	}
	if isAMD64MemoryOperand(src) && amd64ScalarXOperand(dst) {
		value, err := c.evalIntSized(src, amd64IntegerTypeForBits(elemBits))
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeScalarMoveRegister(dst.Reg, elemBits, value, "zeroinitializer", "", false)
	}
	return true, false, fmt.Errorf("amd64 %s two-operand form requires X-to-memory or memory-to-X: %q", baseOp, ins.Raw)
}

func (c *amd64Ctx) lowerVectorScalarMoveMaskedMemory(baseOp string, elemBits int, zeroing bool, ins Instr) (bool, bool, error) {
	if !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s three-operand masked memory form expects K1-K7 in the middle: %q", baseOp, ins.Raw)
	}
	mask, err := c.loadK(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	if amd64ScalarXOperand(ins.Args[0]) && isAMD64MemoryOperand(ins.Args[2]) {
		if zeroing {
			return true, false, fmt.Errorf("amd64 %s cannot use .Z with a memory destination: %q", baseOp, ins.Raw)
		}
		value, err := c.loadXLowInteger(ins.Args[0].Reg, elemBits)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeVectorScalarMemory(ins.Args[2], elemBits, value, mask)
	}
	if isAMD64MemoryOperand(ins.Args[0]) && amd64ScalarXOperand(ins.Args[2]) {
		value, err := c.loadVectorScalarMemory(ins.Args[0], elemBits, mask)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeScalarMoveRegister(ins.Args[2].Reg, elemBits, value, "zeroinitializer", mask, zeroing)
	}
	return true, false, fmt.Errorf("amd64 %s masked memory form requires X, K, memory or memory, K, X: %q", baseOp, ins.Raw)
}

// A masked-off scalar move must not access memory at all. Selecting a loaded
// value afterwards does not suppress faults, and a read/modify/write store
// spuriously reads write-only memory even when the mask is active.
func (c *amd64Ctx) loadVectorScalarMemory(src Operand, elemBits int, mask string) (string, error) {
	condition := amd64MaskBitI1(c, mask, 0)
	return c.loadX86ScalarMemoryIf(src, elemBits, condition)
}

func (c *amd64Ctx) loadX86ScalarMemoryIf(src Operand, elemBits int, condition string) (string, error) {
	return c.loadX86ScalarIf(elemBits, condition, func() (string, error) {
		return c.evalIntSized(src, amd64IntegerTypeForBits(elemBits))
	})
}

func (c *amd64Ctx) loadX86ScalarIf(elemBits int, condition string, load func() (string, error)) (string, error) {
	loadLabel := c.newTmp() + "_scalar_load"
	skipLabel := c.newTmp() + "_scalar_skip"
	joinLabel := c.newTmp() + "_scalar_join"
	fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n%s:\n", condition, loadLabel, skipLabel, loadLabel)
	value, err := load()
	if err != nil {
		return "", err
	}
	fmt.Fprintf(c.b, "  br label %%%s\n%s:\n  br label %%%s\n%s:\n", joinLabel, skipLabel, joinLabel, joinLabel)
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = phi i%d [ %s, %%%s ], [ 0, %%%s ]\n", selected, elemBits, value, loadLabel, skipLabel)
	return "%" + selected, nil
}

func (c *amd64Ctx) lowerVectorScalarMoveRegisterMerge(elemBits int, lowSource, upperSource, maskArg, dst Operand, zeroing bool) (bool, bool, error) {
	low, err := c.loadXLowInteger(lowSource.Reg, elemBits)
	if err != nil {
		return true, false, err
	}
	upperBytes, err := c.loadX(upperSource.Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elemBits
	upper := c.bitcastVectorBytesToIntegerLanes(16, lanes, elemBits, upperBytes)
	mask := ""
	if maskArg.Kind == OpReg {
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}
	return true, false, c.storeScalarMoveRegister(dst.Reg, elemBits, low, upper, mask, zeroing)
}

func amd64ScalarXOperand(op Operand) bool {
	if op.Kind != OpReg {
		return false
	}
	index, ok := amd64ParseXReg(op.Reg)
	return ok && index < 32
}

func amd64NonzeroKOperand(op Operand) bool {
	if op.Kind != OpReg {
		return false
	}
	index, ok := amd64ParseKReg(op.Reg)
	return ok && index != 0
}

func (c *amd64Ctx) loadXLowInteger(reg Reg, elemBits int) (string, error) {
	bytesValue, err := c.loadX(reg)
	if err != nil {
		return "", err
	}
	lanes := 128 / elemBits
	values := c.bitcastVectorBytesToIntegerLanes(16, lanes, elemBits, bytesValue)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 0\n", low, lanes, elemBits, values)
	return "%" + low, nil
}

func (c *amd64Ctx) storeVectorScalarRegister(dst Reg, elemBits int, low, base, mask string, zeroing bool) error {
	lanes := 128 / elemBits
	if mask != "" {
		fallback := "0"
		if !zeroing {
			old, err := c.loadXLowInteger(dst, elemBits)
			if err != nil {
				return err
			}
			fallback = old
		}
		maskBit := amd64MaskBitI1(c, mask, 0)
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %s, i%d %s\n", selected, maskBit, elemBits, low, elemBits, fallback)
		low = "%" + selected
	}
	updated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 0\n", updated, lanes, elemBits, base, elemBits, low)
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", bytesValue, lanes, elemBits, updated)
	return c.storeX(dst, "%"+bytesValue)
}

func (c *amd64Ctx) storeScalarMoveRegister(dst Reg, elemBits int, low, base, mask string, zeroing bool) error {
	if err := c.storeVectorScalarRegister(dst, elemBits, low, base, mask, zeroing); err != nil {
		return err
	}
	// VEX/EVEX scalar writes clear bits above 127, unlike legacy MOVSS/SD.
	// Keep every live wider view coherent with the newly written low X value.
	index, _ := amd64ParseXReg(dst)
	for _, view := range []struct {
		bytes int
		slots map[int]string
	}{{32, c.yRegSlot}, {64, c.zRegSlot}} {
		if slot, live := view.slots[index]; live {
			bytesValue, err := c.loadX(dst)
			if err != nil {
				return err
			}
			indices := make([]string, view.bytes)
			for i := range indices {
				lane := i
				if lane >= 16 {
					lane = 16 // First byte of the zero second source.
				}
				indices[i] = fmt.Sprintf("i32 %d", lane)
			}
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> zeroinitializer, <%d x i32> <%s>\n", wide, bytesValue, view.bytes, strings.Join(indices, ", "))
			fmt.Fprintf(c.b, "  store <%d x i8> %%%s, ptr %s\n", view.bytes, wide, slot)
		}
	}
	return nil
}

func (c *amd64Ctx) storeVectorScalarMemory(dst Operand, elemBits int, value, mask string) error {
	if mask != "" {
		condition := amd64MaskBitI1(c, mask, 0)
		storeLabel := c.newTmp() + "_scalar_store"
		joinLabel := c.newTmp() + "_scalar_join"
		fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n%s:\n", condition, storeLabel, joinLabel, storeLabel)
		if err := c.storeVectorScalarMemory(dst, elemBits, value, ""); err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  br label %%%s\n%s:\n", joinLabel, joinLabel)
		return nil
	}
	switch dst.Kind {
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i%d %s, %s %s, align 1\n", elemBits, value, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i%d %s, ptr %s, align 1\n", elemBits, value, ptr)
		return nil
	case OpFP:
		return c.storeFPResult(dst.FPOffset, amd64IntegerTypeForBits(elemBits), value)
	default:
		return fmt.Errorf("expected scalar memory destination, got %s", dst.String())
	}
}
