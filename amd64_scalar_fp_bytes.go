package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

// These are logical ABI0 field views, not a pointer to a native incoming frame.
// Every byte is resolved independently, so neither padding nor a pointer field
// acquires numeric permissions from an adjacent scalar. Signedness is absent
// here: MOVSS/MOVSD transport bits and do not perform numeric conversions.
func (c *amd64Ctx) scalarFPSpan(off int64, bits int) (bool, error) {
	fail := func(reason string) (bool, error) {
		return false, fmt.Errorf("%w: scalar FP bit view at +%d(FP): %s", ErrProbeNeedsContext, off, reason)
	}
	if bits != 32 && bits != 64 || off < 0 || off > math.MaxInt64-int64(bits/8) {
		return fail("invalid or overflowing byte span")
	}
	result := false
	for current := off; current < off+int64(bits/8); current++ {
		matches := 0
		for _, group := range []struct {
			slots  []FrameSlot
			result bool
		}{{c.sig.Frame.Params, false}, {c.fpResults, true}} {
			for _, slot := range group.slots {
				width := x86FrameTypeSize(slot.Type)
				if slot.Type == Ptr {
					width = int64(goWordSize(c.goarch))
				}
				if width <= 0 || slot.Offset < 0 || slot.Offset > math.MaxInt64-width {
					return fail("invalid typed field extent")
				}
				if current < slot.Offset || current >= slot.Offset+width {
					continue
				}
				switch slot.Type {
				case I8, I16, I32, I64, LLVMType("float"), LLVMType("double"):
				default:
					return fail("byte is not a declared integer or floating scalar")
				}
				matches++
				result = result || group.result
			}
		}
		if matches != 1 {
			return fail(fmt.Sprintf("byte %d has %d declared fields", current, matches))
		}
	}
	return result, nil
}

func (c *amd64Ctx) scalarFPResultInitialized() error {
	if !c.fpScalarChecked {
		c.fpScalarChecked = true
		c.fpScalarCheckErr = c.checkLoweredScalarFPResultInitialization()
	}
	return c.fpScalarCheckErr
}

// A full store may span multiple independently allocated result fields. It
// preserves the existing whole-field writer contract only when every touched
// result field is completely overwritten; covering one field's prefix is not
// enough. scalarFPSpan has already checked extent arithmetic and every byte.
func (c *amd64Ctx) scalarFPStoreCoversResultFields(off int64, bits int) bool {
	end := off + int64(bits/8)
	for _, slot := range c.fpResults {
		slotEnd := slot.Offset + x86FrameTypeSize(slot.Type)
		if off < slotEnd && slot.Offset < end && (off > slot.Offset || end < slotEnd) {
			return false
		}
	}
	return true
}

// Preserve only the existing complete floating-field writer contract. A new
// integer, mixed, or subfield bit view cannot borrow that contract to read an
// undefined X register, even when its store overwrites the whole result.
func (c *amd64Ctx) scalarFPStoreCoversFloatingFields(off int64, bits int) bool {
	end := off + int64(bits/8)
	for _, slots := range [][]FrameSlot{c.sig.Frame.Params, c.fpResults} {
		for _, slot := range slots {
			slotEnd := slot.Offset + x86FrameTypeSize(slot.Type)
			if off >= slotEnd || slot.Offset >= end {
				continue
			}
			if slot.Type != LLVMType("float") && slot.Type != LLVMType("double") ||
				off > slot.Offset || end < slotEnd {
				return false
			}
		}
	}
	return true
}

// All logical scalar consumers share this role decision. A new parameter
// byte view cannot evade must-initialized source checking by subsequently
// writing an old, complete floating result field. The exact natural inputs
// below are the pre-existing scalar contracts, not native frame backing.
func (c *amd64Ctx) scalarFPViewNeedsInitialization(off int64, bits int, write bool) (bool, error) {
	result, err := c.scalarFPSpan(off, bits)
	if err != nil {
		return false, err
	}
	if write {
		return !c.scalarFPStoreCoversFloatingFields(off, bits) ||
			result && !c.scalarFPStoreCoversResultFields(off, bits), nil
	}
	if result {
		return true, nil
	}
	first, found := c.fpParam(off)
	if !found {
		return true, nil
	}
	if bits == 32 && (first.Type == I32 || first.Type == LLVMType("float")) ||
		bits == 64 && (first.Type == I64 || first.Type == LLVMType("double")) {
		return false, nil
	}
	if bits == 64 && first.Type == LLVMType("float") {
		second, found := c.fpParam(off + 4)
		if found && second.Type == LLVMType("float") {
			return false, nil
		}
	}
	return true, nil
}

func (c *amd64Ctx) validateScalarFPSourceViews() error {
	if err := c.validateMixedBoolResultRole(); err != nil {
		return err
	}
	if x86OrdinaryIntegerFPStoreNeedsProof(c.fpScalarSource, c.sig, c.goarch) {
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	if x86TypedFPResultNeedsProof(c.fpScalarSource, c.sig, c.goarch) {
		if err := c.integerEffectResultInitialized("typed numerical effect"); err != nil {
			return err
		}
	}
	if c.sig.amd64GoArguments != nil {
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	if c.fpScalarSource.x86ContinuationFlow != nil {
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	if c.fpScalarSource.x86SourceStack != nil && c.sig.Ret == I1 {
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	if _, valid := x86DirectTailResultRegion(c.fpScalarSource, c.sig, c.goarch); valid {
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	if x86OrdinaryResultAddressNeedsProof(c.fpScalarSource, c.sig, c.goarch) ||
		x86OrdinaryParameterAddressNeedsProof(c.fpScalarSource, c.sig, c.goarch) {
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	// A logical i1 return cannot bypass canonical Go-byte/result validation
	// merely because the complete body contains no FP/SIMD view. The independent
	// ABI0 role requires its complete canonical declared-byte proof too.
	if x86RegisterBoolResultNeedsProof(c.fpScalarSource, c.sig, c.goarch) || x86ABI0BoolResultNeedsProof(c.sig, c.goarch) {
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	integerResult := false
	for _, slot := range c.fpResults {
		if slot.Type == I8 || slot.Type == I16 || slot.Type == I32 || slot.Type == I64 {
			integerResult = true
			break
		}
	}
	for _, ins := range c.fpScalarSource.Instrs {
		if x86LogicalPackedFPStoreBytes(ins, c.goarch) != 0 {
			if err := c.scalarFPResultInitialized(); err != nil {
				return err
			}
		}
		if _, known, err := x86TimestampProperties(ins.Op, ins, c.goarch); c.sig.Ret == Void && known && err == nil {
			if err := c.scalarFPResultInitialized(); err != nil {
				return err
			}
		}
		if width := x86IntegerFPMoveWidth(ins, c.goarch); width != 0 && len(ins.Args) == 2 {
			for index, operand := range ins.Args {
				if operand.Kind == OpFP {
					if _, err := c.integerFPByteView(operand.FPOffset, width, index == 1); err != nil {
						return err
					}
				}
			}
		}
		if _, known, err := x86ByteSwapProperties(ins.Op, ins, c.goarch); c.sig.Ret != Void && known && err == nil {
			if err := c.byteSwapResultInitialized(); err != nil {
				return err
			}
		}
		if _, known, err := x86SignedIntegerFloatProperties(ins, c.goarch); integerResult && known && err == nil {
			if err := c.scalarFPResultInitialized(); err != nil {
				return err
			}
		}
		if _, known, err := x86UnsignedIntegerFloatProperties(ins, c.goarch); integerResult && known && err == nil {
			if err := c.scalarFPResultInitialized(); err != nil {
				return err
			}
		}
		if _, known, err := x86MXCSRProperties(ins, c.goarch); known && err == nil {
			if err := c.scalarFPResultInitialized(); err != nil {
				return err
			}
		}
		if _, known, err := amd64PackedStringCompareProperties(ins.Op, ins, c.goarch); integerResult && known && err == nil {
			if err := c.scalarFPResultInitialized(); err != nil {
				return err
			}
		}
		if integerResult && x86ResultCallerAddressDifferenceNeedsProof(ins, c.sig, c.goarch) {
			if err := c.scalarFPResultInitialized(); err != nil {
				return err
			}
		}
		if _, known, err := x86ScalarBitScanProperties(ins.Op, ins, c.goarch); integerResult && known && err == nil {
			if err := c.scalarFPResultInitialized(); err != nil {
				return err
			}
		}
		if form, known, err := x86GPSIMDTransferProperties(ins, c.goarch); integerResult && known && err == nil {
			staticStore := form.memoryWrite && x86ScalarFPStaticSymbolMemory(ins.Args[form.memory])
			ordinaryRegister := form.memory < 0 && !form.mmx && !form.spec.rawOnly &&
				ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpReg &&
				!ins.x86Encoded && ins.x86SourceRaw == nil && ins.x86RawNearReturn == nil &&
				ins.x86AddressBits == 0 && !ins.x86UnboundAddressOverride && ins.x86SegmentPrefix == 0
			if staticStore || ordinaryRegister {
				// Register-only GP/X moves can feed an ordinary GP-to-FP
				// result store without a later lane probe. Sparse numerical
				// bytes require the same complete, cached source proof. This
				// grants no raw/MMX/native role or canonical bool knowledge.
				// Static stores retain their existing independent trigger.
				if err := c.scalarFPResultInitialized(); err != nil {
					return err
				}
			}
		}
		form, recognized, err := amd64ScalarVectorMoveProperties(ins, c.goarch)
		if !recognized || err != nil || form.spec.rawOnly || form.memory < 0 {
			continue // The normal dispatcher retains malformed/raw-family errors.
		}
		operand := ins.Args[form.memory]
		if operand.Kind != OpFP {
			continue
		}
		needs, err := c.scalarFPViewNeedsInitialization(operand.FPOffset, form.spec.bits, form.memoryWrite)
		if err != nil {
			return err
		}
		if form.mask >= 0 || needs {
			if err := c.scalarFPResultInitialized(); err != nil {
				return err
			}
		}
	}
	return nil
}

// This is only a reason to require the complete result proof. A validated
// ordinary SB role can have either parser representation; its grouped spelling
// grants neither an address envelope nor an FP/result alias to that proof.
func x86ScalarFPStaticSymbolMemory(operand Operand) bool {
	var symbol string
	switch operand.Kind {
	case OpSym:
		symbol = operand.Sym
	case OpMem:
		symbol = operand.Mem.Sym
	default:
		return false
	}
	return strings.HasSuffix(strings.TrimSpace(symbol), "(SB)")
}

func (c *amd64Ctx) loadScalarFPBits(off int64, bits int) (string, error) {
	needs, err := c.scalarFPViewNeedsInitialization(off, bits, false)
	if err != nil {
		return "", err
	}
	if needs {
		if err := c.scalarFPResultInitialized(); err != nil {
			return "", err
		}
	}
	bytes, err := c.loadFPVectorBytes(off, bits/8)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", value, bits/8, bytes, bits)
	return "%" + value, nil
}

func (c *amd64Ctx) storeScalarFPBits(off int64, bits int, value string) error {
	needs, err := c.scalarFPViewNeedsInitialization(off, bits, true)
	if err != nil {
		return err
	}
	// Only complete floating-field stores retain the existing contract. New
	// numeric bit views must prove the source as well as the result bytes;
	// whole overwrite does not initialize an unknown source register.
	if needs {
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to <%d x i8>\n", bytes, bits, value, bits/8)
	return c.storeFPVectorBytes(off, bits/8, "%"+bytes, "")
}

func (c *amd64Ctx) storeScalarFPFloat(off int64, bits int, value string) error {
	if _, err := c.scalarFPSpan(off, bits); err != nil {
		return err
	}
	typ := "float"
	if bits == 64 {
		typ = "double"
	}
	integer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", integer, typ, value, bits)
	return c.storeScalarFPBits(off, bits, "%"+integer)
}
