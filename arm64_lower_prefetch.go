package plan9asm

import (
	"fmt"
	"strings"
)

type arm64PrefetchOperation string

// arm64PrefetchOperations mirrors Go's prfopfield table.
var arm64PrefetchOperations = map[arm64PrefetchOperation]uint8{
	"PLDL1KEEP": 0,
	"PLDL1STRM": 1,
	"PLDL2KEEP": 2,
	"PLDL2STRM": 3,
	"PLDL3KEEP": 4,
	"PLDL3STRM": 5,
	"PLIL1KEEP": 8,
	"PLIL1STRM": 9,
	"PLIL2KEEP": 10,
	"PLIL2STRM": 11,
	"PLIL3KEEP": 12,
	"PLIL3STRM": 13,
	"PSTL1KEEP": 16,
	"PSTL1STRM": 17,
	"PSTL2KEEP": 18,
	"PSTL2STRM": 19,
	"PSTL3KEEP": 20,
	"PSTL3STRM": 21,
}

type arm64PrefetchKind uint8

const (
	arm64PrefetchScaled arm64PrefetchKind = iota
	arm64PrefetchUnscaled
	arm64PrefetchIndexed
	arm64PrefetchRange
)

type arm64PrefetchExtension struct {
	name  string
	width int
}

var arm64PrefetchExtensions = [...]arm64PrefetchExtension{
	{"uxtw", 32}, {"lsl", 64}, {"sxtw", 32}, {"sxtx", 64},
}

type arm64PrefetchForm struct {
	kind        arm64PrefetchKind
	base, index Reg
	hint        uint8
	offset      int64
	extension   arm64PrefetchExtension
	shift       int
}

func decodeARM64RawLiteralPrefetch(word uint32) (hint uint8, displacement int64, ok bool) {
	if word&0xff000000 != 0xd8000000 {
		return 0, 0, false
	}
	return uint8(word & 31), int64(int32(word<<8)>>13) * 4, true
}

func decodeARM64RawPrefetch(word uint32) (arm64PrefetchForm, bool) {
	var form arm64PrefetchForm
	form.hint = uint8(word & 31)
	switch {
	case word&0xffc00000 == 0xf9800000: // PRFM unsigned, scaled imm12.
		form.kind = arm64PrefetchScaled
		form.offset = int64(word>>10&0xfff) * 8
	case word&0xffe00c00 == 0xf8800000: // PRFUM signed, unscaled imm9.
		form.kind = arm64PrefetchUnscaled
		form.offset = int64(int32(word<<11) >> 23)
	case word&0xffe04c00 == 0xf8a04800: // Register class, option<1> must be set.
		form.index = arm64PrefetchRegister(word>>16&31, ZR)
		optionHigh, optionLow, scaled := word>>15&1, word>>13&1, word>>12&1
		if form.hint >= 24 { // Rt[4:3]=11 selects range, not an indexed hint.
			form.kind = arm64PrefetchRange
			form.hint = uint8(optionHigh<<5 | optionLow<<4 | scaled<<3 | word&7)
		} else {
			form.kind = arm64PrefetchIndexed
			form.extension = arm64PrefetchExtensions[optionHigh<<1|optionLow]
			form.shift = int(scaled) * 3
		}
	default:
		return arm64PrefetchForm{}, false // Literal PRFM needs a source layout proof.
	}
	form.base = arm64PrefetchRegister(word>>5&31, SP)
	return form, true
}

func arm64PrefetchRegister(encoded uint32, register31 Reg) Reg {
	if encoded == 31 {
		return register31
	}
	return Reg(fmt.Sprintf("R%d", encoded))
}

func (f arm64PrefetchForm) effects() arm64RawContinuationEffects {
	base, _ := arm64StackIndex(f.base)
	reads := arm64RawGPBit(base)
	if index, ok := arm64StackIndex(f.index); ok {
		reads |= arm64RawGPBit(index)
	}
	return arm64RawContinuationEffects{gpReads: reads, readsSP: base == 31}
}

func (c *arm64Ctx) lowerARM64Prefetch(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op == "RPRFM" {
		return c.lowerARM64RangePrefetch(ins)
	}
	if op != "PRFM" {
		return false, false, nil
	}
	if ins.arm64Encoded && len(ins.Args) == 2 && ins.Args[0].Kind == OpIdent && ins.Args[1].Kind == OpImm {
		address, err := c.arm64LocalPCAddress(ins.Args[0].Ident, op, ins.Raw)
		if err != nil {
			return true, false, err
		}
		// Both encodings issue the same nonfaulting hint. Materializing the
		// resolved address also handles moved data pools on Mach-O and COFF,
		// where LLVM cannot relocate a literal prefetch across sections.
		c.emitARM64PrefetchImmediate(arm64PrefetchUnscaled, uint8(ins.Args[1].Imm), 0, address)
		return true, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "PRFM" || len(ins.Args) != 2 || ins.Args[0].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 PRFM expects unsigned-scaled memory and a prefetch operation, with no suffix: %q", ins.Raw)
	}
	memory := ins.Args[0].Mem
	validBase := isARM64GeneralOrZeroReg(memory.Base) || memory.Base == SP || memory.Base == Reg("RSP")
	if !validBase || memory.Sym != "" || memory.Index != "" || memory.OffRaw != "" || !arm64PRFMOffsetAccepted(memory.Off) {
		return true, false, fmt.Errorf("arm64 PRFM address is outside Go's C_UOREG32K class: %q", ins.Raw)
	}

	form := arm64PrefetchForm{kind: arm64PrefetchScaled, base: memory.Base}
	if form.base == ZR {
		// Go accepts ZR as a base spelling, and the encoded Rn=31 denotes SP.
		form.base = SP
	}
	switch operation := ins.Args[1]; operation.Kind {
	case OpIdent:
		name := arm64PrefetchOperation(strings.ToUpper(strings.TrimSpace(operation.Ident)))
		value, exists := arm64PrefetchOperations[name]
		if !exists {
			return true, false, fmt.Errorf("arm64 PRFM operation %q is outside Go's prfopfield table: %q", name, ins.Raw)
		}
		form.hint = value
	case OpImm:
		if operation.ImmRaw != "" || operation.ImmIsFloat || operation.Imm < 0 || operation.Imm > 31 {
			return true, false, fmt.Errorf("arm64 PRFM numeric operation must be in [0,31]: %q", ins.Raw)
		}
		form.hint = uint8(operation.Imm)
	default:
		return true, false, fmt.Errorf("arm64 PRFM operation must be a Go prfop name or $0..$31: %q", ins.Raw)
	}

	// Go's case-91 encoder shifts directly and therefore discards the low
	// three offset bits without issuing offsetshift's usual odd-offset error.
	form.offset = memory.Off &^ 7
	return true, false, c.lowerARM64PrefetchForm(form)
}

var arm64RangePrefetchOperations = map[string]uint8{
	"PLDKEEP": 0,
	"PSTKEEP": 1,
	"PLDSTRM": 4,
	"PSTSTRM": 5,
}

func (c *arm64Ctx) lowerARM64RangePrefetch(ins Instr) (ok bool, terminated bool, err error) {
	if strings.ToUpper(string(ins.Op)) != "RPRFM" || len(ins.Args) != 3 || ins.Args[0].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 RPRFM expects (Rn), Rm, operation without a suffix: %q", ins.Raw)
	}
	memory := ins.Args[0].Mem
	base, baseOK := arm64SVEAddressReg(Operand{Kind: OpReg, Reg: memory.Base}, true)
	rangeRegister, rangeOK := arm64SVEAddressReg(ins.Args[1], false)
	if !baseOK || !rangeOK || memory.Sym != "" || memory.Off != 0 || memory.OffRaw != "" || memory.Index != "" {
		return true, false, fmt.Errorf("arm64 RPRFM requires an unoffset R0..R30/RSP base and R0..R30 range register: %q", ins.Raw)
	}
	var hint uint8
	switch operation := ins.Args[2]; operation.Kind {
	case OpIdent:
		var exists bool
		hint, exists = arm64RangePrefetchOperations[strings.ToUpper(strings.TrimSpace(operation.Ident))]
		if !exists {
			return true, false, fmt.Errorf("arm64 RPRFM operation must be PLDKEEP, PSTKEEP, PLDSTRM, or PSTSTRM: %q", ins.Raw)
		}
	case OpImm:
		if operation.ImmRaw != "" || operation.ImmIsFloat || operation.Imm < 0 || operation.Imm > 63 {
			return true, false, fmt.Errorf("arm64 RPRFM numeric operation must be in [0,63]: %q", ins.Raw)
		}
		hint = uint8(operation.Imm)
	default:
		return true, false, fmt.Errorf("arm64 RPRFM operation must be a range-prefetch name or $0..$63: %q", ins.Raw)
	}
	return true, false, c.lowerARM64PrefetchForm(arm64PrefetchForm{
		kind: arm64PrefetchRange, base: base, index: rangeRegister, hint: hint,
	})
}

func (c *arm64Ctx) lowerARM64PrefetchForm(form arm64PrefetchForm) error {
	base, err := c.loadReg(form.base)
	if err != nil {
		return err
	}
	if form.kind == arm64PrefetchScaled || form.kind == arm64PrefetchUnscaled {
		c.emitARM64PrefetchImmediate(form.kind, form.hint, form.offset, base)
		return nil
	}

	index := "$1"
	width := 64
	if form.kind == arm64PrefetchIndexed {
		width = form.extension.width
	}
	if form.index == ZR {
		index = "xzr"
		if width == 32 {
			index = "wzr"
		}
	} else if width == 32 {
		index = "${1:w}"
	}
	var assembly string
	if form.kind == arm64PrefetchRange {
		assembly = fmt.Sprintf("rprfm #%d, %s, [$0]", form.hint, index)
	} else {
		assembly = fmt.Sprintf("prfm #%d, [$0, %s, %s #%d]", form.hint, index, form.extension.name, form.shift)
	}
	if form.index == ZR {
		c.emitMachineNeutralNativeIR("  call void asm sideeffect %q, %q(i64 %s)\n", assembly, "r,~{memory}", base)
		return nil
	}
	indexValue, err := c.loadRegisterWidth(form.index, width)
	if err != nil {
		return err
	}
	c.emitMachineNeutralNativeIR("  call void asm sideeffect %q, %q(i64 %s, i64 %s)\n", assembly, "r,r,~{memory}", base, indexValue)
	return nil
}

func (c *arm64Ctx) emitARM64PrefetchImmediate(kind arm64PrefetchKind, hint uint8, offset int64, base string) {
	mnemonic := "prfm"
	if kind == arm64PrefetchUnscaled {
		mnemonic = "prfum"
	}
	assembly := fmt.Sprintf("%s #%d, [$0, #%d]", mnemonic, hint, offset)
	c.emitMachineNeutralNativeIR("  call void asm sideeffect %q, %q(i64 %s)\n", assembly, "r,~{memory}", base)
}

// arm64PRFMOffsetAccepted mirrors autoclass/oregclass plus cmp(C_UOREG32K,
// class) in Go's ARM64 backend. Some smaller compatible address classes admit
// offsets that are not multiples of eight; case 91 then truncates their low
// three bits.
func arm64PRFMOffsetAccepted(offset int64) bool {
	switch {
	case offset < 0:
		return false
	case offset <= 255:
		return true
	case offset <= 504:
		return offset%8 == 0
	case offset <= 1008:
		return offset%16 == 0
	case offset <= 32760:
		return offset%8 == 0
	default:
		return false
	}
}
