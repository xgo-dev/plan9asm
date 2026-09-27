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

func (c *arm64Ctx) lowerARM64Prefetch(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op == "RPRFM" {
		return c.lowerARM64RangePrefetch(ins)
	}
	if op != "PRFM" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "PRFM" || len(ins.Args) != 2 || ins.Args[0].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 PRFM expects unsigned-scaled memory and a prefetch operation, with no suffix: %q", ins.Raw)
	}
	memory := ins.Args[0].Mem
	validBase := isARM64GeneralOrZeroReg(memory.Base) || memory.Base == SP || memory.Base == Reg("RSP")
	if !validBase || memory.Sym != "" || memory.Index != "" || memory.OffRaw != "" || !arm64PRFMOffsetAccepted(memory.Off) {
		return true, false, fmt.Errorf("arm64 PRFM address is outside Go's C_UOREG32K class: %q", ins.Raw)
	}

	var hint uint8
	switch operation := ins.Args[1]; operation.Kind {
	case OpIdent:
		name := arm64PrefetchOperation(strings.ToUpper(strings.TrimSpace(operation.Ident)))
		value, exists := arm64PrefetchOperations[name]
		if !exists {
			return true, false, fmt.Errorf("arm64 PRFM operation %q is outside Go's prfopfield table: %q", name, ins.Raw)
		}
		hint = value
	case OpImm:
		if operation.ImmRaw != "" || operation.Imm < 0 || operation.Imm > 31 {
			return true, false, fmt.Errorf("arm64 PRFM numeric operation must be in [0,31]: %q", ins.Raw)
		}
		hint = uint8(operation.Imm)
	default:
		return true, false, fmt.Errorf("arm64 PRFM operation must be a Go prfop name or $0..$31: %q", ins.Raw)
	}

	baseReg := memory.Base
	if baseReg == ZR {
		// Register number 31 in an AArch64 memory operand denotes SP. Go's
		// parser accepts ZR here and its encoder consequently emits SP.
		baseReg = SP
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return true, false, err
	}
	// Go's case-91 encoder shifts directly and therefore discards the low
	// three offset bits without issuing offsetshift's usual odd-offset error.
	encodedOffset := memory.Off &^ 7
	assembly := fmt.Sprintf("prfm #%d, [$0, #%d]", hint, encodedOffset)
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", assembly, "r,~{memory}", base)
	return true, false, nil
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
	baseValue, err := c.loadReg(base)
	if err != nil {
		return true, false, err
	}
	rangeValue, err := c.loadReg(rangeRegister)
	if err != nil {
		return true, false, err
	}
	assembly := fmt.Sprintf("rprfm #%d, $1, [$0]", hint)
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s, i64 %s)\n", assembly, "r,r,~{memory}", baseValue, rangeValue)
	return true, false, nil
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
