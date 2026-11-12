package plan9asm

import (
	"fmt"
	"strings"
)

type arm64CacheOperation string

type arm64SystemFields struct {
	op1 uint8
	cm  uint8
	op2 uint8
}

// arm64CacheOperations mirrors exactly the cn=7 entries in Go's ARM64
// sysInstFields table. DC is a SYS alias whose second operand is mandatory for
// every operation currently accepted by Go.
var arm64CacheOperations = map[arm64CacheOperation]arm64SystemFields{
	"IVAC":    {0, 6, 1},
	"ISW":     {0, 6, 2},
	"CSW":     {0, 10, 2},
	"CISW":    {0, 14, 2},
	"ZVA":     {3, 4, 1},
	"CVAC":    {3, 10, 1},
	"CVAU":    {3, 11, 1},
	"CIVAC":   {3, 14, 1},
	"IGVAC":   {0, 6, 3},
	"IGSW":    {0, 6, 4},
	"IGDVAC":  {0, 6, 5},
	"IGDSW":   {0, 6, 6},
	"CGSW":    {0, 10, 4},
	"CGDSW":   {0, 10, 6},
	"CIGSW":   {0, 14, 4},
	"CIGDSW":  {0, 14, 6},
	"GVA":     {3, 4, 3},
	"GZVA":    {3, 4, 4},
	"CGVAC":   {3, 10, 3},
	"CGDVAC":  {3, 10, 5},
	"CGVAP":   {3, 12, 3},
	"CGDVAP":  {3, 12, 5},
	"CGVADP":  {3, 13, 3},
	"CGDVADP": {3, 13, 5},
	"CIGVAC":  {3, 14, 3},
	"CIGDVAC": {3, 14, 5},
	"CVAP":    {3, 12, 1},
	"CVADP":   {3, 13, 1},
}

type arm64CacheForm struct {
	operation arm64CacheOperation
	fields    arm64SystemFields
	address   Reg
}

func parseARM64CacheForm(op Op, ins Instr) (form arm64CacheForm, handled bool, err error) {
	if op != "DC" {
		return form, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "DC" || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpIdent || ins.Args[1].Kind != OpReg ||
		!isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return form, true, fmt.Errorf("arm64 DC expects a Go cache-operation name and one R/ZR operand, with no suffix: %q", ins.Raw)
	}
	form.operation = arm64CacheOperation(strings.ToUpper(strings.TrimSpace(ins.Args[0].Ident)))
	var exists bool
	form.fields, exists = arm64CacheOperations[form.operation]
	if !exists {
		return form, true, fmt.Errorf("arm64 DC operation %q is outside Go's sysInstFields table: %q", form.operation, ins.Raw)
	}
	form.address = ins.Args[1].Reg
	return form, true, nil
}

// Match the complete SYS alias encoding, not just its cache-operation field.
// The named and raw ZVA forms consume the same Go-derived metadata.
func decodeARM64RawDCZVA(word uint32) (arm64CacheForm, bool) {
	fields := arm64CacheOperations["ZVA"]
	encoding := uint32(0xd5080000) | uint32(fields.op1)<<16 | 7<<12 |
		uint32(fields.cm)<<8 | uint32(fields.op2)<<5
	if word & ^uint32(31) != encoding {
		return arm64CacheForm{}, false
	}
	address := Reg(fmt.Sprintf("R%d", word&31))
	if word&31 == 31 {
		address = ZR
	}
	return arm64CacheForm{operation: "ZVA", fields: fields, address: address}, true
}

func arm64DCZVAInstruction(form arm64CacheForm) Instr {
	return Instr{Op: "DC", Args: []Operand{
		{Kind: OpIdent, Ident: string(form.operation)}, {Kind: OpReg, Reg: form.address},
	}}
}

func (c *arm64Ctx) lowerARM64CacheMaintenance(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, handled, err := parseARM64CacheForm(op, ins)
	if !handled || err != nil {
		return handled, false, err
	}
	return true, false, c.lowerARM64CacheForm(form)
}

func (c *arm64Ctx) lowerARM64CacheForm(form arm64CacheForm) error {
	if form.operation == "ZVA" {
		if err := c.requireDCZVANoPrivateAddressSources(); err != nil {
			return err
		}
	}

	prefix := fmt.Sprintf("sys #%d, c7, c%d, #%d", form.fields.op1, form.fields.cm, form.fields.op2)
	emit := func(format string, args ...any) { fmt.Fprintf(c.b, format, args...) }
	if form.operation == "ZVA" && form.address != "R18" && form.address != "R28" {
		emit = c.emitMachineStoreNativeIR
	}
	if form.address == ZR {
		emit("  call void asm sideeffect %q, %q()\n", prefix+", xzr", "~{memory}")
		return nil
	}
	value, err := c.loadReg(form.address)
	if err != nil {
		return err
	}
	emit("  call void asm sideeffect %q, %q(i64 %s)\n", prefix+", $0", "r,~{memory}", value)
	return nil
}

// ZVA stores to a hardware-sized, downward-aligned granule. Virtual frame
// allocas cannot stand in for that physical extent. Until a stronger memory
// contract exists, scan the complete source/decoded CFG (even dead blocks),
// rejecting known syntactic sources of private frame/code/materialized-data
// addresses. This is bounded source proof, not a complete native-layout model.
// This does not promise that an external address has permission or is mapped:
// the real SYS instruction retains DZP, translation and hardware fault behavior.
func (c *arm64Ctx) requireDCZVANoPrivateAddressSources() error {
	return validateARM64DCZVAAddressSources(c.sourceGoFrame, c.frameSize, c.blocks, c.sourceData)
}

func validateARM64DCZVASource(fn Func, data []DataStmt) error {
	for _, original := range fn.Instrs {
		ins := arm64ControlDecode(original)
		form, handled, err := parseARM64CacheForm(arm64ControlOp(ins), ins)
		if handled && err == nil && form.operation == "ZVA" {
			return validateARM64DCZVAAddressSources(arm64SourceGoFrame(fn), fn.FrameSize, arm64SplitBlocks(fn), data)
		}
	}
	return nil
}

func validateARM64DCZVAAddressSources(frame arm64GoFrame, frameSize int64, blocks []arm64Block, data []DataStmt) error {
	context := func(source string) error {
		return fmt.Errorf("%w: ARM64 DC ZVA needs a physical extent contract for private frame/code/materialized-data address sources at %q", ErrProbeNeedsContext, source)
	}
	if frame.present || frameSize > 0 {
		return context("TEXT frame")
	}
	for _, datum := range data {
		if datum.Addr != "" {
			// SB loads can obtain a materialized object's address indirectly
			// through DATA relocations, without any address-of operand in this
			// function. Retain the complete file provenance in both gates;
			// neither pointee extent nor down-aligned neighbours are proved.
			return context(fmt.Sprintf("DATA %s+%d(SB)/%d,$%s", datum.Sym, datum.Off, datum.Width, datum.Addr))
		}
	}
	for _, block := range blocks {
		for _, original := range block.instrs {
			ins := arm64ControlDecode(original)
			op := arm64ControlOp(ins)
			switch op {
			case "CALL", "BL", "BLR", "ADR", "ADRP", OpWORD, "DWORD", arm64RawDataOp:
				return context(original.Raw)
			}
			for _, operand := range ins.Args {
				if operand.Kind == OpFP || operand.Kind == OpFPAddr {
					return context(original.Raw)
				}
				registers := []Reg{operand.Reg, operand.Mem.Base, operand.Mem.Index, operand.ShiftReg}
				registers = append(registers, operand.RegList...)
				if operand.Kind == OpSym {
					symbol := strings.TrimSpace(operand.Sym)
					if strings.HasPrefix(symbol, "$") && strings.Contains(symbol, "(SB)") {
						// A separately laid-out LLVM object's down-aligned zero
						// granule and neighbours lack a native-layout proof.
						// Ordinary SB reads/writes do not take this address.
						return context(original.Raw)
					}
					if memory, ok := parseMem(strings.TrimPrefix(symbol, "$")); ok {
						registers = append(registers, memory.Base, memory.Index)
					}
				}
				for _, reg := range registers {
					if reg == SP || reg == "RSP" || reg == PC ||
						(reg == "R30" && op != OpRET && op != "B" && op != "JMP") {
						return context(original.Raw)
					}
				}
			}
		}
	}
	return nil
}
