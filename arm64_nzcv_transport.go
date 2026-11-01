package plan9asm

import (
	"fmt"
	"strings"
)

// Arm DDI0601 NZCV: only PSTATE.N/Z/C/V in bits 31:28 are transported.
// The remaining read bits are zero and writes ignore them. This is the same
// modeled flag bank used by integer/FP compares and conditional consumers,
// never the incidental physical flags of LLVM's generated bookkeeping.
const arm64NZCVEncoding = 0x5a10

type arm64NZCVForm struct {
	read bool
	reg  Reg
}

func (form arm64NZCVForm) gpEffects() (reads, writes uint32) {
	if form.reg == ZR {
		return 0, 0
	}
	index, ok := arm64AtomicNumberedRegister(form.reg)
	if !ok {
		return 0, 0
	}
	if form.read {
		return 0, 1 << uint(index)
	}
	return 1 << uint(index), 0
}

func parseARM64NZCVForm(op Op, ins Instr) (arm64NZCVForm, bool, error) {
	if op != "MRS" && op != "MSR" {
		return arm64NZCVForm{}, false, nil
	}
	matched := false
	for _, argument := range ins.Args {
		if argument.Kind == OpIdent && (strings.EqualFold(argument.Ident, "NZCV") || strings.EqualFold(argument.Ident, "S3_3_C4_C2_0")) {
			// The physical assembler spelling is not a Go source alias. It
			// must not bypass this source-state role via the generic fallback.
			matched = true
		}
	}
	if !matched {
		return arm64NZCVForm{}, false, nil
	}
	bad := func() (arm64NZCVForm, bool, error) {
		return arm64NZCVForm{}, true, fmt.Errorf("arm64 %s NZCV expects its system-register/GP pair without a suffix: %q", op, ins.Raw)
	}
	if ins.Op != op || len(ins.Args) != 2 {
		return bad()
	}
	form := arm64NZCVForm{read: op == "MRS"}
	system, data := ins.Args[0], ins.Args[1]
	if !form.read {
		system, data = data, system
	}
	if system.Kind != OpIdent || system.Ident != "NZCV" {
		return bad()
	}
	if !form.read && data.Kind == OpImm && data.Imm == 0 && data.ImmRaw == "" && !data.ImmIsFloat {
		// Go's C_ZCON is compatible with case36's C_ZREG, not the
		// case37 PSTATE immediate encoding (which does not permit NZCV).
		form.reg = ZR
	} else if data.Kind == OpReg && isARM64GeneralOrZeroReg(data.Reg) {
		form.reg = data.Reg
	} else {
		return bad()
	}
	return form, true, nil
}

func decodeARM64RawNZCV(word uint32) (arm64NZCVForm, bool) {
	form, known := decodeARM64RawSystemRegister(word)
	if !known || form.encoding != arm64NZCVEncoding {
		return arm64NZCVForm{}, false
	}
	reg := ZR
	if form.reg != 31 {
		reg = Reg(fmt.Sprintf("R%d", form.reg))
	}
	return arm64NZCVForm{read: form.read, reg: reg}, true
}

func (c *arm64Ctx) lowerARM64NZCV(form arm64NZCVForm) error {
	if !form.read {
		value := "0"
		if form.reg != ZR {
			var err error
			value, err = c.loadRegisterWidth(form.reg, 32)
			if err != nil {
				return err
			}
		}
		c.storeARM64NativeCompareFlags(value)
		return nil
	}
	if form.reg == ZR {
		// An architectural NZCV read has no side effects. Discarding it
		// neither consumes an undefined entry value nor defines flags.
		return nil
	}
	if form.reg == "R18" || form.reg == "R28" {
		return arm64GoABIContext("MRS NZCV numerical output has no platform/g machine-state contract for %s", form.reg)
	}
	if err := c.requireARM64Flags(arm64FlagAll, "MRS NZCV"); err != nil {
		return err
	}
	value := "0"
	for index, slot := range []string{c.flagsVSlot, c.flagsCSlot, c.flagsZSlot, c.flagsNSlot} {
		c.recordMachineRegister(Reg(slot), 1, false)
		flag, extended, shifted, merged := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", flag, slot)
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", extended, flag)
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %d\n", shifted, extended, 28+index)
		fmt.Fprintf(c.b, "  %%%s = or i64 %s, %%%s\n", merged, value, shifted)
		value = "%" + merged
	}
	return c.storeReg(form.reg, value)
}
