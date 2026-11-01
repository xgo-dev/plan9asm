package plan9asm

import (
	"fmt"
	"strings"
)

// FPCR/FPSR are native floating-point state, separate from the modeled NZCV
// bank. Their exact register transfers have no implicit GP, SIMD or data-store
// effects. This registration does not extend to other system registers.
type arm64FPControlForm struct {
	read     bool
	encoding uint16
	reg      Reg
}

func arm64FPControlEncoding(name string) (uint16, bool) {
	switch name {
	case "FPCR":
		return 0x5a20, true
	case "FPSR":
		return 0x5a21, true
	default:
		return 0, false
	}
}

func parseARM64FPControl(op Op, instruction Instr) (arm64FPControlForm, bool, error) {
	if op != "MRS" && op != "MSR" {
		return arm64FPControlForm{}, false, nil
	}
	matched := false
	for _, operand := range instruction.Args {
		if operand.Kind == OpIdent {
			name := strings.ToUpper(operand.Ident)
			_, known := arm64FPControlEncoding(name)
			// Printed physical names are a raw-decoder role, not accepted Go
			// source aliases. Claim them only to reject the malformed source.
			matched = matched || known || name == "S3_3_C4_C4_0" || name == "S3_3_C4_C4_1"
		}
	}
	if !matched {
		return arm64FPControlForm{}, false, nil
	}
	bad := func() (arm64FPControlForm, bool, error) {
		return arm64FPControlForm{}, true, fmt.Errorf("arm64 %s FPCR/FPSR requires its system-register/GP pair without a suffix: %q", op, instruction.Raw)
	}
	if instruction.Op != op || len(instruction.Args) != 2 {
		return bad()
	}
	form := arm64FPControlForm{read: op == "MRS"}
	system, data := instruction.Args[0], instruction.Args[1]
	if !form.read {
		system, data = data, system
	}
	var known bool
	form.encoding, known = arm64FPControlEncoding(system.Ident)
	if system.Kind != OpIdent || !known {
		return bad()
	}
	if !form.read && data.Kind == OpImm && data.Imm == 0 && data.ImmRaw == "" && !data.ImmIsFloat {
		// Go's C_ZCON inherits the C_ZREG case36, not the immediate PSTATE
		// case37. No nonzero or floating immediate has this role.
		form.reg = ZR
	} else if data.Kind == OpReg && isARM64GeneralOrZeroReg(data.Reg) {
		form.reg = data.Reg
	} else {
		return bad()
	}
	return form, true, nil
}

func arm64RawFPControl(form arm64RawSystemRegister) (arm64FPControlForm, bool) {
	if form.encoding != 0x5a20 && form.encoding != 0x5a21 {
		return arm64FPControlForm{}, false
	}
	register := ZR
	if form.reg != 31 {
		register = Reg(fmt.Sprintf("R%d", form.reg))
	}
	return arm64FPControlForm{form.read, form.encoding, register}, true
}

func (c *arm64Ctx) lowerARM64FPControl(form arm64FPControlForm) error {
	if (form.encoding != 0x5a20 && form.encoding != 0x5a21) || !isARM64GeneralOrZeroReg(form.reg) {
		return fmt.Errorf("arm64 invalid FPCR/FPSR transfer form")
	}
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		return fmt.Errorf("%w: FPCR/FPSR transfers require an explicit native little-endian AArch64 target", ErrProbeNeedsContext)
	}
	system := arm64EncodedSystemRegisterName(form.encoding)
	if form.read {
		value := c.newTmp()
		format := "  %%%s = call i64 asm sideeffect %q, %q()\n"
		if form.reg == "R18" || form.reg == "R28" {
			// A physical platform/g destination still has no typed entry
			// role. Do not remove its original opaque-machine boundary.
			fmt.Fprintf(c.b, format, value, "mrs $0, "+system, "=r,~{memory}")
		} else {
			c.emitMachineNeutralNativeIR(format, value, "mrs $0, "+system, "=r,~{memory}")
		}
		return c.storeReg(form.reg, "%"+value)
	}
	value := "0"
	if form.reg != ZR {
		var err error
		value, err = c.loadReg(form.reg)
		if err != nil {
			return err
		}
	}
	// Preserve the actual write even when no later floating operation reads
	// it. The barrier orders other native FP operations; it is not a store
	// into the source function's private or caller memory.
	c.emitMachineNeutralNativeIR("  call void asm sideeffect %q, %q(i64 %s)\n",
		"msr "+system+", $0", "r,~{memory}", value)
	return nil
}

func validateARM64FPControlTarget(file *File, options Options) error {
	if file == nil || file.Arch != ArchARM64 {
		return nil
	}
	needsNative := false
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			_, matched, err := parseARM64FPControl(arm64ControlOp(instruction), instruction)
			if err != nil {
				return err
			}
			needsNative = needsNative || matched
			if instruction.Op != OpWORD || len(instruction.Args) != 1 || instruction.Args[0].Kind != OpImm ||
				instruction.Args[0].ImmRaw != "" || instruction.Args[0].ImmIsFloat {
				continue
			}
			if raw, valid := decodeARM64RawSystemRegister(uint32(instruction.Args[0].Imm)); valid {
				_, matched := arm64RawFPControl(raw)
				needsNative = needsNative || matched
			}
		}
	}
	if !needsNative {
		return nil
	}
	// Only this family's files need another raw syntax pass. Check the whole
	// source before target context, including unreachable malformed WORDs.
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			if err := arm64RawWordPreflightError(instruction); err != nil {
				return err
			}
		}
	}
	if !arm64ScalarConversionNativeTarget(options.TargetTriple) || options.Goarch != "" && options.Goarch != "arm64" {
		return fmt.Errorf("%w: FPCR/FPSR transfers require an explicit native little-endian AArch64 target, got %q/%q",
			ErrProbeNeedsContext, options.Goarch, options.TargetTriple)
	}
	return nil
}
