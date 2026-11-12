package plan9asm

import (
	"fmt"
	"strings"
)

type arm64ScalarMinMaxSpec struct {
	opcode string
	bits   int
}

var arm64ScalarMinMaxSpecs = map[Op]arm64ScalarMinMaxSpec{
	"FMAXS": {"fmax", 32}, "FMAXD": {"fmax", 64},
	"FMINS": {"fmin", 32}, "FMIND": {"fmin", 64},
	"FMAXNMS": {"fmaxnm", 32}, "FMAXNMD": {"fmaxnm", 64},
	"FMINNMS": {"fminnm", 32}, "FMINNMD": {"fminnm", 64},
}

type arm64ScalarMinMaxForm struct {
	arm64ScalarMinMaxSpec
	first, second, destination Reg
}

func parseARM64ScalarMinMax(op Op, instruction Instr) (arm64ScalarMinMaxForm, bool, error) {
	spec, matched := arm64ScalarMinMaxSpecs[op]
	if !matched {
		return arm64ScalarMinMaxForm{}, false, nil
	}
	if strings.ToUpper(string(instruction.Op)) != string(op) || len(instruction.Args) != 2 && len(instruction.Args) != 3 {
		return arm64ScalarMinMaxForm{}, true, fmt.Errorf("arm64 %s expects Fsrc,Fdst or Fsrc1,Fsrc2,Fdst and no suffix: %q", op, instruction.Raw)
	}
	for _, operand := range instruction.Args {
		if operand.Kind != OpReg || !isARM64FReg(operand.Reg) {
			return arm64ScalarMinMaxForm{}, true, fmt.Errorf("arm64 %s accepts only F registers: %q", op, instruction.Raw)
		}
	}
	return arm64ScalarMinMaxForm{spec, instruction.Args[1].Reg, instruction.Args[0].Reg, instruction.Args[len(instruction.Args)-1].Reg}, true, nil
}

func arm64ScalarMinMaxOpcode(kind string) string {
	switch kind {
	case "maximum":
		return "fmax"
	case "minimum":
		return "fmin"
	case "maxnum":
		return "fmaxnm"
	case "minnum":
		return "fminnm"
	default:
		return ""
	}
}

func (c *arm64Ctx) recordARM64ScalarMinMax(form arm64ScalarMinMaxForm) func() {
	flow := c.machineAvailability
	if flow == nil || flow.flagsOnly || flow.suspended != 0 {
		return func() {}
	}
	c.recordMachineRegister(form.first, form.bits, false)
	c.recordMachineRegister(form.second, form.bits, false)
	// FPCR.NEP may copy V[n]'s upper bits to V[d]. Copy their definedness,
	// not old V[d]'s definition, without requiring unobserved upper inputs.
	flow.blocks[flow.current].effects = append(flow.blocks[flow.current].effects,
		arm64MachineEffect{register: arm64MachineRegister(form.destination), copyFrom: arm64MachineRegister(form.first),
			width: 128, write: true, vectorSpan: true, source: flow.source},
		arm64MachineEffect{register: arm64MachineRegister(form.destination), width: form.bits,
			write: true, vectorSpan: true, source: flow.source},
	)
	flow.suspended++
	return func() { flow.suspended-- }
}

func (c *arm64Ctx) lowerARM64ScalarMinMax(form arm64ScalarMinMaxForm) error {
	if form.bits != 16 && form.bits != 32 && form.bits != 64 {
		return fmt.Errorf("arm64 invalid scalar min/max width %d", form.bits)
	}
	switch form.opcode {
	case "fmax", "fmin", "fmaxnm", "fminnm":
	default:
		return fmt.Errorf("arm64 invalid scalar min/max operation %q", form.opcode)
	}
	for _, register := range []Reg{form.first, form.second, form.destination} {
		if !isARM64FReg(register) {
			return fmt.Errorf("arm64 invalid scalar min/max register %q", register)
		}
	}
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		return fmt.Errorf("%w: ARM64 scalar min/max requires an explicit native little-endian AArch64 FPCR/FPSR target", ErrProbeNeedsContext)
	}
	finish := c.recordARM64ScalarMinMax(form)
	defer finish()
	first, err := c.loadVReg(form.first)
	if err != nil {
		return err
	}
	second, err := c.loadVReg(form.second)
	if err != nil {
		return err
	}
	modifier := arm64ScalarConversionModifier(form.bits, false)
	operation := fmt.Sprintf("%s ${0:%s}, ${1:%s}, ${2:%s}", form.opcode, modifier, modifier, modifier)
	result := c.newTmp()
	// DDI0602 scalar FMIN/FMAX and numeric variants merge V[n], not V[d],
	// under IsMerging(FPCR). Tie the full first-source carrier to the output.
	// One native instruction preserves NaN priority, AH/FZ/DN and cumulative
	// FPSR/traps even with a dead result. The compiler barrier orders MRS/MSR;
	// it confers no memory permission and does not write NZCV.
	c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(<16 x i8> %s, <16 x i8> %s)\n",
		result, operation, "=w,0,w,~{memory}", first, second)
	return c.storeVReg(form.destination, "%"+result)
}

func validateARM64ScalarMinMaxTarget(file *File, options Options) error {
	if file == nil || file.Arch != ArchARM64 {
		return nil
	}
	needsNative := false
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			_, matched, err := parseARM64ScalarMinMax(arm64ControlOp(instruction), instruction)
			if err != nil {
				return err
			}
			needsNative = needsNative || matched
			if instruction.Op != OpWORD || len(instruction.Args) != 1 || instruction.Args[0].Kind != OpImm ||
				instruction.Args[0].ImmRaw != "" || instruction.Args[0].ImmIsFloat {
				continue // Unidentified WORDs keep their generic source validator.
			}
			word := uint32(instruction.Args[0].Imm)
			if word&0xff20cc00 != 0x1e204800 {
				continue
			}
			form, valid := decodeARM64RawScalarFloatBinary(word)
			if !valid || arm64ScalarMinMaxOpcode(form.kind) == "" {
				return fmt.Errorf("unsupported ARM64 scalar min/max WORD encoding %#08x: %q", word, instruction.Raw)
			}
			needsNative = true
		}
	}
	if !needsNative {
		return nil
	}
	// Unrelated files retain their existing raw/source validator. Only this
	// native family needs the complete syntax pass before its target check.
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			if err := arm64RawWordPreflightError(instruction); err != nil {
				return err
			}
		}
	}
	if !arm64ScalarConversionNativeTarget(options.TargetTriple) || options.Goarch != "" && options.Goarch != "arm64" {
		return fmt.Errorf("%w: ARM64 scalar min/max requires an explicit native little-endian AArch64 FPCR/FPSR target, got %q/%q",
			ErrProbeNeedsContext, options.Goarch, options.TargetTriple)
	}
	return nil
}
