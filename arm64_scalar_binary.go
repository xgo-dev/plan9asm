package plan9asm

import (
	"fmt"
	"strings"
)

type arm64ScalarBinarySpec struct {
	opcode string
	bits   int
}

// Go asm7 case 54 shares both FREG,FREG and FREG,FREG,FREG rows.
// H is a separately authenticated WORD encoding, not a named Go spelling.
var arm64ScalarBinarySpecs = map[Op]arm64ScalarBinarySpec{
	"FADDS": {"fadd", 32}, "FADDD": {"fadd", 64},
	"FSUBS": {"fsub", 32}, "FSUBD": {"fsub", 64},
	"FMULS": {"fmul", 32}, "FMULD": {"fmul", 64},
	"FNMULS": {"fnmul", 32}, "FNMULD": {"fnmul", 64},
	"FDIVS": {"fdiv", 32}, "FDIVD": {"fdiv", 64},
}

type arm64ScalarBinaryForm struct {
	arm64ScalarBinarySpec
	first, second, destination Reg
}

func parseARM64ScalarBinary(op Op, instruction Instr) (arm64ScalarBinaryForm, bool, error) {
	spec, matched := arm64ScalarBinarySpecs[op]
	if !matched {
		return arm64ScalarBinaryForm{}, false, nil
	}
	if strings.ToUpper(string(instruction.Op)) != string(op) || len(instruction.Args) != 2 && len(instruction.Args) != 3 {
		return arm64ScalarBinaryForm{}, true, fmt.Errorf("arm64 %s expects Fsrc,Fdst or Fsrc1,Fsrc2,Fdst and no suffix: %q", op, instruction.Raw)
	}
	for _, operand := range instruction.Args {
		if operand.Kind != OpReg || !isARM64FReg(operand.Reg) {
			return arm64ScalarBinaryForm{}, true, fmt.Errorf("arm64 %s accepts only F registers: %q", op, instruction.Raw)
		}
	}
	return arm64ScalarBinaryForm{spec, instruction.Args[1].Reg, instruction.Args[0].Reg, instruction.Args[len(instruction.Args)-1].Reg}, true, nil
}

func arm64ScalarBinaryOpcode(kind string) string {
	switch kind {
	case "add", "sub", "mul", "nmul", "div":
		return "f" + kind
	default:
		return ""
	}
}

func (c *arm64Ctx) recordARM64ScalarBinary(form arm64ScalarBinaryForm) func() {
	flow := c.machineAvailability
	if flow == nil || flow.flagsOnly || flow.suspended != 0 {
		return func() {}
	}
	c.recordMachineRegister(form.first, form.bits, false)
	c.recordMachineRegister(form.second, form.bits, false)
	// FPCR.NEP can copy the first source's upper bits, not the old destination.
	// Preserve their exact definedness without inventing or requiring dead bits.
	flow.blocks[flow.current].effects = append(flow.blocks[flow.current].effects,
		arm64MachineEffect{register: arm64MachineRegister(form.destination), copyFrom: arm64MachineRegister(form.first),
			width: 128, write: true, vectorSpan: true, source: flow.source},
		arm64MachineEffect{register: arm64MachineRegister(form.destination), width: form.bits,
			write: true, vectorSpan: true, source: flow.source},
	)
	flow.suspended++
	return func() { flow.suspended-- }
}

func (c *arm64Ctx) lowerARM64ScalarBinary(form arm64ScalarBinaryForm) error {
	if form.bits != 16 && form.bits != 32 && form.bits != 64 {
		return fmt.Errorf("arm64 invalid scalar binary width %d", form.bits)
	}
	switch form.opcode {
	case "fadd", "fsub", "fmul", "fnmul", "fdiv":
	default:
		return fmt.Errorf("arm64 invalid scalar binary operation %q", form.opcode)
	}
	for _, register := range []Reg{form.first, form.second, form.destination} {
		if !isARM64FReg(register) {
			return fmt.Errorf("arm64 invalid scalar binary register %q", register)
		}
	}
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		return fmt.Errorf("%w: ARM64 scalar binary requires an explicit native little-endian AArch64 FPCR/FPSR target", ErrProbeNeedsContext)
	}
	finish := c.recordARM64ScalarBinary(form)
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
	// DDI0602: native scalar arithmetic observes FPCR, accumulates FPSR and
	// can trap even when its value is dead. IsMerging(FPCR) copies V[n]'s high
	// bits. Tie the full first source to the output to preserve that identity.
	// The compiler barrier orders MRS/MSR; it grants no data-memory access and
	// does not change the independently tracked NZCV bank.
	c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(<16 x i8> %s, <16 x i8> %s)\n",
		result, operation, "=w,0,w,~{memory}", first, second)
	return c.storeVReg(form.destination, "%"+result)
}

func validateARM64ScalarBinaryTarget(file *File, options Options) error {
	if file == nil || file.Arch != ArchARM64 {
		return nil
	}
	needsNative := false
	var rawError error
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			if instruction.Op == OpWORD && rawError == nil {
				rawError = arm64RawWordPreflightError(instruction)
			}
			_, matched, err := parseARM64ScalarBinary(arm64ControlOp(instruction), instruction)
			if err != nil {
				return err
			}
			needsNative = needsNative || matched
			if instruction.Op != OpWORD || len(instruction.Args) != 1 || instruction.Args[0].Kind != OpImm ||
				instruction.Args[0].ImmRaw != "" || instruction.Args[0].ImmIsFloat {
				continue // Unidentified WORDs retain their generic source validator.
			}
			word := uint32(instruction.Args[0].Imm)
			switch word & 0xff20fc00 {
			case 0x1e200800, 0x1e201800, 0x1e202800, 0x1e203800, 0x1e208800:
				form, valid := decodeARM64RawScalarFloatBinary(word)
				if !valid || arm64ScalarBinaryOpcode(form.kind) == "" {
					return fmt.Errorf("unsupported ARM64 scalar binary WORD encoding %#08x: %q", word, instruction.Raw)
				}
				needsNative = true
			}
		}
	}
	if needsNative && rawError != nil {
		return rawError // Illegal/dead WORD syntax is not native-target Context.
	}
	if needsNative && (!arm64ScalarConversionNativeTarget(options.TargetTriple) || options.Goarch != "" && options.Goarch != "arm64") {
		return fmt.Errorf("%w: ARM64 scalar binary requires an explicit native little-endian AArch64 FPCR/FPSR target, got %q/%q",
			ErrProbeNeedsContext, options.Goarch, options.TargetTriple)
	}
	return nil
}
