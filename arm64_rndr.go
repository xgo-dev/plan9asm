package plan9asm

import (
	"fmt"
	"strings"
)

// RNG reads share Go's MRS/MOVD C_SPR -> C_ZREG row, not a general system-
// register or caller-state permission. The raw Rt/reseed decoder remains the
// single numerical/status representation used by lowering and continuation.
func parseARM64RNDR(instruction Instr) (arm64RawRNDR, bool, error) {
	op := arm64ControlOp(instruction)
	if op == OpWORD {
		if instruction.Op == OpWORD && len(instruction.Args) == 1 && instruction.Args[0].Kind == OpImm &&
			instruction.Args[0].ImmRaw == "" && !instruction.Args[0].ImmIsFloat {
			form, matched := decodeARM64RawRNDR(uint32(instruction.Args[0].Imm))
			return form, matched, nil
		}
		return arm64RawRNDR{}, false, nil
	}
	if op != "MRS" && op != "MSR" && op != "MOVD" {
		return arm64RawRNDR{}, false, nil
	}
	matched := false
	for _, operand := range instruction.Args {
		if operand.Kind == OpIdent {
			switch strings.ToUpper(operand.Ident) {
			case "RNDR", "RNDRRS", "S3_3_C2_C4_0", "S3_3_C2_C4_1":
				matched = true
			}
		}
	}
	if !matched {
		return arm64RawRNDR{}, false, nil
	}
	invalid := func() (arm64RawRNDR, bool, error) {
		return arm64RawRNDR{}, true, fmt.Errorf("arm64 RNG requires MRS/MOVD RNDR/RNDRRS,GP/ZR without suffix: %q", instruction.Raw)
	}
	if instruction.Op != op || op == "MSR" || len(instruction.Args) != 2 {
		return invalid()
	}
	system, destination := instruction.Args[0], instruction.Args[1]
	if system.Kind != OpIdent || (system.Ident != "RNDR" && system.Ident != "RNDRRS") ||
		destination.Kind != OpReg || !isARM64GeneralOrZeroReg(destination.Reg) {
		return invalid()
	}
	register := 31
	if destination.Reg != ZR {
		var valid bool
		register, valid = arm64StackIndex(destination.Reg)
		if !valid || register < 0 || register > 30 {
			return invalid()
		}
	}
	return arm64RawRNDR{reseed: system.Ident == "RNDRRS", reg: register}, true, nil
}

func validateARM64RNDRTarget(file *File, options Options) error {
	if file == nil || file.Arch != ArchARM64 {
		return nil
	}
	needsNative := false
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			_, matched, err := parseARM64RNDR(instruction)
			if err != nil {
				return err
			}
			needsNative = needsNative || matched
		}
	}
	if needsNative && (!arm64ScalarConversionNativeTarget(options.TargetTriple) || options.Goarch != "" && options.Goarch != "arm64") {
		return fmt.Errorf("%w: ARM64 RNG requires an explicit native little-endian AArch64 target", ErrProbeNeedsContext)
	}
	return nil
}
