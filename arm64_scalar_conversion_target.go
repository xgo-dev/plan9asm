package plan9asm

import (
	"fmt"
	"strings"
)

func arm64ScalarConversionNativeTarget(triple string) bool {
	parts := strings.Split(triple, "-")
	return len(parts) >= 3 && (parts[0] == "aarch64" || parts[0] == "arm64")
}

func arm64RawScalarConversion(word uint32) bool {
	if _, ok := decodeARM64RawScalarFCVTToInt(word); ok {
		return true
	}
	if _, ok := decodeARM64RawScalarIntToFloat(word); ok {
		return true
	}
	if _, ok := decodeARM64RawScalarVectorFCVTZ(word); ok {
		return true
	}
	return false
}

func validateARM64ScalarConversionNativeTarget(file *File, options Options) error {
	if file == nil || file.Arch != ArchARM64 {
		return nil
	}
	needsNative := false
	var rawError error
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			if instruction.Op == OpWORD {
				if err := arm64RawWordPreflightError(instruction); err != nil && rawError == nil {
					rawError = err
				}
				if len(instruction.Args) != 1 || instruction.Args[0].Kind != OpImm ||
					instruction.Args[0].ImmRaw != "" || instruction.Args[0].ImmIsFloat {
					continue
				}
				word := uint32(instruction.Args[0].Imm)
				if arm64RawScalarConversion(word) {
					needsNative = true
				}
				continue
			}
			_, matched, err := parseARM64ScalarConversion(arm64ControlOp(instruction), instruction)
			if err != nil {
				return err
			}
			needsNative = needsNative || matched
		}
	}
	if !needsNative {
		return nil
	}
	if rawError != nil {
		return rawError // Illegal/dead WORDs are not target-context successes.
	}
	if !arm64ScalarConversionNativeTarget(options.TargetTriple) || options.Goarch != "" && options.Goarch != "arm64" {
		return fmt.Errorf("%w: ARM64 scalar conversion requires an explicit native little-endian AArch64 FPCR/FPSR target, got %q/%q",
			ErrProbeNeedsContext, options.Goarch, options.TargetTriple)
	}
	return nil
}
