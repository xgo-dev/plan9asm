package plan9asm

import (
	"fmt"
	"strings"
)

func validateARM64ScalarCompareTarget(file *File, options Options) error {
	if file == nil || file.Arch != ArchARM64 {
		return nil
	}
	needsNative := false
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			op := Op(strings.SplitN(strings.ToUpper(string(instruction.Op)), ".", 2)[0])
			_, matched, err := parseARM64ScalarCompare(op, instruction)
			if err != nil {
				return err
			}
			needsNative = needsNative || matched
			_, matched, err = parseARM64ConditionalCompare(op, instruction)
			if err != nil {
				return err
			}
			needsNative = needsNative || matched
			if instruction.Op != OpWORD {
				continue
			}
			if len(instruction.Args) != 1 || instruction.Args[0].Kind != OpImm ||
				instruction.Args[0].ImmRaw != "" || instruction.Args[0].ImmIsFloat {
				// Only decoded members belong to this family's target check.
				// Symbolic constants and unrelated malformed WORD operands keep
				// their existing resolution and generic-validation ownership.
				continue
			}
			word := uint32(instruction.Args[0].Imm)
			if word&0xff200c00 == 0x1e200400 {
				if _, valid := decodeARM64RawConditionalCompare(word); !valid {
					return fmt.Errorf("unsupported ARM64 conditional compare WORD encoding %#08x: %q", word, instruction.Raw)
				}
				needsNative = true
				continue
			}
			if word&0xff20fc00 != 0x1e202000 {
				continue
			}
			// Complete architectural scalar-compare class, including reserved
			// ftype/opc fields. Do not turn malformed raw source into Context.
			if _, valid := decodeARM64RawScalarFloatCompare(word); !valid {
				return fmt.Errorf("unsupported ARM64 scalar compare WORD encoding %#08x: %q", word, instruction.Raw)
			}
			needsNative = true
		}
	}
	if !needsNative {
		return nil
	}
	return requireARM64ScalarCompareTarget(options.Goarch, options.TargetTriple)
}

func requireARM64ScalarCompareTarget(goarch, target string) error {
	arch := strings.SplitN(target, "-", 2)[0]
	if (arch != "aarch64" && arch != "arm64") || goarch != "" && goarch != "arm64" {
		return fmt.Errorf("%w: ARM64 scalar compare requires an explicit native little-endian AArch64 FPCR/FPSR target, got %q/%q",
			ErrProbeNeedsContext, goarch, target)
	}
	return nil
}
