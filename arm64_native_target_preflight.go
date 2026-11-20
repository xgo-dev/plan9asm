package plan9asm

import "errors"

// A native-target requirement is deferred until every registered family's
// source grammar has been checked. Otherwise a valid conversion can hide an
// invalid compare or system-register transfer later in the same source file.
// This changes error precedence only; it never supplies a native target or
// any entry, memory, flag, source-encoder or continuation permission.
func validateARM64NativeTargets(file *File, options Options) error {
	if file == nil || file.Arch != ArchARM64 {
		return nil
	}
	// Check the source class before any native-family matching, dead-code
	// filtering or raw PC/data normalization can consume a truncated word.
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			if instruction.Op == OpWORD {
				if _, err := arm64RawWordValue(instruction); err != nil {
					return err
				}
			}
		}
	}
	file = arm64NativeTargetCodeView(file)
	var targetError error
	for _, validate := range []func(*File, Options) error{
		validateARM64ScalarConversionNativeTarget,
		validateARM64ScalarCompareTarget,
		validateARM64FPControlTarget,
		validateARM64ScalarBinaryTarget,
		validateARM64ScalarMinMaxTarget,
		validateARM64RNDRTarget,
	} {
		if err := validate(file, options); err != nil {
			if !errors.Is(err, ErrProbeNeedsContext) {
				return err
			}
			if targetError == nil {
				targetError = err
			}
		}
	}
	if targetError != nil {
		// Some native families do not themselves claim unrelated WORDs.
		// Their target error still cannot hide a malformed instruction.
		for _, function := range file.Funcs {
			for _, instruction := range function.Instrs {
				if err := arm64RawWordPreflightError(instruction); err != nil && !errors.Is(err, ErrProbeNeedsContext) {
					return err
				}
			}
		}
	}
	return targetError
}

// WORD's source constant class applies to code and data alike, but native
// instruction grammars apply only to code. Reuse the lowerer's bounded raw
// routine/pool proof, without a caller return-clobber permission, to mark
// appended data. Unlike later emission, preflight must not classify a dead
// source WORD as data merely because it follows RET.
//
// This is a private inspection copy, not the source consumed by translation.
// If the proof cannot close, leave the original function intact. Do not
// rewrite any branch or other instruction in this syntax-only view.
func arm64NativeTargetCodeView(file *File) *File {
	view := *file
	view.Funcs = append([]Func(nil), file.Funcs...)
	for index, function := range file.Funcs {
		hasWord := false
		for _, instruction := range function.Instrs {
			if instruction.Op == OpWORD {
				hasWord = true
				break
			}
		}
		if !hasWord {
			continue
		}
		points := make([]arm64RawLayoutPoint, len(function.Instrs))
		knownLabels := make(map[string]bool)
		point := arm64RawLayoutPoint{}
		for at, instruction := range function.Instrs {
			points[at] = point
			if instruction.Op == OpLABEL && len(instruction.Args) == 1 && instruction.Args[0].Kind == OpLabel {
				knownLabels[instruction.Args[0].Sym] = true
			}
			width, known := arm64RawKnownSourceWidth(function, instruction)
			if !known {
				point.segment++
				point.offset = 0
			} else {
				point.offset += width
			}
		}
		data, _, _ := identifyARM64UnlabelledPool(function, points, knownLabels, 0)
		if len(data) == 0 {
			continue
		}
		view.Funcs[index].Instrs = append([]Instr(nil), function.Instrs...)
		for at := range data {
			view.Funcs[index].Instrs[at].Op = arm64RawDataOp
		}
	}
	return &view
}
