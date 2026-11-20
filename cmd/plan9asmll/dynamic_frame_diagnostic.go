package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

func unboundCallerFrameEntry(fn plan9asm.Func, resolve func(string) string,
	sigs map[string]plan9asm.FuncSig, declaredSizes map[string]int64,
) (string, bool) {
	name := resolve(stripABISuffix(fn.Sym))
	sig, known := sigs[name]
	size, declared := declaredSizes[name]
	if !known || !declared || size != 0 || hasExplicitTextArgSize(fn) ||
		len(sig.Args) != 0 || sig.Ret != plan9asm.Void ||
		len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 0 {
		return "", false
	}
	for _, ins := range fn.Instrs {
		for _, operand := range ins.Args {
			if operand.Kind == plan9asm.OpFP || operand.Kind == plan9asm.OpFPAddr {
				return name, true
			}
		}
	}
	return "", false
}

// Source shape only selects a diagnostic probe. Only the complete translator's
// actual dynamic-entry failure may precede ordinary frame-owner capture. A
// successful probe, another failure, or an unrelated symbol grants nothing.
func rejectUnboundCallerFrame(file *plan9asm.File, options plan9asm.Options, declaredSizes map[string]int64) error {
	for _, fn := range file.Funcs {
		if _, candidate := unboundCallerFrameEntry(fn, options.ResolveSym, options.Sigs, declaredSizes); !candidate {
			continue
		}
		// Translate owns and releases its temporary LLVM context and module.
		// Even a successful result is never published or returned to a caller.
		if _, err := plan9asm.Translate(file, options); err != nil {
			original := fmt.Errorf("translate: %w", err)
			if annotated := annotateUnboundCallerFrame(file, options.ResolveSym, options.Sigs, declaredSizes, original); annotated != original {
				return annotated
			}
		}
		break
	}
	return nil
}

// This is a failed-entry diagnostic, not signature inference or an exception.
// An omitted TEXT argument size and a zero-argument source declaration do not
// describe the caller-owned frame addressed by the assembly. Keep the original
// Context error and every ordinary source/translation applicability decision.
func annotateUnboundCallerFrame(file *plan9asm.File, resolve func(string) string,
	sigs map[string]plan9asm.FuncSig, declaredSizes map[string]int64, err error,
) error {
	if file == nil || resolve == nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) ||
		!strings.Contains(err.Error(), "bound typed frame storage") {
		return err
	}
	for _, fn := range file.Funcs {
		name, candidate := unboundCallerFrameEntry(fn, resolve, sigs, declaredSizes)
		if !candidate ||
			!strings.HasPrefix(err.Error(), "translate: "+name+": ") {
			continue
		}
		return fmt.Errorf("%w; actual source: empty Go declaration does not bind a dynamic caller frame; TEXT argument size is unspecified; local stack size, argument-only length and pointer bitmap are not a complete caller-frame contract", err)
	}
	return err
}
