package plan9asm

import (
	"errors"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

var sdkLiteralAlignmentRequested = errors.New("typed literal-address masked predicate requests an independent minimum")

// GoX86SDKLiteralAlignmentRequested is a bounded cost query, not a source,
// layout, result or address permission. Only the independent live producer
// and BindNumericalReadsWithLiteralAlignment may authorize a masked predicate.
func GoX86SDKLiteralAlignmentRequested(file *File, options Options) bool {
	if file == nil || file.Arch != ArchAMD64 || options.Goarch != "amd64" && options.Goarch != "386" || len(file.Funcs) > 256 || len(file.Globl) > gostaticstorage.ObjectSymbolInventoryLimit {
		return false
	}
	literals := make(map[string]int64)
	for _, global := range file.Globl {
		readonly, err := globlReadOnly(global.Flags)
		if err == nil && readonly && global.Size > 0 && global.SizeRaw == "" {
			literals[global.Sym] = global.Size
		}
	}
	if len(literals) == 0 {
		return false
	}
	for _, fn := range file.Funcs {
		name := fn.Sym
		if options.ResolveSym != nil {
			name = options.ResolveSym(name)
		}
		sig, found := options.Sigs[name]
		if !found || !x86SDKLiteralBoolPredicateRole(fn, sig, options.Goarch) {
			continue
		}
		// Reuse the complete bounded literal CFG, physical source aliases,
		// origin/escape checks and cycle budget. The query has no fake floor,
		// linked address, minimum certificate or initialized numerical bytes.
		_, err := proveX86SDKLiteralAccessesAtMinimumRequest(fn, sig, options.Goarch, literals, nil, true)
		if errors.Is(err, sdkLiteralAlignmentRequested) {
			return true
		}
	}
	return false
}

func x86SDKLiteralAlignmentRequestStep(ins Instr, state *x86SDKLiteralState, arch string) (bool, error) {
	word := x86ResultPointerWord(arch)
	read := func(operand Operand) (int, x86SDKLiteralValue, bool) {
		root, _, valid := x86ResultGP(operand.Reg, word, arch)
		return root, state.gp[root], operand.Kind == OpReg && valid
	}
	if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known && err == nil && form.spec.stem == "OR" {
		_, first, validSource := read(form.source)
		destination, previous, validDestination := read(form.destination)
		if int64(form.spec.bits/8) != word || !validSource || !validDestination || first.symbol == "" || previous.symbol == "" ||
			first.bad && !first.bitsOnly || previous.bad && !previous.bitsOnly {
			return false, nil
		}
		// This is only may-demand propagation to a later TEST. It does not
		// set hasMinimum/lowMask/lowValue, or emit any instruction fact.
		previous.bad, previous.bitsOnly = true, true
		state.gp[destination], state.compared = previous, false
		return true, nil
	}
	if form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known && err == nil && form.test {
		root, _, valid := x86ResultGP(form.args[1].Reg, int64(form.bits/8), arch)
		value := state.gp[root]
		if valid && form.args[1].Kind == OpReg && form.args[0].Kind == OpImm && value.symbol != "" && (!value.bad || value.bitsOnly) {
			return true, sdkLiteralAlignmentRequested
		}
	}
	return false, nil
}
