package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/types"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

func x86SDKNeedsDirectTailDeclarations(file *plan9asm.File) bool {
	if file != nil && file.Arch == plan9asm.ArchAMD64 {
		for _, fn := range file.Funcs {
			for _, ins := range fn.Instrs {
				if ins.Op == plan9asm.OpJMP && len(ins.Args) == 1 && strings.Contains(ins.Args[0].Sym, "<>") {
					return true // Cost query only; the inventory and graph still validate every use.
				}
			}
		}
	}
	return false
}

// The authenticated SDK route starts from actual declarations, not fabricated
// FP words for private graph nodes. This is only an inventory: the existing
// live source binder and complete direct-tail graph still own admission.
func x86SDKDirectTailDeclarationInventory(pkg plan9asm.GoPackage, file *plan9asm.File, options plan9asm.Options) (map[string]plan9asm.FuncSig, map[string]int64, bool, error) {
	if !x86SDKNeedsDirectTailDeclarations(file) {
		return nil, nil, false, nil
	}
	if pkg.Types == nil || pkg.Types.Path() != pkg.Path || options.ResolveSym == nil ||
		options.Goarch != "386" && options.Goarch != "amd64" {
		return nil, nil, true, fmt.Errorf("%w: SDK tail inventory lacks its actual typed package/resolver/mode", plan9asm.ErrProbeNeedsContext)
	}
	requests, err := assemblySignatureRequests(pkg.Path, file, options.ResolveSym)
	if err != nil {
		return nil, nil, true, err
	}
	signatures, sizes := make(map[string]plan9asm.FuncSig), make(map[string]int64)
	for symbol, request := range requests {
		if strings.Contains(request.original, "<>") {
			continue // A private graph node has no independent callable ABI.
		}
		actual, size, found, err := tryDeclSig(pkg.Types.Scope(), stripABISuffix(request.original), symbol,
			linknameRemoteToLocal(pkg.Syntax), options.Goarch, types.SizesFor("gc", options.Goarch),
			strings.HasSuffix(request.original, "<ABIInternal>"))
		if err != nil || !found {
			return nil, nil, true, fmt.Errorf("%w: SDK tail inventory lacks actual declaration %s: %v", plan9asm.ErrProbeNeedsContext, symbol, err)
		}
		signatures[symbol], sizes[symbol] = actual, size
	}
	options.Sigs = signatures
	bound, err := x86SDKDirectTailDeclarationOptions(pkg, file, options)
	if err != nil {
		return nil, nil, true, err
	}
	return bound.Sigs, sizes, true, nil
}

// This is an inventory adapter, not a source or entry producer. The live SDK
// binder subsequently authenticates every original declaration/node and the
// direct-tail graph proves each root's state and terminal compatibility. Generic
// CLI fallback signatures remain unchanged outside this complete-source route.
func x86SDKDirectTailDeclarationOptions(pkg plan9asm.GoPackage, file *plan9asm.File, options plan9asm.Options) (plan9asm.Options, error) {
	if !x86SDKNeedsDirectTailDeclarations(file) {
		return options, nil
	}
	contextError := func(reason string) error {
		return fmt.Errorf("%w: SDK numerical tail declarations: %s", plan9asm.ErrProbeNeedsContext, reason)
	}
	if pkg.Types == nil || pkg.Types.Path() != pkg.Path || options.ResolveSym == nil ||
		(options.Goarch != "386" && options.Goarch != "amd64") {
		return plan9asm.Options{}, contextError("missing actual typed package/resolver/mode")
	}
	sizes := types.SizesFor("gc", options.Goarch)
	linknames := linknameRemoteToLocal(pkg.Syntax)
	declared := make(map[string]plan9asm.FuncSig)
	helpers := make(map[string]bool)
	texts := make(map[string]bool)
	add := func(symbol string) error {
		logical := stripABISuffix(symbol)
		name := options.ResolveSym(logical)
		if name == "" {
			return contextError("empty original declaration identity")
		}
		actual, _, present, err := tryDeclSig(pkg.Types.Scope(), logical, name, linknames, options.Goarch, sizes, false)
		if err != nil || !present {
			return contextError("root/ordinary terminal lacks its actual Go declaration: " + logical)
		}
		provided, present := options.Sigs[name]
		// JSON is solely an equality projection. Keep the original value, including
		// its private caller/local capabilities; never reconstruct one from bytes.
		before, actualErr := json.Marshal(actual)
		after, providedErr := json.Marshal(provided)
		if !present || actualErr != nil || providedErr != nil || !bytes.Equal(before, after) {
			return contextError("supplied root/terminal transport differs from its actual declaration: " + name)
		}
		declared[name] = provided
		return nil
	}
	for _, fn := range file.Funcs {
		if texts[fn.Sym] {
			return plan9asm.Options{}, contextError("duplicate original TEXT")
		}
		texts[fn.Sym] = true
		if strings.HasSuffix(fn.Sym, "<>") {
			helpers[options.ResolveSym(fn.Sym)] = true
			continue
		}
		if err := add(fn.Sym); err != nil {
			return plan9asm.Options{}, err
		}
	}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op != plan9asm.OpJMP || len(ins.Args) != 1 || ins.Args[0].Kind != plan9asm.OpSym {
				continue
			}
			operand := strings.TrimSpace(ins.Args[0].Sym)
			if !strings.HasSuffix(operand, "(SB)") {
				continue // Local source labels retain the graph's separate CFG audit.
			}
			symbol, offset := splitSymPlusOff(strings.TrimSuffix(operand, "(SB)"))
			if symbol == "" || offset != 0 {
				return plan9asm.Options{}, contextError("offset/unknown ordinary terminal")
			}
			if strings.HasSuffix(symbol, "<>") {
				if !texts[symbol] {
					return plan9asm.Options{}, contextError("private terminal lacks its complete original TEXT")
				}
				continue
			}
			if err := add(symbol); err != nil {
				return plan9asm.Options{}, err
			}
		}
	}
	for name := range options.Sigs {
		if _, present := declared[name]; !present && !helpers[name] {
			return plan9asm.Options{}, contextError("unassociated callable signature: " + name)
		}
	}
	options.Sigs = declared
	return options, nil
}
