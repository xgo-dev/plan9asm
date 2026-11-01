package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
)

var nativeCodeObjectName = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9.]*$`)

// A bound bare TEXT is an address-only native import tail stub, never an
// inferred Go declaration or an inferred C prototype. Its complete source
// establishes that it does not allocate a Go/native frame or touch registers.
func validateNativeCodeEntry(fn Func, opts NativeOptions) error {
	if !nativeName.MatchString(fn.Sym) || len(fn.Instrs) < 2 || len(fn.Instrs) > 3 {
		return fmt.Errorf("native code entry requires a bare import tail stub: %s", fn.Sym)
	}
	parts := strings.Split(fn.Instrs[0].Raw, ",")
	if len(parts) != 3 || (strings.TrimSpace(parts[2]) != "$0" && strings.TrimSpace(parts[2]) != "$0-0") {
		return fmt.Errorf("native code entry requires zero frame and arguments: %s", fn.Sym)
	}
	flags, err := nativeFlags(parts[1], "NOSPLIT", "NOFRAME")
	if err != nil {
		return err
	}
	if !flags["NOSPLIT"] || !flags["NOFRAME"] {
		return fmt.Errorf("native code entry requires NOSPLIT|NOFRAME: %s", fn.Sym)
	}
	tail := fn.Instrs[1]
	if (tail.Op != "JMP" && (opts.GOARCH != "arm64" || tail.Op != "B")) || len(tail.Args) != 1 || tail.Args[0].Kind != OpSym {
		return fmt.Errorf("native code entry requires a direct native import tail: %s", fn.Sym)
	}
	target := strings.TrimSuffix(tail.Args[0].Sym, "(SB)")
	if tail.Args[0].Sym != target+"(SB)" || !nativeName.MatchString(target) || opts.Imports[target] == "" {
		return fmt.Errorf("native code entry has no exact declared native import: %s", fn.Sym)
	}
	if len(fn.Instrs) == 3 && (fn.Instrs[2].Op != "RET" || len(fn.Instrs[2].Args) != 0) {
		return fmt.Errorf("native code entry only permits an unreachable zero-operand RET: %s", fn.Sym)
	}
	return nil
}

func validateNativeCodeBindings(f *File, opts NativeOptions) error {
	seen := make(map[string]bool, len(opts.CodeEntries))
	for source, object := range opts.CodeEntries {
		if !nativeName.MatchString(source) || !nativeCodeObjectName.MatchString(object) || strings.HasPrefix(object, "__plan9_native_") {
			return fmt.Errorf("unsupported native code entry binding %q -> %q", source, object)
		}
		if seen[object] {
			return fmt.Errorf("duplicate native code entry object %q", object)
		}
		seen[object] = true
		if _, imported := opts.Imports[source]; imported {
			return fmt.Errorf("native code entry collides with import identity %q", source)
		}
		for _, alias := range opts.Imports {
			if object == alias {
				return fmt.Errorf("native code entry collides with native import %q", object)
			}
		}
		found := false
		for _, fn := range f.Funcs {
			found = found || fn.Sym == source
		}
		if !found {
			return fmt.Errorf("native code entry has no source TEXT %q", source)
		}
		for _, g := range f.Globl {
			if object == opts.PackagePath+"."+strings.TrimPrefix(g.Sym, "·") {
				return fmt.Errorf("native code entry collides with DATA %q", object)
			}
		}
	}
	return nil
}
