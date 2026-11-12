package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
)

var nativeCodeObjectName = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9.]*$`)

// A bound bare TEXT is an address-only native entry, never an
// inferred Go declaration or C prototype. The physical backend validates
// its complete body and assembler-managed frame independently.
func validateNativeCodeEntry(fn Func, opts NativeOptions) error {
	if !nativeName.MatchString(fn.Sym) || len(fn.Instrs) < 2 {
		return fmt.Errorf("native code entry requires complete bare TEXT: %s", fn.Sym)
	}
	_, err := nativeTextFrame(fn, opts)
	return err
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
