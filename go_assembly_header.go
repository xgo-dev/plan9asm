package plan9asm

import (
	"bytes"
	"fmt"
	"go/constant"
	"go/types"
)

// GoAssemblyHeader supplies cmd/compile's go_asm.h definitions from the actual
// selected package declarations and the target's gc layout. As in cmd/compile,
// float/complex constants, non-struct types, blank fields, and uninstantiated
// generic types have no definitions. Concrete generic instances and aliases
// retain their actual layout; a missing package/target/layout is an error.
func GoAssemblyHeader(pkg GoPackage, goarch string) ([]byte, error) {
	if pkg.Types == nil || pkg.Types.Scope() == nil {
		return nil, fmt.Errorf("generated go_asm.h requires actual package types")
	}
	sizes := types.SizesFor("gc", goarch)
	if sizes == nil {
		return nil, fmt.Errorf("generated go_asm.h: unknown gc target layout %q", goarch)
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "// generated from selected Go declarations for %s\n", pkg.Types.Path())
	for _, name := range pkg.Types.Scope().Names() {
		if name == "_" {
			continue
		}
		switch obj := pkg.Types.Scope().Lookup(name).(type) {
		case *types.Const:
			if obj.Val() == nil || obj.Val().Kind() == constant.Unknown {
				return nil, fmt.Errorf("generated go_asm.h: unknown constant %s", name)
			}
			if obj.Val().Kind() == constant.Float || obj.Val().Kind() == constant.Complex {
				continue
			}
			fmt.Fprintf(&out, "#define const_%s %s\n", name, obj.Val().ExactString())
		case *types.TypeName:
			st, ok := obj.Type().Underlying().(*types.Struct)
			if !ok || goTypeHasUnboundTypeParams(obj.Type()) {
				continue
			}
			size := sizes.Sizeof(obj.Type())
			if size < 0 {
				return nil, fmt.Errorf("generated go_asm.h: unbound size of %s", name)
			}
			fmt.Fprintf(&out, "#define %s__size %d\n", name, size)
			fields := make([]*types.Var, st.NumFields())
			for i := range fields {
				fields[i] = st.Field(i)
			}
			for i, offset := range sizes.Offsetsof(fields) {
				field := fields[i]
				if field.Name() == "_" {
					continue
				}
				if offset < 0 {
					return nil, fmt.Errorf("generated go_asm.h: unbound offset of %s.%s", name, field.Name())
				}
				fmt.Fprintf(&out, "#define %s_%s %d\n", name, field.Name(), offset)
			}
		}
	}
	return out.Bytes(), nil
}
