package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Inspect the actual LLVM values. LLVM legitimately omits quotes around
// runtime.cmpstring while retaining them around internal/bytealg.Compare.
func amd64ArgumentCompareEntryTypes(module llvm.Module) error {
	for _, row := range []struct {
		name   string
		fields int
	}{
		{"internal/bytealg.Compare", 3},
		{"runtime.cmpstring", 2},
	} {
		function := module.NamedFunction(row.name)
		if function.IsNil() || function.IsDeclaration() || function.BasicBlocksCount() == 0 {
			return fmt.Errorf("missing complete entry definition %s", row.name)
		}
		typ := function.GlobalValueType()
		result := typ.ReturnType()
		if result.TypeKind() != llvm.IntegerTypeKind || result.IntTypeWidth() != 64 ||
			typ.IsFunctionVarArg() || typ.ParamTypesCount() != 2 {
			return fmt.Errorf("entry signature differs for %s", row.name)
		}
		for _, parameter := range typ.ParamTypes() {
			if parameter.TypeKind() != llvm.StructTypeKind || parameter.IsStructPacked() ||
				parameter.IsStructOpaque() || parameter.StructElementTypesCount() != row.fields {
				return fmt.Errorf("argument grouping differs for %s", row.name)
			}
			for index, field := range parameter.StructElementTypes() {
				valid := field.TypeKind() == llvm.PointerTypeKind
				if index != 0 {
					valid = field.TypeKind() == llvm.IntegerTypeKind && field.IntTypeWidth() == 64
				}
				if !valid {
					return fmt.Errorf("argument field %d differs for %s", index, row.name)
				}
			}
		}
	}
	return nil
}

func TestAMD64GoArgumentIRUsesActualEntryIdentityAndTypes(t *testing.T) {
	const source = `define i64 @"internal/bytealg.Compare"({ ptr, i64, i64 } %a, { ptr, i64, i64 } %b) {
  ret i64 0
}
define i64 @runtime.cmpstring({ ptr, i64 } %a, { ptr, i64 } %b) {
  ret i64 0
}
`
	for _, row := range []struct {
		name, ir string
		failure  bool
	}{
		{"canonical-printer", source, false},
		{"quoted-identifier", strings.ReplaceAll(source, "@runtime.cmpstring", "@\"runtime.cmpstring\""), false},
		{"renamed-entry", strings.ReplaceAll(source, "runtime.cmpstring", "runtime.other"), true},
		{"missing-entry", strings.Split(source, "define i64 @runtime")[0], true},
		{"wrong-result", strings.ReplaceAll(source, "i64", "i32"), true},
		{"wrong-length-width", strings.ReplaceAll(source, "ptr, i64", "ptr, i32"), true},
		{"pointer-bits", strings.ReplaceAll(source, "ptr,", "i64,"), true},
		{"collapsed-group", strings.ReplaceAll(source, "{ ptr, i64, i64 }", "{ ptr, i64 }"), true},
		{"packed-group", strings.ReplaceAll(source, "{ ptr, i64 }", "<{ ptr, i64 }>"), true},
	} {
		t.Run(row.name, func(t *testing.T) {
			context := llvm.NewContext()
			defer context.Dispose()
			module, err := parseIRModuleInContext(context, row.ir)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal("signature-only test fixture is not valid LLVM IR", err)
			}
			if err := amd64ArgumentCompareEntryTypes(module); (err != nil) != row.failure {
				t.Fatalf("signature check error=%v; want failure=%t", err, row.failure)
			}
		})
	}
}
