package plan9asm

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"strconv"
)

// These complete function shapes describe the registered Go loader/linker rule,
// not a literal's address. Whole original source bytes are separately retained.
const goDataSymalignRule = `package ld
func symalign(ldr *loader.Loader, s loader.Sym) int32 {
 min := int32(thearch.Minalign)
 align := ldr.SymAlign(s)
 if align >= min { return align } else if align != 0 { return min }
 align = int32(thearch.Maxalign)
 ssz := ldr.SymSize(s)
 for int64(align) > ssz && align > min { align >>= 1 }
 ldr.SetSymAlign(s, align)
 return align
}`

const goLoaderSymalignRule = `package loader
func (l *Loader) SymAlign(i Sym) int32 {
 if int(i) >= len(l.align) { return 0 }
 abits := l.align[i]
 if abits == 0 { return 0 }
 return int32(1 << (abits - 1))
}`

const goLiteralDefaultPIERule = `package platform
func DefaultPIE(goos, goarch string, isRace bool) bool {
 switch goos {
 case "android", "ios": return true
 case "windows": if isRace { return false }; return true
 case "darwin": return true
 }
 return false
}`

func verifyGoLiteralDefaultPIE(data []byte) error {
	actual, err := goAlignmentFunctionShape(data, "DefaultPIE")
	expected, expectedErr := goAlignmentFunctionShape([]byte(goLiteralDefaultPIERule), "DefaultPIE")
	if err != nil || expectedErr != nil || !bytes.Equal(actual, expected) {
		return sdkASMDataContext("unregistered complete actual Go default PIE profile")
	}
	return nil
}

func goAlignmentFunctionShape(data []byte, name string) ([]byte, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "original.go", data, 0)
	if err != nil {
		return nil, err
	}
	var result []byte
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != name {
			continue
		}
		if result != nil {
			return nil, sdkASMDataContext("duplicate original linker alignment function")
		}
		var output bytes.Buffer
		// Ignore physical blank/comment line positions, but compare the whole
		// declaration, receiver, expressions and control flow without cropping.
		if err := format.Node(&output, token.NewFileSet(), function); err != nil {
			return nil, err
		}
		result = output.Bytes()
	}
	if result == nil {
		return nil, sdkASMDataContext("missing original linker alignment function")
	}
	return result, nil
}

func verifyGoAssemblyDataAlignmentRule(data, loader, limits, arch []byte) error {
	for _, row := range []struct {
		actual         []byte
		expected, name string
	}{
		{data, goDataSymalignRule, "symalign"}, {loader, goLoaderSymalignRule, "SymAlign"},
	} {
		actual, err := goAlignmentFunctionShape(row.actual, row.name)
		expected, expectedErr := goAlignmentFunctionShape([]byte(row.expected), row.name)
		if err != nil || expectedErr != nil || !bytes.Equal(actual, expected) {
			return sdkASMDataContext("unregistered complete original linker/loader alignment rule: %s", row.name)
		}
	}
	fset := token.NewFileSet()
	constantsFile, err := parser.ParseFile(fset, "l.go", limits, 0)
	if err != nil {
		return err
	}
	constants := map[string]int{}
	ast.Inspect(constantsFile, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
			return true
		}
		literal, ok := value.Values[0].(*ast.BasicLit)
		if ok && literal.Kind == token.INT {
			constants[value.Names[0].Name], _ = strconv.Atoi(literal.Value)
		}
		return true
	})
	archFile, err := parser.ParseFile(fset, "obj.go", arch, 0)
	if err != nil {
		return err
	}
	values := map[string]int{}
	valid := true
	ast.Inspect(archFile, func(node ast.Node) bool {
		field, ok := node.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := field.Key.(*ast.Ident)
		if !ok || key.Name != "Maxalign" && key.Name != "Minalign" {
			return true
		}
		if _, duplicate := values[key.Name]; duplicate {
			valid = false
		}
		value, ok := field.Value.(*ast.Ident)
		if !ok {
			valid = false
			return true
		}
		values[key.Name] = constants[value.Name]
		return true
	})
	if !valid || len(values) != 2 || values["Maxalign"] != 32 || values["Minalign"] != 1 {
		return sdkASMDataContext("unregistered actual x86 linker minimum/maximum alignment")
	}
	return nil
}
