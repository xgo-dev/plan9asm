package plan9asm

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"sort"
)

func arm64ByteCarrierSyntax(file *ast.File) (string, error) {
	if file == nil || file.Name == nil {
		return "", arm64ByteCarrierContext("incomplete Go syntax")
	}
	var output bytes.Buffer
	err := ast.Fprint(&output, nil, file, func(name string, value reflect.Value) bool {
		// Source positions and parser object cycles are not semantics. Retain
		// all declarations, bodies, comments, directives and identifier text.
		return value.Type() != reflect.TypeOf(token.Pos(0)) && name != "Obj" && name != "Scope" && name != "Unresolved"
	})
	return output.String(), err
}

func arm64ByteCarrierGoView(source *GoARM64ByteCarrierSource, pkg GoPackage) ([]string, error) {
	if pkg.Types == nil || pkg.Path != source.request.PackagePath || pkg.Types.Path() != pkg.Path ||
		pkg.Types.Name() != source.guard.selection.Name || len(pkg.Syntax) != len(source.guard.selection.GoFiles) ||
		len(pkg.Imports) != 0 || len(pkg.Types.Imports()) != 0 || pkg.SourceSelection != nil ||
		len(pkg.Types.Scope().Names()) != len(source.report.Declarations) {
		return nil, arm64ByteCarrierContext("complete typed Go owner/source inventory differs")
	}
	var expected, actual []string
	for _, name := range source.guard.selection.GoFiles {
		parsed, err := parser.ParseFile(token.NewFileSet(), name, source.report.Sources[name], parser.ParseComments)
		if err != nil {
			return nil, arm64ByteCarrierContext("original Go syntax changed: %v", err)
		}
		text, err := arm64ByteCarrierSyntax(parsed)
		if err != nil {
			return nil, err
		}
		expected = append(expected, text)
	}
	for _, file := range pkg.Syntax {
		text, err := arm64ByteCarrierSyntax(file)
		if err != nil {
			return nil, err
		}
		actual = append(actual, text)
	}
	sort.Strings(expected)
	sort.Strings(actual)
	if !reflect.DeepEqual(expected, actual) {
		return nil, arm64ByteCarrierContext("whole original Go syntax differs from the consumer package")
	}
	for _, name := range pkg.Types.Scope().Names() {
		function, valid := pkg.Types.Scope().Lookup(name).(*types.Func)
		if !valid || function.Pkg() != pkg.Types || function.Parent() != pkg.Types.Scope() ||
			types.TypeString(function.Type(), nil) != source.report.Declarations[name] {
			return nil, arm64ByteCarrierContext("whole original Go declaration semantics differ")
		}
	}
	return actual, nil
}

func arm64ByteCarrierGoResult(source *GoARM64ByteCarrierSource, result *GoModuleTranslation) error {
	if result == nil || result.Module.IsNil() || len(result.Functions) != len(source.file.Funcs) ||
		len(result.Signatures) != len(source.declarations) {
		return arm64ByteCarrierContext("complete Go/LLVM function metadata is missing")
	}
	for ordinal, original := range source.file.Funcs {
		name := source.request.PackagePath + "." + original.Sym[len("·"):]
		function := result.Functions[ordinal]
		actual, present := result.Signatures[name]
		expected := source.declarations[original.Sym[len("·"):]]
		if function.TextSymbol != original.Sym || function.ResolvedSymbol != name || result.Module.NamedFunction(name).IsNil() ||
			!present || !bytes.Equal(arm64ScratchPublicSignature(actual), arm64ScratchPublicSignature(expected)) {
			return arm64ByteCarrierContext("Go metadata/LLVM name/signature does not match the frozen actual entry")
		}
	}
	return nil
}

func finishARM64ByteCarrierGoSource(source *GoARM64ByteCarrierSource, pkg GoPackage, prior []string, result *GoModuleTranslation) error {
	current, err := arm64ByteCarrierGoView(source, pkg)
	if err == nil && !reflect.DeepEqual(prior, current) {
		err = arm64ByteCarrierContext("Go package changed during binding/lowering callbacks")
	}
	if result != nil {
		err = errors.Join(err, arm64ByteCarrierGoResult(source, result))
	}
	return errors.Join(err, source.Verify(source.lease))
}
