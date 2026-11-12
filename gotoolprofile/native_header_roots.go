package gotoolprofile

import (
	"fmt"
	"go/ast"
	"strconv"
)

// Native header queries and same-mode declaration queries share the original
// AST closure machinery, not their consumer capabilities. Every constant and
// nongeneric type root is retained. An uninstantiated generic declaration has
// no native header definitions, just like variable initializers and function
// bodies. Actual compiler acceptance remains independently required.
func requireNativeHeaderRoots(root *instrumentationDeclarationReplay) error {
	for name := range root.constants {
		if err := root.requireName(name); err != nil {
			return err
		}
	}
	for name, declaration := range root.types {
		if declaration.TypeParams != nil && len(declaration.TypeParams.List) != 0 {
			// Go omits these from AsmHdrDecls. This only removes a top-level
			// property root: a concrete alias, field or constant referring to
			// the declaration must still close through requireName/requireType.
			// Do not broaden the shared instrumentation type/ABI contract.
			continue
		}
		if err := root.requireName(name); err != nil {
			return err
		}
	}
	return nil
}

// This adapter only closes properties independent of foreign declarations.
// Imported constants/types still need a separately authenticated source graph;
// an actual export digest alone cannot supply their independent property replay.
func nativeHeaderIndependentFiles(files []*ast.File) ([]*ast.File, error) {
	foreign := false
	for _, file := range files {
		for _, spec := range file.Imports {
			spelling, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, fmt.Errorf("native header original import path is invalid: %w", err)
			}
			foreign = foreign || spelling != "unsafe"
		}
	}
	if !foreign {
		return files, nil
	}

	root := &instrumentationDeclarationReplay{
		files: files, functions: make(map[string]*ast.FuncDecl),
		types: make(map[string]*ast.TypeSpec), constants: make(map[string]*ast.GenDecl),
		other: make(map[string]bool), needed: make(map[ast.Node]bool),
	}
	for _, file := range files {
		if err := root.index(file); err != nil {
			return nil, err
		}
	}
	root.selector = func(expression *ast.SelectorExpr) error {
		qualifier, ok := expression.X.(*ast.Ident)
		if !ok {
			return fmt.Errorf("native property selector is not a direct original import")
		}
		for _, file := range files {
			if expression.Pos() < file.Pos() || expression.End() > file.End() {
				continue
			}
			for _, spec := range file.Imports {
				spelling, _ := strconv.Unquote(spec.Path.Value) // Checked above.
				name := spelling
				if spec.Name != nil {
					name = spec.Name.Name
				}
				if spelling == "unsafe" && name == qualifier.Name {
					root.needed[spec] = true
					return nil
				}
			}
		}
		return fmt.Errorf("native header property needs an authenticated imported declaration")
	}
	if err := requireNativeHeaderRoots(root); err != nil {
		return nil, &nativeHeaderUnsupportedDomain{err.Error()}
	}
	return root.selectedFiles(), nil
}
