// Package opcodeinventory reads declared opcode names from lowering source.
package opcodeinventory

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/arm64atomic"
	"github.com/xgo-dev/plan9asm/internal/wasmsimd"
	"github.com/xgo-dev/plan9asm/internal/x86cmov"
	"github.com/xgo-dev/plan9asm/internal/x86x87"
)

// CollectGenerated reads names from the compiled grammar when the inspected
// lowering source uses that grammar.
func CollectGenerated(supported map[string]struct{}, file *ast.File, goarch string) {
	for _, imported := range file.Imports {
		path := stringLiteral(imported.Path)
		switch {
		case goarch == "arm64" && path == "github.com/xgo-dev/plan9asm/internal/arm64atomic":
			arm64atomic.AddNamed(supported)
			return
		case goarch == "wasm" && path == "github.com/xgo-dev/plan9asm/internal/wasmsimd":
			wasmsimd.AddNamed(supported)
			return
		case (goarch == "386" || goarch == "amd64") && path == "github.com/xgo-dev/plan9asm/internal/x86cmov":
			x86cmov.Visit(func(name string, _ int, _ string) {
				supported[name] = struct{}{}
			})
			return
		case (goarch == "386" || goarch == "amd64") && path == "github.com/xgo-dev/plan9asm/internal/x86x87":
			x86x87.VisitArithmetic(func(stem, suffix string) {
				supported[stem+suffix] = struct{}{}
			})
			return
		}
	}
}

// CollectMap adds names declared by an opcode map or typed family table.
// Name claims remain separate from the caller's operand and execution probes.
func CollectMap(supported map[string]struct{}, literal *ast.CompositeLit, goarch string, normalize func(string) string) {
	add := func(candidate string) {
		if opcode := normalize(candidate); opcode != "" {
			supported[opcode] = struct{}{}
		}
	}
	if goarch == "arm64" {
		collectARM64NamedRows(literal, add)
	}
	name, named := literal.Type.(*ast.Ident)
	widthFamily := named && name.Name == "x86OpcodeWidths" && (goarch == "386" || goarch == "amd64")
	mapType, _ := literal.Type.(*ast.MapType)
	keyType, _ := MapKeyIdent(mapType)
	if !widthFamily && keyType != "string" && keyType != "Op" {
		return
	}
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key := stringLiteral(pair.Key)
		if !widthFamily {
			add(key)
			continue
		}
		if key == "" {
			continue
		}
		for _, width := range stringLiteral(pair.Value) {
			if strings.ContainsRune("BWLQ", width) && (width != 'Q' || goarch == "amd64") {
				add(key + string(width))
			}
		}
	}
}

func collectARM64NamedRows(literal *ast.CompositeLit, add func(string)) {
	array, ok := literal.Type.(*ast.ArrayType)
	if !ok {
		return
	}
	element, ok := array.Elt.(*ast.Ident)
	if !ok {
		return
	}
	var highHalf bool
	switch element.Name {
	case "arm64IntegerNarrowOp":
		highHalf = true
	case "arm64SaturatingArithmeticOp":
	default:
		return
	}
	for _, row := range literal.Elts {
		spec, ok := row.(*ast.CompositeLit)
		if !ok {
			continue
		}
		for _, field := range spec.Elts {
			pair, ok := field.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := pair.Key.(*ast.Ident)
			if !ok || key.Name != "name" {
				continue
			}
			name := stringLiteral(pair.Value)
			if name != "" {
				add(name)
				if highHalf {
					add(name + "2")
				}
			}
			break
		}
	}
}

func stringLiteral(expr ast.Expr) string {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return ""
	}
	value, _ := strconv.Unquote(literal.Value)
	return value
}

func MapKeyIdent(mapType *ast.MapType) (string, bool) {
	if mapType == nil {
		return "", false
	}
	ident, ok := mapType.Key.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}
