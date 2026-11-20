package plan9asm

import (
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// A typed-source query result, never a terminal-call capability. The actual
// SDK issuer must independently associate the declaration with compiler and
// original assembler objects before retaining any normal-successor role.
type x86GoPanicTerminalDeclaration struct {
	name, nativeName, filename string
	startLine, endLine         int
	panicLine                  int
}

func x86GoPanicTerminalDeclarations(pkg GoPackage) ([]x86GoPanicTerminalDeclaration, error) {
	bodies, err := x86GoSinglePanicBodies(pkg)
	if err != nil {
		return nil, err
	}
	redirectedLocal, redirectedNative := make(map[string]bool), make(map[string]bool)
	// Compiler symbol pragmas belong to the complete file, not fn.Doc.
	// Index them once; unrelated names never lend or remove a callee role.
	for _, file := range pkg.Syntax {
		for _, group := range file.Comments {
			for _, comment := range group.List {
				fields := strings.Fields(comment.Text)
				if len(fields) >= 2 && fields[0] == "//go:linkname" {
					redirectedLocal[fields[1]] = true
					if len(fields) >= 3 {
						redirectedNative[fields[2]] = true
					}
				}
			}
		}
	}
	var declarations []x86GoPanicTerminalDeclaration
	for object, body := range bodies {
		nativeName := gosym.PackagePrefix(pkg.Path) + "." + object.Name()
		if redirectedLocal[object.Name()] || redirectedNative[nativeName] {
			continue
		}
		start := pkg.SourceSelection.Fset.Position(body.Pos())
		end := pkg.SourceSelection.Fset.Position(body.End())
		panic := pkg.SourceSelection.Fset.Position(body.Body.List[0].Pos())
		declarations = append(declarations, x86GoPanicTerminalDeclaration{name: object.Name(), nativeName: nativeName,
			filename: start.Filename, startLine: start.Line, endLine: end.Line, panicLine: panic.Line})
	}
	sort.Slice(declarations, func(i, j int) bool { return declarations[i].name < declarations[j].name })
	return declarations, nil
}
