package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gosym"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func (source *GoARM64ScratchSource) captureObjectSourceMetadata(root string) error {
	filename := filepath.Join(root, "src", "cmd", "internal", "src", "pos.go")
	data, err := source.read(filename)
	if err != nil {
		return err
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), filename, data, 0)
	if err != nil {
		return err
	}
	count := 0
	for _, declaration := range syntax.Decls {
		group, valid := declaration.(*ast.GenDecl)
		if !valid || group.Tok != token.CONST {
			continue
		}
		for _, specification := range group.Specs {
			value, valid := specification.(*ast.ValueSpec)
			if !valid || len(value.Names) != 1 || value.Names[0].Name != "FileSymPrefix" {
				continue
			}
			if len(value.Values) != 1 {
				return arm64ScratchContext("unknown actual object source-symbol metadata")
			}
			literal, valid := value.Values[0].(*ast.BasicLit)
			if !valid || literal.Kind != token.STRING {
				return arm64ScratchContext("unknown actual object source-symbol prefix")
			}
			prefix, err := strconv.Unquote(literal.Value)
			if err != nil || prefix != "gofile.." {
				return arm64ScratchContext("unregistered actual object source-symbol prefix")
			}
			source.filePrefix = prefix
			count++
		}
	}
	if count != 1 {
		return arm64ScratchContext("missing or ambiguous actual object source-symbol metadata")
	}
	flags, err := source.read(filepath.Join(root, "src", "cmd", "asm", "internal", "flags", "flags.go"))
	if err != nil {
		return err
	}
	// This actual registered old-assembler role is only passed for a selected
	// SDK package. Stock export/archive equality still proves the original
	// body's real producer role; neither this flag nor a prefix grants one.
	source.compilingRuntime = bytes.Contains(flags, []byte(`flag.Bool("compiling-runtime"`))
	return source.captureBuiltinObjectVersions(root)
}

// objfile's builtin relocation printer passes the builtin ABI value to
// goobjName. Old SDK observations can therefore contain name<1>, unlike an
// ordinary indexed symbol. Bind that metadata only to this actual SDK's
// complete generated builtin table. This is not an ABI or callee admission.
func (source *GoARM64ScratchSource) captureBuiltinObjectVersions(root string) error {
	filename := filepath.Join(root, "src", "cmd", "internal", "goobj", "builtinlist.go")
	data, err := source.read(filename)
	if err != nil {
		return err
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), filename, data, 0)
	if err != nil {
		return err
	}
	versions := make(map[string]string)
	count := 0
	for _, declaration := range syntax.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.VAR {
			continue
		}
		for _, specification := range group.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "builtins" || len(value.Values) != 1 {
				continue
			}
			list, ok := value.Values[0].(*ast.CompositeLit)
			if !ok || len(list.Elts) == 0 || len(list.Elts) > 1024 {
				return arm64ScratchContext("unknown actual object builtin metadata")
			}
			count++
			for _, element := range list.Elts {
				row, ok := element.(*ast.CompositeLit)
				if !ok || len(row.Elts) != 2 {
					return arm64ScratchContext("unknown actual object builtin row")
				}
				name, nameOK := row.Elts[0].(*ast.BasicLit)
				abi, abiOK := row.Elts[1].(*ast.BasicLit)
				if !nameOK || !abiOK || name.Kind != token.STRING || abi.Kind != token.INT || abi.Value != "0" && abi.Value != "1" {
					return arm64ScratchContext("unknown actual object builtin ABI metadata")
				}
				symbol, err := strconv.Unquote(name.Value)
				if err != nil || symbol == "" || strings.ContainsAny(symbol, "<>\r\n") {
					return arm64ScratchContext("unknown actual object builtin name")
				}
				if abi.Value == "1" {
					key := symbol + "<1>"
					if _, duplicate := versions[key]; duplicate {
						return arm64ScratchContext("ambiguous actual object builtin metadata")
					}
					versions[key] = symbol
				}
			}
		}
	}
	if count != 1 || len(versions) == 0 {
		return arm64ScratchContext("missing actual object builtin metadata")
	}
	source.builtinVersions = versions
	return nil
}

func (source *GoARM64ScratchSource) originalObjectCallTarget(symbol string) string {
	if canonical, captured := source.builtinVersions[symbol]; captured {
		return canonical
	}
	for packagePath := range source.packages {
		logical := arm64ScratchLogicalNativeSymbol(packagePath, symbol)
		if logical != symbol {
			return logical
		}
	}
	return symbol
}

// Translate only the exact native prefix of an actually selected package.
// Never percent-decode arbitrary function names, unknown packages or metadata.
// Original source, ABI roles and complete native bodies are still independent.
func arm64ScratchLogicalNativeSymbol(packagePath, symbol string) string {
	prefix := gosym.PackagePrefix(packagePath) + "."
	if strings.HasPrefix(symbol, prefix) {
		return packagePath + "." + strings.TrimPrefix(symbol, prefix)
	}
	return symbol
}

// Normalize only the actual SDK's source metadata spelling. The result must
// already be a captured canonical regular file with identical current bytes.
// A relative spelling, logical/symlink alias or unrelated equal-byte file
// cannot turn an object location into source authority.
func (source *GoARM64ScratchSource) originalObjectSource(name string) (string, bool) {
	if source.filePrefix != "" && strings.HasPrefix(name, source.filePrefix) {
		name = strings.TrimPrefix(name, source.filePrefix)
	}
	name, valid := originalGoObjectSourcePath(name, source.settings["GOROOT"])
	if !valid {
		return "", false
	}
	physical, err := sourcepath.Resolve(name)
	if err != nil || physical != name {
		return "", false
	}
	digest, captured := source.inputs[name]
	if !captured {
		return "", false
	}
	data, err := goAMD64FrameRead(name)
	return name, err == nil && sha256.Sum256(data) == digest
}

// This spelling is metadata only, never a wrapper/body admission. The actual
// captured SDK prefix may decorate this marker in old object source records;
// the exact bytes, ABI role and wrapper transport are checked independently.
func (source *GoARM64ScratchSource) originalObjectGenerated(name string) bool {
	if source.filePrefix != "" {
		name = strings.TrimPrefix(name, source.filePrefix)
	}
	return name == "<autogenerated>"
}
