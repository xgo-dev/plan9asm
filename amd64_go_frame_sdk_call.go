package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// The existing selected dependency graph supplies both language declarations
// and actual ABI0 entries. Neither a supplied signature nor an SDK spelling
// creates this role; no pointee extent or noescape property follows from it.
func (source *GoAMD64FrameSource) ordinarySDKCallDeclarations(path string, entries map[string]bool) (map[string]goAMD64FrameDeclaration, error) {
	selected, found := source.imports[path]
	if !found || !selected.Standard || selected.Module != nil || selected.ImportPath != path || selected.Export == "" {
		return nil, goAMD64FrameContext("ordinary foreign CALL lacks its actual selected SDK source: %s", path)
	}
	directory, err := sourcepath.Resolve(selected.Dir)
	if err != nil || directory != filepath.Join(source.env["GOROOT"], "src", filepath.FromSlash(path)) {
		return nil, goAMD64FrameContext("ordinary foreign CALL lacks its physical SDK package: %s: %v", path, err)
	}
	fset := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range selected.GoFiles {
		filename := filepath.Join(directory, name)
		data, err := source.read(filename)
		if err != nil {
			return nil, err
		}
		file, err := parser.ParseFile(fset, filename, data, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		syntax = append(syntax, file)
	}
	actualImporter := importer.ForCompiler(fset, "gc", func(imported string) (io.ReadCloser, error) {
		if target, mapped := selected.ImportMap[imported]; mapped {
			imported = target
		}
		dependency, present := source.imports[imported]
		if !present || dependency.Export == "" {
			return nil, goAMD64FrameContext("SDK CALL declaration lacks its captured compiler import: %s", imported)
		}
		data, err := source.read(dependency.Export)
		return io.NopCloser(bytes.NewReader(data)), err
	})
	sizes := types.SizesFor("gc", "amd64")
	config := &types.Config{Sizes: sizes, Importer: actualImporter, IgnoreFuncBodies: true}
	typed, err := config.Check(path, fset, syntax, nil)
	if err != nil {
		return nil, goAMD64FrameContext("actual selected SDK CALL declarations: %v", err)
	}
	texts, err := source.ordinarySDKCallTexts(selected, entries)
	if err != nil {
		return nil, err
	}
	declarations := make(map[string]goAMD64FrameDeclaration, len(entries))
	for name := range entries {
		fn, valid := typed.Scope().Lookup(name).(*types.Func)
		if !valid {
			return nil, goAMD64FrameContext("SDK CALL has no actual Go function declaration: %s", name)
		}
		sig := fn.Type().(*types.Signature)
		if sig.Recv() != nil || sig.Variadic() || sig.TypeParams().Len() != 0 {
			return nil, goAMD64FrameContext("SDK CALL excludes method, variadic or generic transport")
		}
		var language strings.Builder
		for _, tuple := range []*types.Tuple{sig.Params(), sig.Results()} {
			if tuple.Len() > 4096 {
				return nil, goAMD64FrameContext("SDK CALL declaration tuple bound")
			}
			language.WriteString("[")
			for index := 0; index < tuple.Len(); index++ {
				identity, err := goAMD64FrameLanguageTypeRole(tuple.At(index).Type(), sizes, true)
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(&language, "%q:%s;", tuple.At(index).Name(), identity)
				if language.Len() > 64<<10 {
					return nil, goAMD64FrameContext("SDK CALL language byte bound")
				}
			}
			language.WriteString("]")
		}
		actual, err := DeriveGoFuncABI0Signature(path+"."+name, fn, "amd64", sizes)
		if err != nil || !goAMD64FrameScalarCall(actual) || !goAMD64FrameSDKABI0Entry(texts, actual.Name) {
			return nil, goAMD64FrameContext("SDK CALL lacks its exact scalar ABI0 declaration/entry: %s: %v", name, err)
		}
		declarations[actual.Name] = goAMD64FrameDeclaration{signature: actual,
			transport: goAMD64FrameCompositeTransport, languageType: language.String()}
	}
	return declarations, nil
}

func (source *GoAMD64FrameSource) ordinarySDKCallTexts(selected goAMD64FrameSelection, entries map[string]bool) ([]gostaticstorage.TextRecord, error) {
	builtin, err := source.read(filepath.Join(source.env["GOROOT"], "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		return nil, err
	}
	referenced := make(map[string]gostaticstorage.SDKReferencedArchive)
	remaining := int64(64 << 20) // Same complete-archive budget as the decoder.
	paths := []string{selected.ImportPath}
	for len(paths) != 0 {
		path := paths[len(paths)-1]
		paths = paths[:len(paths)-1]
		if _, captured := referenced[path]; captured || path == "unsafe" {
			continue
		}
		dependency, found := source.imports[path]
		if !found || !dependency.Standard || dependency.Module != nil || dependency.Export == "" {
			return nil, goAMD64FrameContext("SDK CALL archive lacks its actual dependency: %s", path)
		}
		archive, err := source.readBound(dependency.Export, remaining)
		if err != nil {
			return nil, err
		}
		remaining -= int64(len(archive))
		referenced[path] = gostaticstorage.SDKReferencedArchive{PackagePath: path, Sources: dependency.SFiles, Archive: archive}
		paths = append(paths, dependency.Imports...)
	}
	archive := referenced[selected.ImportPath].Archive
	if len(selected.SFiles) == 0 {
		return gostaticstorage.ObserveX86SDKCompilerText(archive, builtin, source.request.Target, referenced)
	}
	targets := make(map[string]bool, len(entries))
	for name := range entries {
		targets[selected.ImportPath+"."+name] = true
	}
	members, err := gostaticstorage.ObserveX86SDKCallArchiveReferences(archive, builtin, source.request.Target, selected.SFiles, referenced, targets)
	if err != nil {
		return nil, goAMD64FrameContext("actual SDK CALL archive: %v", err)
	}
	var texts []gostaticstorage.TextRecord
	for _, member := range members {
		texts = append(texts, member.Texts...)
	}
	return texts, nil
}

func goAMD64FrameSDKABI0Entry(texts []gostaticstorage.TextRecord, name string) bool {
	// These roles belong to the existing decoder's pinned current goobj
	// schema (objabi.IsText, goobj.SymFlagABIWrapper and objabi.R_CALL).
	const (
		textKind       = 1
		fipsTextKind   = 2
		abiWrapperFlag = 1 << 6
		callRelocation = 7
	)
	var entry, internal *gostaticstorage.TextRecord
	for index := range texts {
		text := &texts[index]
		if text.Name != name {
			continue
		}
		if text.Kind != textKind && text.Kind != fipsTextKind || text.Size <= 0 || text.Size != int64(len(text.Code)) {
			return false
		}
		switch text.ABI {
		case 0:
			if entry != nil {
				return false
			}
			entry = text
		case 1:
			if internal != nil {
				return false
			}
			internal = text
		default:
			return false
		}
	}
	if entry == nil {
		return false
	}
	// An original ABI0 assembly entry needs no adapter; an actual generated
	// adapter must retain its unique ABIInternal target in the same archive.
	if entry.Flags2&abiWrapperFlag == 0 {
		return true
	}
	calls := 0
	for _, relocation := range entry.Relocations {
		if relocation.Type == callRelocation && relocation.Target.Name == name {
			if !relocation.Target.ABIKnown || relocation.Target.ABI != 1 || relocation.Size != 4 || relocation.Add != 0 {
				return false
			}
			calls++
		}
	}
	return internal != nil && calls == 1
}
