package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gosym"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// GoARM64ScratchCaptureRequest describes actual stock-Go inputs. No field is
// a claim that source, an object, a callee or a native frame has been verified.
type GoARM64ScratchCaptureRequest struct {
	GoBinary, Directory, AssemblyFile, Target string
	Environment                               []string
}

// GoARM64ScratchSource is a live, nonserializable native-source observation.
// Its only potential permission is that an entire actual callee closure does
// not observe incoming Go assembler R27 scratch. Independently actual bodyless
// declarations and wrapper byte transport supply the ordinary call tuple; no
// memory, stack, caller-save or register-entry permission is supplied here.
type GoARM64ScratchSource struct {
	mu               sync.Mutex
	ready            bool
	request          GoARM64ScratchCaptureRequest
	settings         map[string]string
	inputs           map[string][32]byte
	generatedPaths   map[string]string
	bytes            int64
	owned            string
	ownedInfo        os.FileInfo
	selection        []byte
	packages         map[string]arm64ScratchPackage
	actual           GoPackage
	file             *File
	native           map[string][]arm64ScratchNativeBody
	ordinal          int
	functions        map[string]Func
	loaded           map[string]bool
	typed            map[string]GoPackage
	closed           map[string]FuncSig
	assembly         map[string]bool
	abis             map[string]string
	filePrefix       string
	builtinVersions  map[string]string
	compilingRuntime bool
}

type arm64ScratchPackage struct {
	Dir, ImportPath, Name, Export, ForTest                                         string
	Standard, Goroot                                                               bool
	GoFiles, CompiledGoFiles, SFiles, HFiles, Imports                              []string
	CgoFiles, CFiles, CXXFiles, MFiles, FFiles, SwigFiles, SwigCXXFiles, SysoFiles []string
	ImportMap                                                                      map[string]string
	Module                                                                         *struct {
		Path, Version, Dir, GoMod, GoVersion string
		Main                                 bool
		Replace                              json.RawMessage
	}
	Error      json.RawMessage
	DepsErrors []json.RawMessage
}

type arm64ScratchNativeBody struct {
	source string
	code   []uint32
	calls  []string
	relocs []arm64ScratchNativeRelocation
}

type arm64ScratchNativeRelocation struct {
	at, width    int
	kind, target string
	addend       int64
}

func arm64ScratchContext(format string, args ...any) error {
	return fmt.Errorf("%w: ARM64 actual native scratch closure: %s", ErrProbeNeedsContext, fmt.Sprintf(format, args...))
}

func (source *GoARM64ScratchSource) run(ctx context.Context, args ...string) ([]byte, error) {
	if err := source.verifyGeneratedPaths(); err != nil {
		return nil, err
	}
	output, err := goasmcmd.Run(ctx, source.request.Directory, source.request.Environment, source.request.GoBinary, args...)
	return output, errors.Join(err, source.verifyGeneratedPaths())
}

func (source *GoARM64ScratchSource) read(name string) ([]byte, error) {
	data, err := goAMD64FrameRead(name)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if old, exists := source.inputs[name]; exists {
		if old != digest {
			return nil, arm64ScratchContext("input changed during capture: %s", filepath.Base(name))
		}
	} else {
		if len(source.inputs) >= 8192 || int64(len(data)) > 256<<20-source.bytes {
			return nil, arm64ScratchContext("shared source/tool/archive input budget exceeded")
		}
		source.bytes += int64(len(data))
		source.inputs[name] = digest
	}
	return data, nil
}

func CaptureGoARM64ScratchSource(ctx context.Context, pkg GoPackage, request GoARM64ScratchCaptureRequest) (_ *GoARM64ScratchSource, result error) {
	if ctx == nil || ctx.Err() != nil || pkg.Types == nil || pkg.Types.Path() != pkg.Path ||
		!filepath.IsAbs(request.GoBinary) || !filepath.IsAbs(request.Directory) ||
		filepath.Base(request.AssemblyFile) != request.AssemblyFile || filepath.Ext(request.AssemblyFile) != ".s" {
		return nil, arm64ScratchContext("requires a live context and actual absolute source/tool inputs")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, arm64ScratchContext("capture context is unbounded")
	}
	goos, goarch, valid := strings.Cut(request.Target, "/")
	if !valid || goarch != "arm64" || goos != "linux" && goos != "darwin" && goos != "windows" {
		return nil, arm64ScratchContext("target is outside the ordinary ARM64 object domain")
	}
	var err error
	request.Directory, err = sourcepath.Resolve(request.Directory)
	if err != nil {
		return nil, err
	}
	request.Environment = append([]string(nil), request.Environment...)
	source := &GoARM64ScratchSource{request: request, settings: make(map[string]string),
		inputs: make(map[string][32]byte), generatedPaths: make(map[string]string),
		packages: make(map[string]arm64ScratchPackage), native: make(map[string][]arm64ScratchNativeBody),
		functions: make(map[string]Func), loaded: make(map[string]bool), typed: make(map[string]GoPackage),
		closed: make(map[string]FuncSig), assembly: make(map[string]bool), abis: make(map[string]string)}
	for _, item := range request.Environment {
		key, value, valid := strings.Cut(item, "=")
		if !valid || key == "" {
			return nil, arm64ScratchContext("malformed actual environment")
		}
		source.settings[key] = value
	}
	for key, value := range map[string]string{"GOOS": goos, "GOARCH": goarch, "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOEXPERIMENT": ""} {
		if source.settings[key] != value {
			return nil, arm64ScratchContext("actual %s is outside the ordinary source role", key)
		}
	}
	if driver := source.settings["GOPACKAGESDRIVER"]; driver != "" && driver != "off" {
		return nil, arm64ScratchContext("custom package driver requires an independent source role")
	}
	if _, err := source.read(request.GoBinary); err != nil {
		return nil, err
	}
	observed, err := source.run(ctx, "env", "-json", "GOROOT", "GOTOOLDIR", "GOCACHE", "GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOEXPERIMENT")
	if err != nil {
		return nil, err
	}
	var settings map[string]string
	if err := json.Unmarshal(observed, &settings); err != nil {
		return nil, err
	}
	for key, value := range settings {
		if supplied, exists := source.settings[key]; exists && supplied != value {
			return nil, arm64ScratchContext("actual driver changed %s", key)
		}
		source.settings[key] = value
	}
	if settings["CGO_ENABLED"] != "0" {
		return nil, arm64ScratchContext("actual CGO role needs an independent native closure")
	}
	root, err := sourcepath.Resolve(settings["GOROOT"])
	if err != nil || !filepath.IsAbs(root) || !goAssemblyPathWithinRoot(root, request.GoBinary) {
		return nil, arm64ScratchContext("actual Go binary and SDK differ")
	}
	source.settings["GOROOT"] = root
	version, err := source.read(filepath.Join(root, "VERSION"))
	if err != nil || strings.Split(string(version), "\n")[0] != settings["GOVERSION"] {
		return nil, arm64ScratchContext("actual SDK version differs")
	}
	for _, tool := range []string{"asm", "compile", "objdump", "pack"} {
		name, err := source.run(ctx, "tool", "-n", tool)
		if err != nil {
			return nil, err
		}
		if err := source.readObservedTool(tool, strings.TrimSpace(string(name))); err != nil {
			return nil, err
		}
	}
	// Backend source is an input identity, not a version-based permission.
	for _, directory := range []string{"cmd/internal/obj/arm64", "cmd/internal/goobj", "cmd/internal/objabi", "cmd/internal/archive", "cmd/internal/objfile", "cmd/internal/src", "cmd/asm/internal/flags", "cmd/compile/internal/ssagen", "cmd/compile/internal/abi"} {
		entries, err := os.ReadDir(filepath.Join(root, "src", directory))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				if _, err := source.read(filepath.Join(root, "src", directory, entry.Name())); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := source.captureObjectSourceMetadata(root); err != nil {
		return nil, err
	}
	source.selection, err = source.run(ctx, "list", "-deps", "-export", "-compiled", "-mod=readonly", "-json", ".")
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(source.selection))
	for decoder.More() {
		var selected arm64ScratchPackage
		if err := decoder.Decode(&selected); err != nil {
			return nil, err
		}
		if selected.ImportPath == "" || len(source.packages) >= 256 || selected.ForTest != "" ||
			len(selected.Error) != 0 || len(selected.DepsErrors) != 0 {
			return nil, arm64ScratchContext("unknown or nonordinary actual package selection")
		}
		if _, duplicate := source.packages[selected.ImportPath]; duplicate {
			return nil, arm64ScratchContext("duplicate actual package identity")
		}
		source.packages[selected.ImportPath] = selected
	}
	selected, present := source.packages[pkg.Path]
	if !present || selected.Dir != request.Directory || selected.Module == nil || !selected.Module.Main ||
		len(selected.Module.Replace) != 0 || len(selected.CgoFiles) != 0 || len(selected.SysoFiles) != 0 ||
		!reflect.DeepEqual(selected.GoFiles, selected.CompiledGoFiles) || selected.Export == "" {
		return nil, arm64ScratchContext("capture requires the unchanged ordinary main-package selection")
	}
	if _, err := source.read(selected.Module.GoMod); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(selected.Dir, "go.sum")); err == nil {
		if _, err := source.read(filepath.Join(selected.Dir, "go.sum")); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := source.typecheck(ctx, pkg, selected); err != nil {
		return nil, err
	}
	temporary := source.settings["TMPDIR"]
	if !filepath.IsAbs(temporary) {
		return nil, arm64ScratchContext("actual owned temporary directory must be absolute")
	}
	source.owned, err = os.MkdirTemp(temporary, "plan9asm-arm64-native-scratch-")
	if err != nil {
		return nil, err
	}
	source.ownedInfo, err = os.Lstat(source.owned)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, source.Close())
		}
	}()
	// Request TMPDIR may be an alias. Bind only this newly created factory
	// directory to its physical path; original/tool inputs remain strict.
	canonicalOwned, err := sourcepath.Resolve(source.owned)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(canonicalOwned)
	if err != nil || !info.IsDir() || !os.SameFile(info, source.ownedInfo) {
		return nil, arm64ScratchContext("created object directory identity changed: %v", err)
	}
	source.owned = canonicalOwned
	if err := source.captureAssembly(ctx, selected); err != nil {
		return nil, err
	}
	// Finish every transitive native/source/declaration observation before this
	// token becomes visible. Bind and all consumers only read the sealed maps.
	for _, function := range source.file.Funcs {
		for _, instruction := range function.Instrs {
			if (instruction.Op != "CALL" && instruction.Op != "BL") || len(instruction.Args) != 1 || instruction.Args[0].Kind != OpSym {
				continue
			}
			symbol := strings.TrimSuffix(instruction.Args[0].Sym, "(SB)")
			if strings.Contains(symbol, "<") {
				continue
			}
			canonical := strings.ReplaceAll(symbol, "·", ".")
			if strings.HasPrefix(canonical, ".") {
				canonical = source.actual.Path + canonical
			}
			closed, err := source.closedNativeCallee(ctx, canonical, make(map[string]bool), 0)
			if err != nil {
				return nil, err
			}
			if !closed {
				continue
			}
			layout, err := source.actualCalleeSignature(ctx, canonical, canonical)
			if err != nil {
				return nil, err
			}
			if source.abis[canonical] == "ABIInternal" && !source.actualABI0Wrapper(canonical, layout) {
				return nil, arm64ScratchContext("actual SDK ABI0 wrapper does not preserve its declared tuple")
			}
			source.closed[canonical] = layout
		}
	}
	source.ready = true
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

func (source *GoARM64ScratchSource) typecheck(_ context.Context, supplied GoPackage, selected arm64ScratchPackage) error {
	fset := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range selected.GoFiles {
		if filepath.Base(name) != name {
			return arm64ScratchContext("nonlocal selected Go filename")
		}
		filename := filepath.Join(selected.Dir, name)
		data, err := source.read(filename)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(fset, filename, data, parser.ParseComments)
		if err != nil {
			return err
		}
		syntax = append(syntax, file)
	}
	lookup := func(path string) (io.ReadCloser, error) {
		if mapped := selected.ImportMap[path]; mapped != "" {
			path = mapped
		}
		pkg, present := source.packages[path]
		if !present || pkg.Export == "" {
			return nil, arm64ScratchContext("missing actual imported export for %s", path)
		}
		data, err := source.readObservedExport(pkg)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	config := types.Config{Importer: importer.ForCompiler(fset, "gc", lookup), Sizes: types.SizesFor("gc", "arm64")}
	if selected.Module != nil && selected.Module.GoVersion != "" {
		config.GoVersion = "go" + selected.Module.GoVersion
	}
	pkg, err := config.Check(selected.ImportPath, fset, syntax, nil)
	if err != nil {
		return arm64ScratchContext("actual selected source failed its independent typecheck: %v", err)
	}
	if supplied.Types != nil {
		for _, name := range pkg.Scope().Names() {
			actual, ok := pkg.Scope().Lookup(name).(*types.Func)
			if !ok {
				continue
			}
			claimed, ok := supplied.Types.Scope().Lookup(name).(*types.Func)
			if !ok || types.TypeString(actual.Type(), nil) != types.TypeString(claimed.Type(), nil) {
				return arm64ScratchContext("actual declaration differs from loaded type identity")
			}
		}
	}
	actual := GoPackage{Path: pkg.Path(), Types: pkg, Syntax: syntax}
	source.typed[pkg.Path()] = actual
	if supplied.Types != nil {
		source.actual = actual
	}
	return nil
}

func (source *GoARM64ScratchSource) preprocess(pkg arm64ScratchPackage, name string) (string, error) {
	filename := filepath.Join(pkg.Dir, name)
	data, err := source.read(filename)
	if err != nil {
		return "", err
	}
	// Match the ordinary profile consumer's token-based CPP frontend. Original
	// files and native objects remain independently bound below; canonical
	// serialization does not relax the exact selected File or its Raw fields.
	options := AssemblyPreprocessOptions{
		FileName: filename, Defines: GoAssemblerDefinesWithEnv(source.settings["GOOS"], "arm64", source.settings),
		ReadInclude: func(parent, include string) (string, []byte, error) {
			if filepath.Base(include) != include || include == "go_asm.h" {
				return "", nil, arm64ScratchContext("generated or redirected include requires its own producer")
			}
			name := filepath.Join(pkg.Dir, include)
			if _, err := os.Lstat(name); os.IsNotExist(err) {
				name = filepath.Join(source.settings["GOROOT"], "pkg", "include", include)
			}
			value, err := source.read(name)
			return name, value, err
		},
	}
	return PreprocessAssemblySource(string(data), options)
}

func (source *GoARM64ScratchSource) captureAssembly(ctx context.Context, pkg arm64ScratchPackage) error {
	present := false
	for _, name := range pkg.SFiles {
		present = present || name == source.request.AssemblyFile
	}
	if !present {
		return arm64ScratchContext("original assembly is not selected")
	}
	expanded, err := source.preprocess(pkg, source.request.AssemblyFile)
	if err != nil {
		return err
	}
	expanded = string(ExpandGoAssemblySource(source.actual, []byte(expanded), "arm64"))
	source.file, err = Parse(ArchARM64, expanded)
	if err != nil {
		return err
	}
	// Capture every selected assembly member before a Keep/chunk operation.
	for _, name := range pkg.SFiles {
		if _, err := source.read(filepath.Join(pkg.Dir, name)); err != nil {
			return err
		}
	}
	if err := source.captureOriginalAssembly(ctx, pkg, source.request.AssemblyFile); err != nil {
		return err
	}
	return source.captureNativePackage(ctx, pkg)
}

func (source *GoARM64ScratchSource) captureOriginalAssembly(ctx context.Context, pkg arm64ScratchPackage, name string) error {
	if filepath.Base(name) != name || filepath.Ext(name) != ".s" {
		return arm64ScratchContext("unknown selected assembly filename")
	}
	filename := filepath.Join(pkg.Dir, name)
	if source.assembly[filename] {
		return nil
	}
	expanded, err := source.preprocess(pkg, name)
	if err != nil {
		return err
	}
	file, err := Parse(ArchARM64, expanded)
	if err != nil {
		return err
	}
	for _, function := range file.Funcs {
		symbol := strings.ReplaceAll(function.Sym, "·", ".")
		if strings.HasPrefix(symbol, ".") {
			symbol = pkg.ImportPath + symbol
		}
		symbol = goStripABISuffix(symbol)
		if _, duplicate := source.functions[symbol]; duplicate {
			return arm64ScratchContext("duplicate original assembly symbol")
		}
		source.functions[symbol] = function
	}
	object := filepath.Join(source.owned, fmt.Sprintf("original-%d.o", source.ordinal))
	source.ordinal++
	args := []string{"tool", "asm", "-S", "-p", pkg.ImportPath, "-I", pkg.Dir, "-I", filepath.Join(source.settings["GOROOT"], "pkg", "include"), "-o", object}
	if pkg.Standard && pkg.Goroot && source.compilingRuntime {
		args = append(args, "-compiling-runtime")
	}
	for _, define := range GoAssemblerDefinesWithEnv(source.settings["GOOS"], "arm64", source.settings) {
		args = append(args, "-D", define)
	}
	args = append(args, filename)
	symabis := filepath.Join(source.owned, fmt.Sprintf("symabis-%d", source.ordinal))
	argsABI := append([]string(nil), args...)
	for i := range argsABI {
		if argsABI[i] == "-S" {
			argsABI[i] = "-gensymabis"
		}
		if argsABI[i] == object {
			argsABI[i] = symabis
		}
	}
	if _, err := source.run(ctx, argsABI...); err != nil {
		return err
	}
	definitions, err := source.read(symabis)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(definitions), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 || fields[0] != "def" && fields[0] != "ref" || fields[2] != "ABI0" && fields[2] != "ABIInternal" {
			return arm64ScratchContext("unknown actual assembler ABI role")
		}
		if fields[0] == "def" {
			symbol := arm64ScratchLogicalNativeSymbol(pkg.ImportPath, fields[1])
			// Stock asm's older symabis frontend leaves a same-package name
			// as "".Name. Its compiler canonicalizes that exact prefix using
			// the actual selected package. Bind the result to this captured
			// source definition; this metadata supplies no ABI by itself.
			if strings.HasPrefix(symbol, `"".`) {
				symbol = pkg.ImportPath + symbol[2:]
				if _, present := source.functions[symbol]; !present {
					return arm64ScratchContext("local assembler ABI definition has no original source")
				}
			}
			if source.abis[symbol] != "" {
				return arm64ScratchContext("duplicate actual assembler ABI definition")
			}
			source.abis[symbol] = fields[2]
		}
	}
	if _, err := source.run(ctx, args...); err != nil {
		return err
	}
	if _, err := source.read(object); err != nil {
		return err
	}
	output, err := source.run(ctx, "tool", "objdump", object)
	if err != nil {
		return err
	}
	bodies, err := arm64ScratchObjectBodies(output)
	if err != nil {
		return err
	}
	for symbol, body := range bodies {
		symbol = arm64ScratchLogicalNativeSymbol(pkg.ImportPath, symbol)
		source.native[symbol] = append(source.native[symbol], body)
	}
	source.assembly[filename] = true
	return nil
}

// Go archives retain ABI0 assembly and compiler-generated ABI wrappers as
// distinct members with the same displayed symbol. Inspect ALL members, not
// objdump's default first matching entry. All same-name bodies must be safe.
func (source *GoARM64ScratchSource) captureNativePackage(ctx context.Context, pkg arm64ScratchPackage) error {
	if len(pkg.CgoFiles)+len(pkg.CFiles)+len(pkg.CXXFiles)+len(pkg.MFiles)+len(pkg.FFiles)+len(pkg.SwigFiles)+len(pkg.SwigCXXFiles)+len(pkg.SysoFiles) != 0 {
		return arm64ScratchContext("native foreign/object roles are not selected assembly")
	}
	archive, err := source.readObservedExport(pkg)
	if err != nil {
		return err
	}
	members, err := arm64ScratchArchiveMembers(archive)
	if err != nil {
		return err
	}
	var names []string
	for symbol := range source.functions {
		if strings.HasPrefix(symbol, pkg.ImportPath+".") && !source.loaded[symbol] {
			native := gosym.PackagePrefix(pkg.ImportPath) + strings.TrimPrefix(symbol, pkg.ImportPath)
			names = append(names, regexp.QuoteMeta(native))
		}
	}
	if len(names) == 0 {
		return arm64ScratchContext("no actual assembly body for native package")
	}
	pattern := "^(" + strings.Join(names, "|") + ")$"
	for _, member := range members {
		if member.name == "__.PKGDEF" {
			continue
		}
		if !bytes.HasPrefix(member.data, []byte("go object "+strings.ReplaceAll(source.request.Target, "/", " ")+" ")) {
			return arm64ScratchContext("archive member is not the actual target Go object")
		}
		filename := filepath.Join(source.owned, fmt.Sprintf("native-%d.o", source.ordinal))
		source.ordinal++
		// Existing files are never replaced, including members from a second package.
		file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(member.data)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return err
		}
		if _, err := source.read(filename); err != nil {
			return err
		}
		output, err := source.run(ctx, "tool", "objdump", "-s", pattern, filename)
		if err != nil {
			return err
		}
		bodies, err := arm64ScratchObjectBodies(output)
		if err != nil {
			return err
		}
		for name, body := range bodies {
			name = arm64ScratchLogicalNativeSymbol(pkg.ImportPath, name)
			source.native[name] = append(source.native[name], body)
		}
	}
	for symbol := range source.functions {
		if strings.HasPrefix(symbol, pkg.ImportPath+".") {
			source.loaded[symbol] = true
		}
	}
	return nil
}

type arm64ScratchArchiveMember struct {
	name string
	data []byte
}

func arm64ScratchArchiveMembers(data []byte) ([]arm64ScratchArchiveMember, error) {
	if !bytes.HasPrefix(data, []byte("!<arch>\n")) {
		return nil, arm64ScratchContext("actual export is not a Go archive")
	}
	var result []arm64ScratchArchiveMember
	names := make(map[string]bool)
	for offset := 8; offset < len(data); {
		if len(result) >= 256 || len(data)-offset < 60 || string(data[offset+58:offset+60]) != "`\n" {
			return nil, arm64ScratchContext("incomplete or over-bound archive header")
		}
		header := data[offset : offset+60]
		name := strings.TrimSpace(string(header[:16]))
		size, err := strconv.ParseUint(strings.TrimSpace(string(header[48:58])), 10, 32)
		offset += 60
		if err != nil || size == 0 || size > uint64(len(data)-offset) || filepath.Base(name) != name || names[name] {
			return nil, arm64ScratchContext("unknown, duplicate or truncated archive member")
		}
		names[name] = true
		result = append(result, arm64ScratchArchiveMember{name, data[offset : offset+int(size)]})
		offset += int(size)
		if offset%2 != 0 {
			if offset == len(data) || data[offset] != 0 {
				return nil, arm64ScratchContext("missing archive padding")
			}
			offset++
		}
	}
	return result, nil
}

var arm64ScratchRelocation = regexp.MustCompile(`^\[0:([0-9]+)\](R_[A-Z0-9_]+):([^+\s]+)(?:\+(-?[0-9]+))?$`)

func arm64ScratchObjectBodies(output []byte) (map[string]arm64ScratchNativeBody, error) {
	result := make(map[string]arm64ScratchNativeBody)
	name := ""
	var next uint64
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "TEXT" {
			if len(fields) != 3 || !strings.HasSuffix(fields[1], "(SB)") {
				return nil, arm64ScratchContext("unknown native object header")
			}
			name = strings.TrimSuffix(fields[1], "(SB)")
			if _, duplicate := result[name]; duplicate {
				return nil, arm64ScratchContext("duplicate object body")
			}
			result[name] = arm64ScratchNativeBody{source: fields[2]}
			next = 0
			continue
		}
		if name == "" || len(fields) < 4 || len(fields[2]) != 8 {
			return nil, arm64ScratchContext("unknown native object row")
		}
		pc, err := strconv.ParseUint(strings.TrimPrefix(fields[1], "0x"), 16, 64)
		word, wordErr := strconv.ParseUint(fields[2], 16, 32)
		body := result[name]
		if err != nil || wordErr != nil || len(body.code) != 0 && pc != next {
			return nil, arm64ScratchContext("native bytes have a gap or overlap")
		}
		next = pc + 4
		body.code = append(body.code, uint32(word))
		for _, field := range fields[4:] {
			if strings.Contains(field, "R_") {
				match := arm64ScratchRelocation.FindStringSubmatch(field)
				if match == nil {
					body.relocs = append(body.relocs, arm64ScratchNativeRelocation{at: len(body.code) - 1, kind: "unknown"})
				} else {
					width, err := strconv.Atoi(match[1])
					if err != nil {
						return nil, arm64ScratchContext("native relocation width overflow")
					}
					var addend int64
					if match[4] != "" {
						addend, err = strconv.ParseInt(match[4], 10, 64)
					}
					if err != nil {
						return nil, arm64ScratchContext("native relocation width/addend overflow")
					}
					body.relocs = append(body.relocs, arm64ScratchNativeRelocation{len(body.code) - 1, width, match[2], match[3], addend})
					if match[2] == "R_CALLARM64" {
						body.calls = append(body.calls, match[3])
					}
				}
			}
		}
		result[name] = body
	}
	return result, nil
}

// Only these two stock-Go cache observations are transient after a fresh
// export. Retain every other field, including unknown future fields, the full
// record ordering and the actual raw observation in source.selection. Module,
// dependency export, BuildID and complete selected-file identities are not
// projected to the smaller package struct used for parsing declarations.
func arm64ScratchSelectionIdentity(observation []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(observation))
	var records []json.RawMessage
	for {
		var record map[string]json.RawMessage
		if err := decoder.Decode(&record); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if record == nil || len(records) >= 256 {
			return nil, arm64ScratchContext("missing or over-bound source selection record")
		}
		delete(record, "Stale")
		delete(record, "StaleReason")
		canonical, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		records = append(records, canonical)
	}
	if len(records) == 0 {
		return nil, arm64ScratchContext("empty source selection")
	}
	return json.Marshal(records)
}

// This first wrapper transport domain is deliberately bounded: up to eight
// complete pointer/integer words and no results. The actual assembler's
// symabis definition selects ABIInternal; an actual compiler archive member
// must then implement the opposite ABI0 entry. Merely seeing <autogenerated>
// or a self relocation cannot establish the incoming stack tuple.
func (source *GoARM64ScratchSource) actualABI0Wrapper(symbol string, signature FuncSig) bool {
	if signature.Ret != Void || len(signature.Args) == 0 || len(signature.Args) > 8 ||
		len(signature.Frame.Results) != 0 || len(signature.Frame.Params) != len(signature.Args) ||
		len(signature.ArgRegs) != 0 || signature.ARM64GoRegisterABI != nil || signature.ARM64ClosureABI != nil {
		return false
	}
	for i, argument := range signature.Args {
		slot := signature.Frame.Params[i]
		if argument != I64 && argument != Ptr || slot.Type != argument || slot.Index != i || slot.Offset != int64(i)*8 {
			return false
		}
	}
	wrappers := 0
	for _, body := range source.native[symbol] {
		if !source.originalObjectGenerated(body.source) {
			continue
		}
		wrappers++
		code := body.code
		for len(code) != 0 && code[len(code)-1] == 0 {
			code = code[:len(code)-1]
		}
		if len(code) != len(signature.Args)+7 || len(body.calls) != 1 || source.originalObjectCallTarget(body.calls[0]) != symbol ||
			code[0]&^uint32(0x1ff<<12) != 0xf8000ffe {
			return false
		}
		// STR x30,[sp,#-autosize]! encodes the physical frame, not the
		// declaration's logical FP area. Reconstruct the sign, then verify
		// every actual load is from incoming SP+8+typed parameter offset.
		autosize := -int64(int32(code[0]<<11) >> 23)
		if autosize < 16 || autosize > 240 || autosize%16 != 0 ||
			code[1] != 0xf81f83fd || code[2] != 0xd10023fd {
			return false
		}
		for i, slot := range signature.Frame.Params {
			offset := autosize + 8 + slot.Offset
			if offset < 0 || offset%8 != 0 || offset/8 >= 4096 ||
				code[3+i] != 0xf94003e0|uint32(offset/8)<<10|uint32(i) {
				return false
			}
		}
		i := len(signature.Args) + 3
		if code[i] != 0x94000000 || !arm64ScratchGeneratedRestore(code[i+1:i+3], autosize) || code[i+3] != 0xd65f03c0 {
			return false
		}
	}
	return wrappers == 1
}

// Stock obj7's two registered small-frame epilogues: separate BP/LR loads,
// or the older paired BP/LR load followed by the exact SP restoration. This
// checks physical bytes, not a SDK version or a guessed source frame.
func arm64ScratchGeneratedRestore(code []uint32, autosize int64) bool {
	if len(code) != 2 || autosize < 16 || autosize > 240 || autosize%16 != 0 {
		return false
	}
	return code[0] == 0xf85f83fd && code[1] == 0xf84007fe|uint32(autosize)<<12 ||
		code[0] == 0xa97ffbfd && code[1] == 0x910003ff|uint32(autosize)<<10
}

func (source *GoARM64ScratchSource) Verify(ctx context.Context) (result error) {
	if source == nil {
		return arm64ScratchContext("nil capture")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	defer func() {
		if result != nil {
			source.ready = false
		}
	}()
	if !source.ready || ctx == nil || ctx.Err() != nil {
		return arm64ScratchContext("capture is closed or context expired")
	}
	info, err := os.Lstat(source.owned)
	if err != nil || !info.IsDir() || !os.SameFile(info, source.ownedInfo) {
		return arm64ScratchContext("owned object directory changed")
	}
	if err := source.verifyInputBytes(); err != nil {
		return err
	}
	selection, err := source.run(ctx, "list", "-deps", "-export", "-compiled", "-mod=readonly", "-json", ".")
	if err != nil {
		return arm64ScratchContext("actual source/export selection changed: %v", err)
	}
	actual, actualErr := arm64ScratchSelectionIdentity(selection)
	expected, expectedErr := arm64ScratchSelectionIdentity(source.selection)
	if actualErr != nil || expectedErr != nil || !bytes.Equal(actual, expected) {
		return arm64ScratchContext("actual source/export selection changed")
	}
	// The actual selection command is inside, not after, this byte guard.
	// A tool/source/object replacement during that command must revoke the
	// observation even when its stdout claims the same selected identities.
	return source.verifyInputBytes()
}

func (source *GoARM64ScratchSource) verifyInputBytes() error {
	if err := source.verifyGeneratedPaths(); err != nil {
		return err
	}
	for filename, digest := range source.inputs {
		data, err := goAMD64FrameRead(filename)
		if err != nil || sha256.Sum256(data) != digest {
			return arm64ScratchContext("source/tool/export/object input changed: %s", filepath.Base(filename))
		}
	}
	return nil
}

func (source *GoARM64ScratchSource) Close() error {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.ready = false
	if source.owned == "" {
		return nil
	}
	info, err := os.Lstat(source.owned)
	if err != nil || !info.IsDir() || !os.SameFile(info, source.ownedInfo) {
		return arm64ScratchContext("refusing cleanup of replaced owned directory")
	}
	err = os.RemoveAll(source.owned)
	if err == nil {
		source.owned = ""
	}
	return err
}
