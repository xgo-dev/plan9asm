package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// This declaration-only directory describes numerical reads of Go-defined
// variables. It is deliberately separate from emitted DATA, writable objects,
// address values and the SDK's native compiler-record/source capabilities.
type goReadOnlyStorage struct {
	pkg          GoPackage
	sizes        types.Sizes
	file         *File
	original     [32]byte
	declarations map[string]*goReadOnlyDeclaration
	objects      map[string]goReadOnlyObject
	symbols      map[string]string
	resolve      func(string) string
	failure      error
}

// An empty path denotes the current package; other keys are its actual direct
// imports. Each translation rechecks these declarations without capturing an
// SDK, reloading a package, or retaining observations beyond this call.
type goReadOnlyDeclaration struct {
	path    string
	pkg     GoPackage
	syntax  []string
	objects map[string]goReadOnlyObject
}

type goReadOnlyObject struct {
	variable *types.Var
	native   string
	imported bool
	size     int64
	spans    [][2]int64 // half-open numerical byte intervals; padding is absent
	shape    string
}

type goReadOnlyRead struct {
	operand Operand
	width   int64
}

func (read *goReadOnlyRead) allows(operand Operand, width int64) bool {
	return read != nil && width == read.width && reflect.DeepEqual(operand, read.operand)
}

// These complete named rows have paired exact-width volatile emitters. This
// query describes a read role only; it cannot establish storage or NUM itself.
func goReadOnlyOperand(ins Instr, arch string) (Operand, int64, bool) {
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil || ins.x86SDKLiteral != nil {
		return Operand{}, 0, false
	}
	if form, known := x86ScalarStaticLoadProperties(ins, arch); known {
		return form.source, form.bytes, true
	}
	if operand, width, known := goReadOnlyArithmeticOperand(ins, arch); known {
		return operand, width, true
	}
	if form, known := x86NumericalSBVectorReadProperties(ins, arch); known {
		return ins.Args[form.operand], form.spec.sourceBytes, true
	}
	form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch)
	if !known || err != nil || form.memory < 0 {
		return Operand{}, 0, false
	}
	return form.args[form.memory], int64(form.bits / 8), true
}

// Reuse the complete ALU and explicit IMUL grammars. A source declaration
// establishes neither a memory destination nor an implicit accumulator pair.
func goReadOnlyArithmeticOperand(ins Instr, arch string) (Operand, int64, bool) {
	if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known && err == nil &&
		!form.spec.unary && !form.spec.bitString && form.destination.Kind == OpReg {
		if _, valid := x86StaticSBReadAddress(form.source, arch); valid {
			return form.source, int64(form.spec.bits / 8), true
		}
	}
	if form, known, err := x86ExplicitIMULProperties(ins.Op, ins, arch); known && err == nil {
		if _, valid := x86StaticSBReadAddress(form.source, arch); valid {
			return form.source, int64(form.bits / 8), true
		}
	}
	return Operand{}, 0, false
}

func (source *goReadOnlyStorage) readFor(ins Instr, arch string) *goReadOnlyRead {
	if source == nil {
		return nil
	}
	operand, width, valid := goReadOnlyOperand(ins, arch)
	if !valid || !source.allows(operand, width, arch) {
		return nil
	}
	address, _ := x86StaticSBSourceAddress(operand, arch)
	if source.object(address.symbol).imported && !goReadOnlyImportedComparison(ins, arch) {
		return nil
	}
	return &goReadOnlyRead{operand: operand, width: width}
}

func goReadOnlyImportedComparison(ins Instr, arch string) bool {
	form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch)
	return known && err == nil && form.memory >= 0 && !form.test
}

func goReadOnlyContext(format string, args ...any) error {
	return fmt.Errorf("%w: ordinary Go global read: %s", ErrProbeNeedsContext, fmt.Sprintf(format, args...))
}

func goReadOnlyName(pkgPath, symbol string) string {
	if strings.HasPrefix(symbol, "·") {
		symbol = strings.TrimPrefix(symbol, "·")
	} else if strings.HasPrefix(symbol, pkgPath+".") {
		symbol = strings.TrimPrefix(symbol, pkgPath+".")
	}
	if !token.IsIdentifier(symbol) || symbol == "_" {
		return ""
	}
	return symbol
}

func goReadOnlyLocalName(pkg GoPackage, symbol string) string {
	if name := goReadOnlyName(pkg.Path, symbol); name != "" {
		return name
	}
	return goReadOnlyName(pkg.Types.Path(), symbol)
}

func goReadOnlyImportedName(symbol string) (path, name string) {
	symbol = strings.ReplaceAll(strings.ReplaceAll(symbol, "∕", "/"), "·", ".")
	separator := strings.LastIndexByte(symbol, '.')
	if separator <= 0 || !token.IsIdentifier(symbol[separator+1:]) || symbol[separator+1:] == "_" {
		return "", ""
	}
	return symbol[:separator], symbol[separator+1:]
}

func goReadOnlyImportedPackage(pkg GoPackage, path string) (GoPackage, error) {
	dependency := pkg.Imports[path]
	if dependency == nil || dependency == pkg.Types || dependency.Path() != path || !dependency.Complete() || dependency.Scope() == nil {
		return GoPackage{}, goReadOnlyContext("missing complete typed import %q", path)
	}
	found := false
	for _, actual := range pkg.Types.Imports() {
		if actual == dependency {
			found = true
		}
	}
	if !found {
		return GoPackage{}, goReadOnlyContext("import %q differs from the actual typed dependency", path)
	}
	imports := make(map[string]*types.Package)
	for _, actual := range dependency.Imports() {
		if actual == nil || !actual.Complete() || actual.Scope() == nil || actual.Path() == "" || imports[actual.Path()] != nil {
			return GoPackage{}, goReadOnlyContext("import %q has incomplete or duplicate dependencies", path)
		}
		imports[actual.Path()] = actual
	}
	return GoPackage{Path: path, Types: dependency, Imports: imports, Syntax: pkg.ImportSyntax[path]}, nil
}

func (source *goReadOnlyStorage) object(symbol string) goReadOnlyObject {
	if name := goReadOnlyLocalName(source.pkg, symbol); name != "" {
		return source.objects[gosym.PackagePrefix(source.pkg.Path)+"."+name]
	}
	path, name := goReadOnlyImportedName(symbol)
	if path != "" && source.declarations[path] != nil {
		return source.objects[gosym.PackagePrefix(path)+"."+name]
	}
	return goReadOnlyObject{}
}

func goReadOnlySyntax(pkg GoPackage) ([]string, error) {
	if len(pkg.Syntax) == 0 || len(pkg.Syntax) > 256 {
		return nil, goReadOnlyContext("missing or excessive declaration syntax")
	}
	result := make([]string, len(pkg.Syntax))
	for index, file := range pkg.Syntax {
		if file == nil || file.Name == nil || file.Name.Name != pkg.Types.Name() {
			return nil, goReadOnlyContext("declaration package differs")
		}
		var b bytes.Buffer
		if err := format.Node(&b, token.NewFileSet(), file); err != nil || b.Len() > 16<<20 {
			return nil, goReadOnlyContext("declaration syntax is invalid or excessive")
		}
		result[index] = b.String()
	}
	return result, nil
}

type goReadOnlyImporter map[string]*types.Package

func (imports goReadOnlyImporter) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	if pkg := imports[path]; pkg != nil && pkg.Path() == path && pkg.Complete() {
		return pkg, nil
	}
	return nil, goReadOnlyContext("missing actual typed import %q", path)
}

// Recheck already supplied syntax and imports, never go list, an ambient
// importer, a compiler archive capture or the execution of an initializer.
func goReadOnlyTypedSyntax(pkg GoPackage, syntax []string, sizes types.Sizes, objects map[string]goReadOnlyObject) (*types.Package, error) {
	set := token.NewFileSet()
	files := make([]*ast.File, len(syntax))
	for index, source := range syntax {
		file, err := parser.ParseFile(set, fmt.Sprintf("global-source-%d.go", index), source, parser.ParseComments)
		if err != nil {
			return nil, goReadOnlyContext("declaration syntax cannot be rechecked")
		}
		files[index] = file
	}
	typed, err := (&types.Config{Importer: goReadOnlyImporter(pkg.Imports), Sizes: sizes}).Check(pkg.Types.Path(), set, files, nil)
	if err != nil {
		return nil, goReadOnlyContext("syntax does not match a complete typed package: %v", err)
	}
	if err := goReadOnlyCheckAliases(files, typed, objects); err != nil {
		return nil, err
	}
	return typed, nil
}

// This source-only identity check is shared with the actual frame typecheck;
// reusing it must not trigger a second package typecheck or tool invocation.
func goReadOnlyCheckAliases(files []*ast.File, typed *types.Package, objects map[string]goReadOnlyObject) error {
	selfLinknames := make(map[string]bool)
	for _, file := range files {
		for _, comments := range file.Comments {
			for _, comment := range comments.List {
				// Line directives change diagnostic positions, not package or
				// linker identity. Retain them in the complete syntax snapshot
				// and parser/type check; linkname aliases remain separate below.
				words := strings.Fields(comment.Text)
				if len(words) >= 2 && words[0] == "//go:linkname" {
					if objects[words[1]].variable != nil {
						if len(words) != 2 || selfLinknames[words[1]] {
							return goReadOnlyContext("aliased or duplicate global declaration needs its own binding")
						}
						selfLinknames[words[1]] = true
					}
					if len(words) >= 3 {
						for _, object := range objects {
							if words[2] == object.native {
								return goReadOnlyContext("another declaration aliases the requested global")
							}
						}
					}
				}
			}
		}
	}
	if len(selfLinknames) != 0 {
		unsafeImported := false
		for _, dependency := range typed.Imports() {
			unsafeImported = unsafeImported || dependency == types.Unsafe
		}
		if !unsafeImported {
			return goReadOnlyContext("self-linkname declaration lacks its actual unsafe import")
		}
	}
	return nil
}

func goReadOnlyLayout(typ types.Type, sizes types.Sizes) (size int64, spans [][2]int64, shape string, resultErr error) {
	defer func() {
		if recover() != nil {
			size, spans, shape, resultErr = 0, nil, "", goReadOnlyContext("incomplete target type layout")
		}
	}()
	size = sizes.Sizeof(typ)
	if size <= 0 || size > 1<<20 {
		return 0, nil, "", goReadOnlyContext("global numerical extent is empty or excessive")
	}
	var description strings.Builder
	visits := 0
	var visit func(types.Type, int64, int) error
	visit = func(current types.Type, base int64, depth int) error {
		visits++
		if visits > 4096 || description.Len() > 64<<10 {
			return goReadOnlyContext("global layout traversal/description budget exceeded")
		}
		width := sizes.Sizeof(current)
		if depth > 64 || width < 0 || base < 0 || base > size || width > size-base {
			return goReadOnlyContext("global type layout exceeds its numerical extent")
		}
		fmt.Fprintf(&description, "[%T:%d:%d]", current, base, width)
		if named, ok := current.(*types.Named); ok {
			path := ""
			if named.Obj().Pkg() != nil {
				path = named.Obj().Pkg().Path()
			}
			if len(path) > 4096 || len(named.Obj().Name()) > 4096 || description.Len()+len(path)+len(named.Obj().Name())+32 > 64<<10 {
				return goReadOnlyContext("global layout description budget exceeded")
			}
			fmt.Fprintf(&description, "named:%s:%s;", path, named.Obj().Name())
		}
		switch underlying := current.Underlying().(type) {
		case *types.Basic:
			if underlying.Info()&(types.IsInteger|types.IsFloat|types.IsBoolean) == 0 || underlying.Info()&types.IsUntyped != 0 {
				return goReadOnlyContext("global contains pointer/header or nonnumerical storage")
			}
			fmt.Fprintf(&description, "basic:%d;", underlying.Kind())
			if width != 0 {
				end := base + width
				if len(spans) != 0 && spans[len(spans)-1][1] == base {
					spans[len(spans)-1][1] = end
				} else {
					spans = append(spans, [2]int64{base, end})
				}
			}
		case *types.Array:
			fmt.Fprintf(&description, "array:%d;", underlying.Len())
			if underlying.Len() > 1<<20 {
				return goReadOnlyContext("global array exceeds its type bound")
			}
			stride := sizes.Sizeof(underlying.Elem())
			if stride == 0 || underlying.Len() == 0 {
				return nil // Repeated zero-width elements supply no bytes or permission.
			}
			for index := int64(0); index < underlying.Len(); index++ {
				if err := visit(underlying.Elem(), base+index*stride, depth+1); err != nil {
					return err
				}
			}
		case *types.Struct:
			fields := make([]*types.Var, underlying.NumFields())
			for index := range fields {
				fields[index] = underlying.Field(index)
			}
			for index, offset := range sizes.Offsetsof(fields) {
				if len(fields[index].Name()) > 4096 || len(underlying.Tag(index)) > 4096 ||
					description.Len()+len(fields[index].Name())+6*len(underlying.Tag(index))+64 > 64<<10 {
					return goReadOnlyContext("global layout description budget exceeded")
				}
				fmt.Fprintf(&description, "field:%s:%d:%q;", fields[index].Name(), offset, underlying.Tag(index))
				if fields[index].Name() != "_" {
					if err := visit(fields[index].Type(), base+offset, depth+1); err != nil {
						return err
					}
				}
			}
		default:
			return goReadOnlyContext("global contains pointer/header or nonnumerical storage")
		}
		return nil
	}
	if err := visit(typ, 0, 0); err != nil {
		return 0, nil, "", err
	}
	if description.Len() > 64<<10 {
		return 0, nil, "", goReadOnlyContext("global layout description budget exceeded")
	}
	return size, spans, description.String(), nil
}

func bindGoReadOnlyStorage(pkg GoPackage, file *File, sizes types.Sizes, arch string, resolve func(string) string) (*goReadOnlyStorage, error) {
	if file == nil || file.Arch != ArchAMD64 || arch != "amd64" && arch != "386" || pkg.Types == nil || pkg.Types.Scope() == nil {
		return nil, nil
	}
	// Cost-query only complete named numerical-read roles. Other
	// instructions and emitted DATA/GLOBL keep their existing consumers.
	assemblyNames := make(map[string]bool)
	for _, global := range file.Globl {
		assemblyNames[goReadOnlyLocalName(pkg, global.Sym)] = true
	}
	for _, datum := range file.Data {
		assemblyNames[goReadOnlyLocalName(pkg, datum.Sym)] = true
	}
	var emitted map[string]bool
	emittedOwns := func(native string) bool {
		if emitted == nil {
			emitted = make(map[string]bool)
			for _, global := range file.Globl {
				emitted[resolveAssemblyDataSymbol(global.Sym, resolve)] = true
			}
			for _, datum := range file.Data {
				emitted[resolveAssemblyDataSymbol(datum.Sym, resolve)] = true
			}
		}
		return emitted[native]
	}
	source := &goReadOnlyStorage{pkg: pkg, sizes: sizes, resolve: resolve, declarations: make(map[string]*goReadOnlyDeclaration),
		objects: make(map[string]goReadOnlyObject), symbols: make(map[string]string)}
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			operand, _, known := goReadOnlyOperand(instruction, arch)
			if !known {
				continue
			}
			{
				address, valid := x86StaticSBSourceAddress(operand, arch)
				if !valid {
					continue
				}
				owner, path := pkg, ""
				name := goReadOnlyLocalName(pkg, address.symbol)
				if name == "" {
					path, name = goReadOnlyImportedName(address.symbol)
					if path == "" || pkg.Imports[path] == nil || len(pkg.ImportSyntax[path]) == 0 || !goReadOnlyImportedComparison(instruction, arch) {
						continue // Imported storage supplies only the named CMP role.
					}
					var err error
					owner, err = goReadOnlyImportedPackage(pkg, path)
					if err != nil {
						return nil, err
					}
				}
				variable, declared := owner.Types.Scope().Lookup(name).(*types.Var)
				if !declared || variable.IsField() || variable.Pkg() != owner.Types || path == "" && assemblyNames[name] {
					continue // Unknown symbols never inherit another variable's type.
				}
				native := gosym.PackagePrefix(owner.Path) + "." + name
				if emittedOwns(native) {
					continue // A resolved alias definition is still the emitted module's owner.
				}
				if object, present := source.objects[native]; present {
					if object.variable != variable {
						return nil, goReadOnlyContext("different declarations share a native global")
					}
					continue
				}
				if sizes == nil {
					sizes = types.SizesFor("gc", arch)
					source.sizes = sizes
				}
				if sizes == nil {
					return nil, goReadOnlyContext("missing target sizes for a candidate read")
				}
				size, spans, shape, err := goReadOnlyLayout(variable.Type(), sizes)
				if err != nil {
					return nil, err
				}
				object := goReadOnlyObject{variable: variable, native: native, imported: path != "",
					size: size, spans: spans, shape: shape}
				source.objects[native] = object
				declarations := source.declarations[path]
				if declarations == nil {
					// Snapshot maps rather than retaining aliases to caller mutations.
					imports := make(map[string]*types.Package, len(owner.Imports))
					for path, dependency := range owner.Imports {
						imports[path] = dependency
					}
					owner.Imports = imports
					declarations = &goReadOnlyDeclaration{path: path, pkg: owner, objects: make(map[string]goReadOnlyObject)}
					source.declarations[path] = declarations
				}
				declarations.objects[name] = object
			}
		}
	}
	if len(source.objects) == 0 {
		return nil, nil
	}
	if len(source.objects) > 32 {
		return nil, goReadOnlyContext("global declaration inventory exceeds its bound")
	}
	source.file = x86DirectTailSnapshot(file)
	var err error
	for _, declarations := range source.declarations {
		declarations.syntax, err = goReadOnlySyntax(declarations.pkg)
		if err != nil {
			return nil, err
		}
		typed, err := goReadOnlyTypedSyntax(declarations.pkg, declarations.syntax, sizes, declarations.objects)
		if err != nil {
			return nil, err
		}
		for name, object := range declarations.objects {
			actual, present := typed.Scope().Lookup(name).(*types.Var)
			if !present {
				return nil, goReadOnlyContext("global %q has no actual variable declaration", name)
			}
			size, spans, shape, err := goReadOnlyLayout(actual.Type(), sizes)
			if err != nil || size != object.size || shape != object.shape || !reflect.DeepEqual(spans, object.spans) {
				return nil, goReadOnlyContext("global %q type and syntax layouts differ", name)
			}
		}
	}
	source.original, err = x86CallerSourceFingerprint(file)
	if err != nil {
		return nil, err
	}
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			for _, operand := range instruction.Args {
				address, valid := x86StaticSBSourceAddress(operand, arch)
				object := source.object(address.symbol)
				if !valid || object.variable == nil {
					continue
				}
				// Match the exact declaration's native symbol, not an arbitrary
				// resolver alias with a conveniently named Go declaration.
				symbol := address.symbol
				if !strings.ContainsAny(symbol, "·./") {
					symbol = "·" + symbol
				}
				source.symbols[symbol] = object.native
			}
		}
	}
	if err := source.verify(); err != nil {
		return nil, err
	}
	return source, nil
}

func (source *goReadOnlyStorage) verify() error {
	if source == nil {
		return nil
	}
	if source.failure != nil {
		return source.failure
	}
	check := func() error {
		actual, err := x86CallerSourceFingerprint(source.file)
		if err != nil || actual != source.original {
			return goReadOnlyContext("original assembly changed during binding")
		}
		for _, declarations := range source.declarations {
			pkg := source.pkg
			if declarations.path != "" {
				pkg, err = goReadOnlyImportedPackage(source.pkg, declarations.path)
				if err != nil || pkg.Types != declarations.pkg.Types {
					return goReadOnlyContext("actual typed import changed during binding")
				}
			}
			if len(pkg.Imports) != len(declarations.pkg.Imports) {
				return goReadOnlyContext("typed declaration dependencies changed during binding")
			}
			for path, dependency := range declarations.pkg.Imports {
				if pkg.Imports[path] != dependency {
					return goReadOnlyContext("actual typed declaration dependency changed during binding")
				}
			}
			syntax, err := goReadOnlySyntax(pkg)
			if err != nil || !reflect.DeepEqual(syntax, declarations.syntax) {
				return goReadOnlyContext("declaration syntax changed during binding")
			}
			for name, object := range declarations.objects {
				variable, _ := pkg.Types.Scope().Lookup(name).(*types.Var)
				if variable != object.variable {
					return goReadOnlyContext("global declaration identity changed during binding")
				}
				size, spans, shape, err := goReadOnlyLayout(variable.Type(), source.sizes)
				if err != nil || size != object.size || shape != object.shape || !reflect.DeepEqual(spans, object.spans) {
					return goReadOnlyContext("global target layout changed during binding")
				}
			}
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	for symbol, expected := range source.symbols {
		if source.resolve(symbol) != expected {
			return goReadOnlyContext("global resolver differs from its actual declaration")
		}
	}
	return check() // Resolvers are user callbacks and may have changed source.
}

func (source *goReadOnlyStorage) resolveSymbol(symbol string) string {
	actual := source.resolve(symbol)
	if expected, known := source.symbols[symbol]; known && actual != expected {
		source.failure = goReadOnlyContext("global resolver changed during consumption")
	}
	return actual
}

func (source *goReadOnlyStorage) allows(operand Operand, width int64, arch string) bool {
	if source == nil || source.failure != nil || width <= 0 {
		return false
	}
	address, valid := x86StaticSBReadAddress(operand, arch)
	object := source.object(address.symbol)
	if !valid || object.variable == nil || width > object.size || address.offset > object.size-width {
		return false
	}
	for _, span := range object.spans {
		if address.offset >= span[0] && address.offset <= span[1]-width {
			return true
		}
	}
	return false
}
