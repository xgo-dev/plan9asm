package gostaticstorage

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gosym"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"golang.org/x/mod/modfile"
)

// list -export builds the archive before emitting its PackagePublic snapshot.
// Stale/StaleReason describe the pre-build cache state (SDK cmd/go/internal/load
// pkg.go), so the immediately repeated command legitimately omits them. Compare
// every other JSON field, including unknown fields, in its original role. These
// two display fields may only have their official bool/string types; complete
// original stdout is retained separately, never rewritten into evidence.
func sameSelection(first, second []byte) bool {
	decode := func(raw []byte) ([]map[string]json.RawMessage, bool) {
		if len(raw) > 4<<20 {
			return nil, false
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		var result []map[string]json.RawMessage
		for {
			var item map[string]json.RawMessage
			if err := decoder.Decode(&item); err == io.EOF {
				return result, len(result) != 0
			} else if err != nil || item == nil || len(result) >= 64 {
				return nil, false
			}
			for name, value := range item {
				if name == "Stale" {
					var display bool
					if string(value) == "null" || json.Unmarshal(value, &display) != nil {
						return nil, false
					}
					delete(item, name)
				} else if name == "StaleReason" {
					var display string
					if string(value) == "null" || json.Unmarshal(value, &display) != nil {
						return nil, false
					}
					delete(item, name)
				} else {
					var compact bytes.Buffer
					if json.Compact(&compact, value) != nil {
						return nil, false
					}
					item[name] = compact.Bytes()
				}
			}
			result = append(result, item)
		}
	}
	a, okA := decode(first)
	b, okB := decode(second)
	return okA && okB && reflect.DeepEqual(a, b)
}

func reportPackages(report Report, root string) (map[string]Package, error) {
	if report.Protocol == SDKCPUProtocol {
		return sdkCPUPackages(report)
	}
	if report.Protocol == SDKGlobalsProtocol {
		return sdkGlobalsPackages(report)
	}
	if err := ValidateOwnedSourceDirectory(root, report.Environment["GOROOT"], report.Environment["GOMODCACHE"]); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(report.RawSelection))
	packages := make(map[string]Package)
	for {
		var pkg Package
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil || len(packages) >= 64 {
			return nil, contextError("incomplete or oversized actual selection JSON")
		}
		if pkg.ImportPath == "unsafe" && pkg.Standard && pkg.Export == "" {
			continue // Builtin types only; never requested storage.
		}
		if _, duplicate := packages[pkg.ImportPath]; duplicate || pkg.ImportPath == "" || pkg.Module == nil || !pkg.Module.Main ||
			pkg.Module.Dir != root || pkg.Module.Version != "" || len(pkg.Module.Replace) != 0 && string(pkg.Module.Replace) != "null" ||
			pkg.Module.GoMod != filepath.Join(root, "go.mod") || pkg.Standard || pkg.ForTest != "" ||
			len(pkg.Error) != 0 && string(pkg.Error) != "null" || len(pkg.DepsErrors) != 0 || pkg.Export == "" ||
			!filepath.IsAbs(pkg.Export) || !within(root, pkg.Dir) || len(pkg.GoFiles) == 0 || len(pkg.GoFiles) > 256 {
			return nil, contextError("unbound main-module/package/import/archive role")
		}
		for _, files := range [][]string{pkg.SFiles, pkg.CgoFiles, pkg.EmbedFiles, pkg.EmbedPatterns, pkg.CFiles,
			pkg.CXXFiles, pkg.MFiles, pkg.FFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles} {
			if len(files) != 0 {
				return nil, contextError("generated, assembly, cgo, embed or foreign role outside prototype")
			}
		}
		wanted := make([]string, 0, len(pkg.GoFiles))
		seen := make(map[string]bool)
		for _, name := range pkg.GoFiles {
			if filepath.Base(name) != name || seen[name] {
				return nil, contextError("duplicate or noncanonical selected source")
			}
			seen[name] = true
			absolute := filepath.Join(pkg.Dir, name)
			rel, _ := filepath.Rel(root, absolute)
			if report.Source[filepath.ToSlash(rel)] == nil {
				return nil, contextError("selected source lacks original bytes")
			}
			wanted = append(wanted, absolute)
		}
		actual := append([]string(nil), pkg.CompiledGoFiles...)
		for i, file := range actual {
			if !filepath.IsAbs(file) {
				if filepath.Base(file) != file {
					return nil, contextError("unbound relative compiled source")
				}
				actual[i] = filepath.Join(pkg.Dir, file)
			}
		}
		sort.Strings(wanted)
		sort.Strings(actual)
		if !reflect.DeepEqual(wanted, actual) {
			return nil, contextError("effective compiled source differs from original source")
		}
		pkg.CompiledGoFiles = actual
		packages[pkg.ImportPath] = pkg
	}
	entry, exists := packages[report.PackagePath]
	if !exists || entry.Dir != root || entry.Module.Path != report.PackagePath {
		return nil, contextError("requested package differs from actual main-module root")
	}
	mod, err := modfile.Parse("go.mod", report.Source["go.mod"], nil)
	if err != nil || mod.Module == nil || mod.Module.Mod.Path != entry.Module.Path || len(mod.Replace) != 0 {
		return nil, contextError("original module declaration differs from actual selection")
	}
	for _, pkg := range packages {
		if pkg.Module.Path != entry.Module.Path || pkg.ImportPath != entry.Module.Path && !strings.HasPrefix(pkg.ImportPath, entry.Module.Path+"/") {
			return nil, contextError("package identity differs from actual module")
		}
		for _, path := range pkg.Imports {
			if path == "unsafe" {
				continue
			}
			destination := path
			if mapped := pkg.ImportMap[path]; mapped != "" {
				destination = mapped
			}
			if destination != path || packages[destination].ImportPath == "" {
				return nil, contextError("unbound actual import map or dependency")
			}
		}
		if len(pkg.ImportMap) != 0 {
			for path, destination := range pkg.ImportMap {
				found := false
				for _, actual := range pkg.Imports {
					found = found || actual == path
				}
				if !found || path != destination {
					return nil, contextError("unknown actual import-map edge")
				}
			}
		}
	}
	return packages, nil
}

func bindVariables(report Report, packages map[string]Package, references []Reference) ([]Variable, error) {
	_, arch, _ := strings.Cut(report.Target, "/")
	sizes := types.SizesFor("gc", arch)
	if sizes == nil {
		return nil, contextError("unknown actual target layout")
	}
	var result []Variable
	for _, ref := range references {
		pkg, exists := packages[ref.PackagePath]
		if !exists {
			return nil, contextError("variable owner is not an actual imported/entry package")
		}
		fset := token.NewFileSet()
		var syntax []*ast.File
		selfLinknames := make(map[string]bool)
		standardFunctions := make(map[string]bool)
		sourceRoot := pkg.Dir
		if !sdkStorageProtocol(report.Protocol) {
			sourceRoot = pkg.Module.Dir
		}
		for _, file := range pkg.CompiledGoFiles {
			rel, _ := filepath.Rel(sourceRoot, file)
			key := filepath.ToSlash(rel)
			if report.Protocol == SDKGlobalsProtocol {
				key = sdkGlobalSourceKey(report.PackagePath, pkg, filepath.Base(file))
			}
			parsed, err := parser.ParseFile(fset, file, report.Source[key], parser.ParseComments)
			if err != nil {
				return nil, contextError("complete selected Go source cannot be parsed")
			}
			// Linknames need an independently bound aliased backing producer.
			for _, group := range parsed.Comments {
				for _, comment := range group.List {
					if strings.HasPrefix(comment.Text, "//go:linknamestd") && report.Protocol == SDKCPUProtocol {
						words := strings.Fields(comment.Text)
						if len(words) != 2 || words[0] != "//go:linknamestd" || !token.IsIdentifier(words[1]) ||
							words[1] == ref.Name || standardFunctions[words[1]] || selfLinknames[words[1]] ||
							!sdkExternalFunctionDirective(parsed, comment, words[1]) {
							return nil, contextError("invalid, duplicate or variable SDK standard-linkname directive")
						}
						standardFunctions[words[1]] = true
						continue // An unrelated external function supplies no variable backing.
					}
					if report.Protocol == SDKGlobalsProtocol && (strings.HasPrefix(comment.Text, "//go:linkname") || strings.HasPrefix(comment.Text, "//go:linknamestd")) {
						words := strings.Fields(comment.Text)
						if len(words) < 2 || len(words) > 3 || !token.IsIdentifier(words[1]) || words[1] == ref.Name {
							return nil, contextError("requested SDK global has an aliased/linkname storage role")
						}
						continue // Unrelated function directives confer no variable backing.
					}
					if strings.HasPrefix(comment.Text, "//go:linkname") && report.Protocol == SDKCPUProtocol {
						words := strings.Fields(comment.Text)
						if len(words) != 2 || words[0] != "//go:linkname" || !token.IsIdentifier(words[1]) ||
							selfLinknames[words[1]] || standardFunctions[words[1]] {
							return nil, contextError("aliased, duplicate or invalid SDK self-linkname")
						}
						selfLinknames[words[1]] = true
						continue
					}
					if strings.HasPrefix(comment.Text, "//go:linkname") || strings.HasPrefix(comment.Text, "//line ") {
						return nil, contextError("linkname/source remapping outside prototype")
					}
				}
			}
			syntax = append(syntax, parsed)
		}
		actual := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
			data := report.Archives[path]
			if data == nil || packages[path].ImportPath != path {
				return nil, contextError("type importer lacks authenticated actual archive")
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		})
		typed, err := (&types.Config{Importer: actual, Sizes: sizes, GoVersion: "go1.27"}).Check(pkg.ImportPath, fset, syntax, nil)
		if err != nil || typed.Name() != pkg.Name {
			return nil, contextError("same-source target typecheck differs from actual package")
		}
		object, exists := typed.Scope().Lookup(ref.Name).(*types.Var)
		if !exists || object.Pkg() == nil || object.Pkg().Path() != ref.PackagePath {
			return nil, contextError("requested object is not an actual package variable")
		}
		if report.Protocol == SDKGlobalsProtocol && (ref.PackagePath != report.PackagePath || !sdkGlobalPointerFree(object.Type(), 0)) {
			return nil, contextError("SDK global requires its original entry-package pointer-free variable")
		}
		if ref.PackagePath != report.PackagePath || report.Protocol == SDKCPUProtocol {
			// For an imported owner, require the actual selected export's Var,
			// not merely a same-spelled source declaration in another directory.
			imported, err := actual.Import(ref.PackagePath)
			if err != nil {
				return nil, contextError("actual imported variable export cannot be decoded")
			}
			declared, ok := imported.Scope().Lookup(ref.Name).(*types.Var)
			qualifier := func(pkg *types.Package) string { return pkg.Path() }
			if !ok || declared.Pkg() == nil || declared.Pkg().Path() != ref.PackagePath ||
				types.TypeString(declared.Type(), qualifier) != types.TypeString(object.Type(), qualifier) {
				return nil, contextError("actual imported Var differs from complete original declaration")
			}
			object = declared
		}
		size := sizes.Sizeof(object.Type())
		if size <= 0 || size > 1<<20 {
			return nil, contextError("variable extent outside bounded numerical storage")
		}
		numerical := make([]bool, int(size))
		if err := numericBytes(object.Type(), sizes, numerical, 0, 0); err != nil {
			return nil, err
		}
		var records map[string]dataRecord
		if report.Protocol == SDKGlobalsProtocol {
			records, err = readSDKGlobalArchive(report.Archives[ref.PackagePath], report.Target, pkg.SFiles)
		} else if report.Protocol == SDKCPUProtocol {
			records, err = readSDKCPUArchive(report.Archives[ref.PackagePath], report.Target, pkg.SFiles)
		} else {
			records, err = readArchive(report.Archives[ref.PackagePath], report.Target)
		}
		if err != nil {
			return nil, err
		}
		name := gosym.PackagePrefix(ref.PackagePath) + "." + ref.Name
		record, present := records[name]
		flags2 := uint8(0)
		if selfLinknames[ref.Name] {
			flags2 = 16 // SymFlag2Linkname: exact original one-argument Var directive.
		}
		if !present || record.Name != name || record.Size != size || record.ABI != 0 || record.Flags != 0 || record.Flags2 != flags2 {
			return nil, contextError("actual variable and native symbol identity/extent/flags disagree")
		}
		switch record.Kind {
		case 9, 10: // SBSS, SNOPTRBSS; initialized bytes, not constant values.
			if len(record.Data) != 0 || len(record.Relocations) != 0 {
				return nil, contextError("BSS record has nonzero data/relocation role")
			}
		case 5, 7: // SNOPTRDATA, SDATA. Do not infer missing DATA tail bytes.
			if int64(len(record.Data)) != size {
				return nil, contextError("DATA does not explicitly initialize the complete native extent")
			}
		default:
			return nil, contextError("requested object is not ordinary initialized BSS/DATA")
		}
		used := make([]bool, len(numerical))
		for _, relocation := range record.Relocations {
			if relocation.Type != 1 || relocation.Offset < 0 || relocation.Size != 4 && relocation.Size != 8 ||
				relocation.Size > size || relocation.Offset > size-relocation.Size {
				return nil, contextError("unsupported or invalid physical DATA relocation")
			}
			for offset := relocation.Offset; offset < relocation.Offset+relocation.Size; offset++ {
				if used[offset] {
					return nil, contextError("overlapping DATA relocations")
				}
				used[offset], numerical[offset] = true, false
			}
		}
		var spans []Span
		for offset := 0; offset < len(numerical); {
			if !numerical[offset] {
				offset++
				continue
			}
			first := offset
			for offset < len(numerical) && numerical[offset] {
				offset++
			}
			spans = append(spans, Span{int64(first), int64(offset - first)})
		}
		if len(spans) == 0 {
			return nil, contextError("variable contains no initialized numerical byte span")
		}
		result = append(result, Variable{Reference: ref, NativeName: name,
			GoType: types.TypeString(object.Type(), func(pkg *types.Package) string { return pkg.Path() }),
			Size:   size, Alignment: record.Align, Kind: record.Kind, Numerical: spans,
			DefinitionMember: record.Member, DefinitionIndex: record.Index})
	}
	return result, nil
}

func sdkExternalFunctionDirective(file *ast.File, comment *ast.Comment, name string) bool {
	for _, declaration := range file.Decls {
		function, valid := declaration.(*ast.FuncDecl)
		if !valid || function.Name.Name != name || function.Recv != nil || function.Body != nil || function.Doc == nil {
			continue
		}
		for _, actual := range function.Doc.List {
			if actual == comment {
				return true
			}
		}
	}
	return false
}

func numericBytes(typ types.Type, sizes types.Sizes, bytes []bool, base int64, depth int) error {
	if depth > 64 || base < 0 || base > int64(len(bytes)) {
		return contextError("numerical type graph bound exceeded")
	}
	size := sizes.Sizeof(typ)
	if size < 0 || size > int64(len(bytes))-base {
		return contextError("type span exceeds actual object extent")
	}
	switch typ := typ.Underlying().(type) {
	case *types.Basic:
		if typ.Info()&(types.IsInteger|types.IsFloat|types.IsBoolean) != 0 && typ.Info()&types.IsUntyped == 0 {
			for offset := base; offset < base+size; offset++ {
				bytes[offset] = true
			}
		}
	case *types.Array:
		stride := sizes.Sizeof(typ.Elem())
		if typ.Len() > 1<<20 || stride < 0 {
			return contextError("array layout bound exceeded")
		}
		for i := int64(0); i < typ.Len(); i++ {
			if err := numericBytes(typ.Elem(), sizes, bytes, base+i*stride, depth+1); err != nil {
				return err
			}
		}
	case *types.Struct:
		fields := make([]*types.Var, typ.NumFields())
		for i := range fields {
			fields[i] = typ.Field(i)
		}
		for i, off := range sizes.Offsetsof(fields) {
			if fields[i].Name() == "_" {
				continue // Blank padding is not numerical permission.
			}
			if err := numericBytes(fields[i].Type(), sizes, bytes, base+off, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateReport independently reconstructs record/layout agreement from all
// retained bytes. It does not authenticate arbitrary JSON or recreate a token;
// actual source/tool/command guards remain Observation.Verify's obligation.
func ValidateReport(report Report) error {
	sdkCPU := report.Protocol == SDKCPUProtocol
	sdkGlobals := report.Protocol == SDKGlobalsProtocol
	if report.Protocol != Protocol && !sdkCPU && !sdkGlobals || !gotoolchain.AuditedGo127(report.Environment["GOVERSION"]) ||
		report.Environment["GOOS"]+"/"+report.Environment["GOARCH"] != report.Target ||
		report.Environment["GOFLAGS"] != "" || report.Environment["GOEXPERIMENT"] != "" ||
		(!sdkCPU && !sdkGlobals && report.Environment["CGO_ENABLED"] != "0" ||
			(sdkCPU || sdkGlobals) && report.Environment["CGO_ENABLED"] != "0" && report.Environment["CGO_ENABLED"] != "1") ||
		report.Environment["CGO_ENABLED"] != report.CommandEnvironment["CGO_ENABLED"] || report.Environment["GOWORK"] != "off" ||
		len(report.Source) == 0 || len(report.Source) != len(report.SourceSHA256) ||
		len(report.Archives) == 0 || len(report.Archives) > 64 || len(report.Archives) != len(report.ArchiveSHA256) ||
		len(report.Variables) == 0 || len(report.Variables) > 32 {
		return contextError("report lacks bounded complete original inputs")
	}
	if err := validateSourceInventory(report.Source, report.Protocol); err != nil {
		return err
	}
	arguments, toolCount, environmentCount := selectionArguments(), 3+len(formatSources), 16
	if sdkCPU || sdkGlobals {
		arguments, toolCount = sdkCPUArguments(), toolCount+1+len(sdkCPUFormatSources)
		if sdkGlobals {
			arguments = sdkGlobalsArguments(report.PackagePath)
		}
		environmentCount += 4
		for key, expected := range sdkCPUProfile(report.Target) {
			if report.CommandEnvironment[key] != expected || report.Environment[key] != expected {
				return contextError("SDK retained target tuning differs")
			}
		}
		if report.Tools["asm"] == "" {
			return contextError("SDK report omits selected actual assembly tool")
		}
		for role, hash := range sdkCPUFormatSources {
			if report.Tools[role] != hash {
				return contextError("unknown SDK assembly source-to-member rules")
			}
		}
	}
	if len(report.RawEnvironment) > 64<<10 || len(report.RawSelection) > 4<<20 ||
		!reflect.DeepEqual(report.CommandArguments, arguments) || !filepath.IsAbs(report.CommandDirectory) ||
		report.CommandBinary != filepath.Join(report.Environment["GOROOT"], "bin", gotoolchain.HostExecutable("go")) ||
		len(report.Tools) != toolCount || len(report.CommandEnvironment) != environmentCount {
		return contextError("report command/tool inventory differs")
	}
	for _, key := range []string{"GOCACHE", "GOPATH", "GOMODCACHE", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(report.CommandEnvironment[key]) {
			return contextError("report lacks effective command cache/temp role")
		}
	}
	for key, value := range map[string]string{"GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "CGO_ENABLED": "0", "GOPROXY": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GOAMD64": "v1"} {
		if key == "CGO_ENABLED" && (sdkCPU || sdkGlobals) {
			continue // The exact observed value was checked against its command above.
		}
		if report.CommandEnvironment[key] != value {
			return contextError("report effective command profile differs")
		}
	}
	if report.CommandEnvironment["GOOS"]+"/"+report.CommandEnvironment["GOARCH"] != report.Target ||
		report.CommandEnvironment["GOCACHE"] != report.Environment["GOCACHE"] ||
		report.CommandEnvironment["GOMODCACHE"] != report.Environment["GOMODCACHE"] ||
		report.CommandEnvironment["GOROOT"] != "" && report.CommandEnvironment["GOROOT"] != report.Environment["GOROOT"] {
		return contextError("actual effective command directory/target/cache role differs")
	}
	for _, hash := range report.Tools {
		if len(hash) != 64 || strings.IndexFunc(hash, func(r rune) bool { return r < '0' || r > '9' && r < 'a' || r > 'f' }) >= 0 {
			return contextError("invalid original tool digest")
		}
	}
	for _, role := range []string{"go", "VERSION", "compile"} {
		if report.Tools[role] == "" {
			return contextError("report omits actual selected tool role")
		}
	}
	var env map[string]string
	if err := json.Unmarshal(report.RawEnvironment, &env); err != nil || !reflect.DeepEqual(env, report.Environment) {
		return contextError("retained actual environment differs")
	}
	for name, expected := range formatSources {
		if report.Tools[name] != expected {
			return contextError("report uses unknown object-format source rules")
		}
	}
	for name, data := range report.Source {
		if name == "" || strings.Contains(name, "\\") || filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || name == ".." || strings.HasPrefix(name, "../") || digest(data) != report.SourceSHA256[name] {
			return contextError("retained source bytes/name/hash changed")
		}
	}
	total := 0
	for name, data := range report.Archives {
		if len(data) > archiveLimit || digest(data) != report.ArchiveSHA256[name] {
			return contextError("retained actual archive bytes/hash changed")
		}
		members, err := archiveMembers(data)
		if err != nil {
			return err
		}
		for _, member := range members {
			if err := ValidateObjectVersion(member.data, report.Target, report.Environment["GOVERSION"]); err != nil {
				return err
			}
		}
		total += len(data)
	}
	if total > 64<<20 {
		return contextError("retained actual export byte bound exceeded")
	}
	var packagesRaw []Package
	decoder := json.NewDecoder(bytes.NewReader(report.RawSelection))
	for len(packagesRaw) < 65 {
		var pkg Package
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return contextError("incomplete retained selection")
		}
		packagesRaw = append(packagesRaw, pkg)
	}
	root := ""
	if sdkCPU {
		root = filepath.Join(report.Environment["GOROOT"], "src", "internal", "cpu")
	}
	if sdkGlobals {
		root = filepath.Join(report.Environment["GOROOT"], "src", filepath.FromSlash(report.PackagePath))
	}
	for _, pkg := range packagesRaw {
		if pkg.ImportPath == report.PackagePath && pkg.Module != nil {
			root = pkg.Module.Dir
		}
	}
	packages, err := reportPackages(report, root)
	if err != nil || root != report.CommandDirectory || len(packages) != len(report.Archives) {
		return contextError("retained actual package/archive inventory differs")
	}
	var references []Reference
	for i, variable := range report.Variables {
		if !token.IsIdentifier(variable.Name) || variable.Name == "_" || variable.PackagePath == "" ||
			i > 0 && referenceKey(variable.Reference) <= referenceKey(report.Variables[i-1].Reference) {
			return contextError("noncanonical or duplicate requested variable")
		}
		references = append(references, variable.Reference)
	}
	actual, err := bindVariables(report, packages, references)
	if err != nil || !reflect.DeepEqual(actual, report.Variables) {
		return contextError("reader reconstruction differs from recorded numerical/native storage")
	}
	texts, err := textArchives(report, packages)
	if err != nil || report.TextProtocol != TextProtocol || !reflect.DeepEqual(texts, report.TextArchives) {
		return contextError("reader reconstruction differs from actual TEXT records")
	}
	return nil
}
