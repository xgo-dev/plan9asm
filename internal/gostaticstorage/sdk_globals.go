package gostaticstorage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// This producer independently authenticates ordinary Go-defined variables in
// the selected stock SDK. Its actual complete source/export graph, original
// compiler records and target types are separate from the exact CPU producer.
// Neither an SDK path nor a Standard flag alone supplies this authority.
const SDKGlobalsProtocol = "actual_go_sdk_go_numeric_storage_v1"

func CaptureSDKGlobals(ctx context.Context, request Request) (*Observation, error) {
	return captureRole(ctx, request, SDKGlobalsProtocol)
}

func sdkStorageProtocol(protocol string) bool {
	return protocol == SDKCPUProtocol || protocol == SDKGlobalsProtocol
}

func sdkGlobalDirectory(binary, directory, path string) bool {
	return path != "" && filepath.IsLocal(filepath.FromSlash(path)) &&
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) == path &&
		directory == filepath.Join(filepath.Dir(filepath.Dir(binary)), "src", filepath.FromSlash(path))
}

func sdkGlobalsArguments(path string) []string {
	return []string{"list", "-deps", "-json", "-compiled", "-export", "-a", "-p=1", path}
}

func sdkGlobalsSelections(raw []byte, root, entry string, exports bool) (map[string]Package, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	packages := make(map[string]Package)
	for {
		var pkg Package
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil || len(packages) >= 64 {
			return nil, contextError("incomplete or excessive SDK global source graph")
		}
		if !sdkGlobalDirectory(filepath.Join(root, "bin", gotoolchain.HostExecutable("go")), pkg.Dir, pkg.ImportPath) ||
			!pkg.Standard || !pkg.Goroot || pkg.Root != root || pkg.Module != nil || pkg.ForTest != "" || pkg.Name == "" ||
			packages[pkg.ImportPath].ImportPath != "" || len(pkg.GoFiles) == 0 ||
			len(pkg.Error) != 0 && string(pkg.Error) != "null" || len(pkg.DepsErrors) != 0 {
			return nil, contextError("SDK global graph has a foreign/nonoriginal package identity")
		}
		if exports && pkg.ImportPath != "unsafe" && !filepath.IsAbs(pkg.Export) {
			return nil, contextError("SDK global graph lacks its actual compiler export")
		}
		for _, files := range [][]string{pkg.CgoFiles, pkg.EmbedFiles, pkg.EmbedPatterns, pkg.CFiles, pkg.CXXFiles,
			pkg.MFiles, pkg.FFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles} {
			if len(files) != 0 {
				return nil, contextError("SDK global graph needs a separate generated/foreign source mapping")
			}
		}
		seen := make(map[string]bool)
		for _, files := range [][]string{pkg.GoFiles, pkg.SFiles, pkg.HFiles} {
			for _, name := range files {
				if filepath.Base(name) != name || strings.ContainsAny(name, "\\\x00\r\n") || seen[name] {
					return nil, contextError("SDK global selected source identity differs")
				}
				seen[name] = true
			}
		}
		wanted := make([]string, len(pkg.GoFiles))
		for index, name := range pkg.GoFiles {
			wanted[index] = filepath.Join(pkg.Dir, name)
		}
		actual := append([]string(nil), pkg.CompiledGoFiles...)
		for index, name := range actual {
			if !filepath.IsAbs(name) {
				if filepath.Base(name) != name {
					return nil, contextError("SDK global compiled source needs original mapping")
				}
				actual[index] = filepath.Join(pkg.Dir, name)
			}
		}
		sort.Strings(wanted)
		sort.Strings(actual)
		if pkg.ImportPath != "unsafe" && !reflect.DeepEqual(actual, wanted) {
			return nil, contextError("SDK global compiler selection differs from complete original Go sources")
		}
		pkg.CompiledGoFiles = actual
		packages[pkg.ImportPath] = pkg
	}
	if packages[entry].ImportPath != entry || packages["unsafe"].ImportPath != "" && packages["unsafe"].Name != "unsafe" {
		return nil, contextError("SDK global source graph lacks its original entry/builtin identity")
	}
	for _, pkg := range packages {
		for _, path := range pkg.Imports {
			if packages[path].ImportPath != path || pkg.ImportMap[path] != "" && pkg.ImportMap[path] != path {
				return nil, contextError("SDK global import graph has an unobserved/aliased edge")
			}
		}
		for path, destination := range pkg.ImportMap {
			if path != destination || packages[path].ImportPath != path {
				return nil, contextError("SDK global import-map identity differs")
			}
		}
	}
	return packages, nil
}

func sdkGlobalSourceKey(entry string, pkg Package, name string) string {
	if pkg.ImportPath == entry {
		return name
	}
	return "_sdk/" + pkg.ImportPath + "/" + name
}

func (o *Observation) captureSDKGlobalDependencies(ctx context.Context) error {
	// Observe and guard the original sources before the independently forced
	// compiler/export command. Verification repeats its complete selection.
	raw, err := o.run(ctx, "list", "-deps", "-json", "-compiled", o.request.PackagePath)
	if err != nil {
		return err
	}
	packages, err := sdkGlobalsSelections(raw, o.report.Environment["GOROOT"], o.request.PackagePath, false)
	if err != nil {
		return err
	}
	usage, err := sourceUsage(o.report.Source, o.report.Protocol)
	if err != nil {
		return err
	}
	for _, pkg := range packages {
		resolved, resolveErr := sourcepath.Resolve(pkg.Dir)
		info, err := sourcepath.Lstat(pkg.Dir)
		if resolveErr != nil || resolved != pkg.Dir || err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return contextError("SDK global selected directory is redirected/missing")
		}
		o.dirs[pkg.Dir] = info
		for _, files := range [][]string{pkg.GoFiles, pkg.SFiles, pkg.HFiles} {
			for _, name := range files {
				absolute, key := filepath.Join(pkg.Dir, name), sdkGlobalSourceKey(o.request.PackagePath, pkg, name)
				data, err := readRegular(absolute, 16<<20)
				if err != nil {
					return err
				}
				if previous, present := o.report.Source[key]; present {
					if !bytes.Equal(previous, data) {
						return contextError("SDK global original source changed before compiler selection")
					}
				} else if err := usage.add(len(data)); err != nil {
					return err
				}
				o.report.Source[key], o.report.SourceSHA256[key] = data, digest(data)
				o.inputs[absolute] = digest(data)
			}
		}
	}
	return nil
}

func (o *Observation) snapshotSource() (map[string][]byte, error) {
	source, err := snapshot(o.request.Directory, o.report.Protocol)
	if err != nil || o.report.Protocol != SDKGlobalsProtocol {
		return source, err
	}
	packages, err := sdkGlobalsSelections(o.report.RawSelection, o.report.Environment["GOROOT"], o.report.PackagePath, true)
	if err != nil {
		return nil, err
	}
	usage, err := sourceUsage(source, o.report.Protocol)
	if err != nil {
		return nil, err
	}
	for _, pkg := range packages {
		if pkg.ImportPath == o.report.PackagePath {
			continue
		}
		for _, files := range [][]string{pkg.GoFiles, pkg.SFiles, pkg.HFiles} {
			for _, name := range files {
				key := sdkGlobalSourceKey(o.report.PackagePath, pkg, name)
				if _, present := source[key]; present {
					return nil, contextError("SDK dependency source collides with original package inventory")
				}
				data, err := readRegular(filepath.Join(pkg.Dir, name), 16<<20)
				if err != nil {
					return nil, err
				}
				if err := usage.add(len(data)); err != nil {
					return nil, err
				}
				source[key] = data
			}
		}
	}
	return source, nil
}

func sdkGlobalsPackages(report Report) (map[string]Package, error) {
	root := report.Environment["GOROOT"]
	if !sdkCPUTarget(report.Target) || !sdkGlobalDirectory(report.CommandBinary, report.CommandDirectory, report.PackagePath) {
		return nil, contextError("SDK global owner/target/source role differs")
	}
	packages, err := sdkGlobalsSelections(report.RawSelection, root, report.PackagePath, true)
	if err != nil {
		return nil, err
	}
	for path, pkg := range packages {
		if path != "unsafe" && !within(report.Environment["GOCACHE"], pkg.Export) {
			return nil, contextError("SDK global compiler export is outside its observed cache")
		}
		for _, files := range [][]string{pkg.GoFiles, pkg.SFiles, pkg.HFiles} {
			for _, name := range files {
				if report.Source[sdkGlobalSourceKey(report.PackagePath, pkg, name)] == nil {
					return nil, contextError("SDK global complete selected source bytes are absent")
				}
			}
		}
	}
	delete(packages, "unsafe") // The builtin has source, never an archive/global.
	return packages, nil
}

func sdkGlobalPointerFree(typ types.Type, depth int) bool {
	if depth > 64 {
		return false
	}
	switch typ := typ.Underlying().(type) {
	case *types.Basic:
		return typ.Info()&(types.IsInteger|types.IsFloat|types.IsBoolean) != 0 && typ.Info()&types.IsUntyped == 0
	case *types.Array:
		return sdkGlobalPointerFree(typ.Elem(), depth+1)
	case *types.Struct:
		for index := 0; index < typ.NumFields(); index++ {
			if !sdkGlobalPointerFree(typ.Field(index).Type(), depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

// Every actual member is structurally checked in its exact selected SDK role.
// Only compiler SymbolDefs supply Go-defined storage. Assembly data, hashed
// namespaces and exported-type records never supply a requested variable.
func readSDKGlobalArchive(data []byte, target string, sources []string) (map[string]dataRecord, error) {
	return readSDKCompilerStorageArchive(data, target, sources, false)
}

func readSDKCompilerStorageArchive(data []byte, target string, sources []string, cpu bool) (map[string]dataRecord, error) {
	members, err := archiveMembers(data)
	names, namesErr := sdkAssemblyMemberNames(sources)
	if err != nil || namesErr != nil || len(members) != len(sources)+2 ||
		members[0].name != "__.PKGDEF" || members[1].name != "_go_.o" {
		return nil, contextError("SDK global archive differs from complete selected source/member roles")
	}
	var compiler *sdkIndexedMetadataObject
	definitions := make(map[string]bool)
	for index, member := range members[1:] {
		flags := sdkCompilerObjectFlags(target)
		if index != 0 {
			if member.name != names[index-1] {
				return nil, contextError("SDK global assembly source/member identity differs")
			}
			flags |= 4
		}
		reader := objectBody
		if index == 0 {
			reader = sdkObjectBody
		}
		body, err := reader(member.data, target)
		if err != nil {
			return nil, err
		}
		object, err := checkedSDKIndexedMetadata(body, flags, index != 0)
		if err != nil {
			return nil, err
		}
		symbols, err := object.storageSymbols(cpu)
		if err != nil {
			return nil, err
		}
		for _, symbol := range symbols {
			if symbol.Name == "" {
				continue // Anonymous records retain indexed identity and cannot name a variable.
			}
			if cpu && index != 0 && symbol.Kind != 1 {
				return nil, contextError(fmt.Sprintf("assembly data backing outside SDK CPU storage role: member=%s symbol=%q kind=%d ABI=%d", member.name, symbol.Name, symbol.Kind, symbol.ABI))
			}
			identity := symbol.Name + "\x00" + string(rune(symbol.ABI))
			if definitions[identity] {
				return nil, contextError(fmt.Sprintf("SDK global has duplicate same-ABI native definitions: member=%s symbol=%q ABI=%d", member.name, symbol.Name, symbol.ABI))
			}
			definitions[identity] = true
		}
		if index == 0 {
			compiler = object
		}
	}
	result := make(map[string]dataRecord)
	symbols, err := compiler.storageSymbols(cpu)
	if err != nil {
		return nil, err
	}
	for _, symbol := range symbols {
		name, index := symbol.Name, symbol.Index
		if name == "" || symbol.Kind == 1 {
			continue // Anonymous/type metadata and TEXT never provide Go variable storage.
		}
		if result[name].Name != "" {
			return nil, contextError("SDK compiler storage has an empty/duplicate original definition")
		}
		record := dataRecord{Name: name, Member: "_go_.o", Index: index, ABI: symbol.ABI,
			Kind: symbol.Kind, Flags: symbol.Flags, Flags2: symbol.Flags2,
			Size: int64(symbol.Size), Align: int64(symbol.Align)}
		start := binary.LittleEndian.Uint32(compiler.block(13)[index*4:])
		end := binary.LittleEndian.Uint32(compiler.block(13)[(index+1)*4:])
		record.Data = append([]byte(nil), compiler.block(16)[start:end]...)
		first := binary.LittleEndian.Uint32(compiler.block(11)[index*4:])
		last := binary.LittleEndian.Uint32(compiler.block(11)[(index+1)*4:])
		for offset := first; offset < last; offset++ {
			relocation := compiler.block(14)[offset*23 : (offset+1)*23]
			record.Relocations = append(record.Relocations, relocationRecord(relocation))
		}
		result[name] = record
	}
	return result, nil
}

func relocationRecord(value []byte) relocation {
	return relocation{int64(int32(binary.LittleEndian.Uint32(value))), int64(value[4]), binary.LittleEndian.Uint16(value[5:])}
}

// This separate report role retains member identities only. It has no native
// TEXT observations; consumers must bind their independent whole SDK objects.
func sdkGlobalMembers(report Report, packages map[string]Package) (map[string][]TextMember, error) {
	result := make(map[string][]TextMember)
	for path, pkg := range packages {
		if _, err := readSDKGlobalArchive(report.Archives[path], report.Target, pkg.SFiles); err != nil {
			return nil, err
		}
		members, err := archiveMembers(report.Archives[path])
		if err != nil {
			return nil, err
		}
		for index, member := range members {
			flags := uint32(0)
			if index > 0 {
				flags = sdkCompilerObjectFlags(report.Target)
			}
			if index > 1 {
				flags |= 4
			}
			result[path] = append(result[path], TextMember{Name: member.name, Offset: member.offset, Size: int64(len(member.data)), Flags: flags})
		}
	}
	return result, nil
}
