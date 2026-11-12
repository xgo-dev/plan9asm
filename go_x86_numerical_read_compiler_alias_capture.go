package plan9asm

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// These are the selected Go1.27 directive/export, ABI-wrapper and object-flag
// rules. They do not register an older SDK producer or infer semantics from
// the translator's build version. Every byte becomes a normal live input.
var numericalCompilerAliasSchema = map[string]string{
	"src/cmd/compile/internal/noder/noder.go":  "2aa3493281bfced8419994a553606fe074f3dbde6a46cf7a66cff0519cb68e83",
	"src/cmd/compile/internal/noder/writer.go": "53550393cf60bd31892e18a4a79715670a7243289445b57919faa69163a256e0",
	"src/cmd/compile/internal/noder/reader.go": "10051996ac541466c4f0f3ccfb3ca7181c38726050d49d2c113ab784119d8be6",
	"src/cmd/compile/internal/ssagen/abi.go":   "35b5cea74c417723ff4778cea5175d3a7bdd9c58584af163229e9624a1ee709c",
	"src/cmd/internal/goobj/objfile.go":        "caf835a17e23aa02cae9bda6e8723d8be359846fc4453bd53f3a3947744b938a",
	"src/cmd/internal/obj/objfile.go":          "803546227c02cf46bfa4158be3dfd8067e7457f4e4f78349cb6d42c700b2fcb7",
	"src/cmd/internal/objabi/path.go":          "ff1e056f2f2b3aa1f757bf7be3da769f1f5241da65438e5ebb9f65a6716c8343",
}

func (source *GoX86NumericalReadSource) captureCompilerAliases() error {
	if source.role != numericalSBSDKSource {
		return nil
	}
	joined := source.sdkAssemblyJoin()
	var syntax []*ast.File
	for _, name := range source.guard.selection.GoFiles {
		filename := filepath.Join(source.request.Directory, name)
		data, err := source.guard.read(filename)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), filename, data, parser.ParseComments)
		if err != nil {
			return err
		}
		syntax = append(syntax, file)
	}
	names, err := numericalGoLinknameSpellings(syntax, source.request.PackagePath)
	if err != nil {
		return err
	}
	wanted := numericalCompilerAliasDemand(source.file, source.request.PackagePath, names)
	if len(wanted) == 0 {
		return nil
	}
	if joined == nil || source.guard.env["GOARCH"] != "amd64" || joined.Observation.Objects == nil ||
		len(joined.Observation.Objects.Members) < 2 || len(source.native.ArchiveMembers) < 2 {
		return numericalSBContext("foreign declarations need the complete registered compiler/assembly join")
	}
	for role, expected := range numericalCompilerAliasSchema {
		data, err := source.guard.read(filepath.Join(source.guard.env["GOROOT"], filepath.FromSlash(role)))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != expected {
			return numericalSBContext("foreign declaration selected compiler schema differs: %s", role)
		}
	}
	header := joined.Observation.Header
	generated, err := gostaticstorage.ObserveX86SDKCompilerText(header.CompilerObject,
		joined.Observation.ObjectInputs.BuiltinSource, source.request.Target, joined.Observation.ObjectInputs.Referenced)
	if err != nil {
		return numericalSBContext("actual complete header compiler object: %v", err)
	}
	selected := joined.Observation.Objects.Members[1]
	nativeMember := source.native.ArchiveMembers[1]
	if selected.Name != "_go_.o" || nativeMember.Name != selected.Name || nativeMember.Offset != selected.Offset ||
		nativeMember.Size != selected.Size || nativeMember.Flags != selected.Flags || !reflect.DeepEqual(nativeMember.Texts, selected.Texts) {
		return numericalSBContext("foreign declaration lost the actual compiler archive member")
	}
	index, err := numericalCompilerAliasIndex(header.SymABI, generated, selected.Texts)
	if err != nil {
		return err
	}
	aliases := make(map[string]numericalCompilerAliasWitness)
	for ordinal, fn := range source.file.Funcs {
		if strings.HasSuffix(fn.Sym, "<>") {
			continue
		}
		name, abi, valid := source.numericalSourceTextIdentity(ordinal, fn, source.guard.env["GOARCH"])
		if !valid {
			return numericalSBContext("foreign declaration has no complete original native TEXT")
		}
		if !wanted[name] {
			continue
		}
		accepted := 0
		for _, standard := range []bool{false, true} {
			if index.association(name, abi, standard) == nil {
				aliases[name] = numericalCompilerAliasWitness{ABI: abi, Standard: standard}
				accepted++
			}
		}
		if accepted != 1 {
			return numericalSBContext("foreign TEXT lacks its unique original compiler alias/ABI witness")
		}
	}
	source.native.CompilerAliases = aliases
	return nil
}

func numericalCompilerAliasDemand(file *File, pkg string, names numericalGoLinknames) map[string]bool {
	prefix := gosym.PackagePrefix(pkg) + "."
	wanted := make(map[string]bool)
	for _, fn := range file.Funcs {
		if strings.HasSuffix(fn.Sym, "<>") {
			continue
		}
		native := numericalNativeName(goTextSymbolForResolution(fn.Sym), pkg)
		local, aliased := names.nativeToLocal[native]
		if !strings.HasPrefix(native, prefix) || aliased && native != prefix+local {
			wanted[native] = true
		}
	}
	return wanted
}
