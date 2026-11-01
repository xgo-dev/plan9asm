//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// This separate SDK oracle resolves only actual Aux references to sync/atomic
// through the target compiler's NSym block, exactly as the official loader.
// It never falls through into the target's hashed/nonpackage definitions.
const sdkIndexedAuxReaderSource = `package main

import (
	"cmd/internal/archive"
	"cmd/internal/goobj"
	"encoding/json"
	"fmt"
	"os"
)

type Reference struct {
	OwnerIndex, AuxiliaryIndex uint32
	Type uint8
	PackageIndex, SymbolIndex uint32
	Package, Name string
	ABI uint16
	Kind uint8
	DiagnosticPresent bool
}

func compiler(path string) *goobj.Reader {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	a, err := archive.Parse(f, false)
	if err != nil {
		panic(err)
	}
	for _, entry := range a.Entries {
		if entry.Name != "_go_.o" {
			continue
		}
		data := make([]byte, entry.Obj.Size)
		n, err := f.ReadAt(data, entry.Obj.Offset)
		if err != nil || n != len(data) {
			panic(fmt.Sprint(n, err))
		}
		r := goobj.NewReaderFromBytes(data, false)
		if r == nil {
			panic("invalid original compiler object")
		}
		return r
	}
	panic("missing actual compiler member")
}

func main() {
	r, target := compiler(os.Args[1]), compiler(os.Args[2])
	diagnostics := make(map[goobj.SymRef]string)
	for index := 0; index < r.NRefName(); index++ {
		diagnostic := r.RefName(index)
		diagnostics[diagnostic.Sym()] = diagnostic.Name(r)
	}
	var result []Reference
	count := r.NSym() + r.NHashed64def() + r.NHasheddef() + r.NNonpkgdef()
	for index := uint32(0); index < uint32(count); index++ {
		for ordinal, auxiliary := range r.Auxs(index) {
			ref := auxiliary.Sym()
			if ref.PkgIdx == 0 || ref.PkgIdx >= uint32(r.NPkg()) || r.Pkg(int(ref.PkgIdx)) != "sync/atomic" {
				continue
			}
			if ref.SymIdx >= uint32(target.NSym()) {
				panic("foreign reference is not in actual SymbolDefs")
			}
			symbol := target.Sym(ref.SymIdx)
			diagnostic, present := diagnostics[ref]
			if present && diagnostic != symbol.Name(target) {
				panic("diagnostic differs from actual indexed target")
			}
			result = append(result, Reference{OwnerIndex: index, AuxiliaryIndex: uint32(ordinal), Type: auxiliary.Type(),
				PackageIndex: ref.PkgIdx, SymbolIndex: ref.SymIdx, Package: r.Pkg(int(ref.PkgIdx)),
				Name: symbol.Name(target), ABI: symbol.ABI(), Kind: symbol.Type(), DiagnosticPresent: present})
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
`

type indexedAuxOracleReference struct {
	OwnerIndex, AuxiliaryIndex uint32
	Type                       uint8
	PackageIndex, SymbolIndex  uint32
	Package, Name              string
	ABI                        uint16
	Kind                       uint8
	DiagnosticPresent          bool
}

func indexedForeignArchiveFixture(t *testing.T, arch string) ([]byte, []byte, map[string]SDKReferencedArchive) {
	t.Helper()
	directory, compiler, _ := fixture(t)
	consumer := filepath.Join(directory, "auxfixture")
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	goSource := "package auxfixture\nimport \"sync/atomic\"\nvar Flag atomic.Bool\n" +
		"func Store(value bool) { Flag.Store(value) }\nfunc Entry()\n"
	assembly := "#include \"textflag.h\"\nTEXT ·Entry(SB),NOSPLIT,$0-0\nRET\n"
	for name, source := range map[string]string{"value.go": goSource, "entry.s": assembly} {
		if err := os.WriteFile(filepath.Join(consumer, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw := run(t, compiler, consumer, fixtureEnv(t, "linux/"+arch),
		"list", "-deps", "-json", "-compiled", "-export", "-mod=readonly", "-gcflags=-std", "-asmflags=-std", ".")
	decoder := json.NewDecoder(bytes.NewReader(raw))
	referenced := make(map[string]SDKReferencedArchive)
	var archive []byte
	for {
		var selected struct {
			ImportPath, Export string
			SFiles             []string
			Standard           bool
		}
		if err := decoder.Decode(&selected); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if selected.Export == "" {
			continue
		}
		data, err := os.ReadFile(selected.Export)
		if err != nil {
			t.Fatal(err)
		}
		if selected.ImportPath == fixtureModule+"/auxfixture" {
			if selected.Standard || !reflect.DeepEqual(selected.SFiles, []string{"entry.s"}) {
				t.Fatal("first-party binary format fixture acquired SDK source identity")
			}
			archive = data
		} else {
			if !selected.Standard {
				t.Fatal("actual metadata dependency is not this SDK", selected.ImportPath)
			}
			referenced[selected.ImportPath] = SDKReferencedArchive{selected.ImportPath, selected.SFiles, data}
		}
	}
	if archive == nil || referenced["sync/atomic"].Archive == nil {
		t.Fatal("actual SDK dependency/export route is incomplete")
	}
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(compiler)), "src", "cmd", "internal", "goobj", "builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	retainTextArtifact(t, "linux/"+arch, "indexed-aux", map[string][]byte{
		"original.a": archive, "atomic-original.a": referenced["sync/atomic"].Archive,
		"graph.json": raw, "source-value.go": []byte(goSource), "source-entry.s": []byte(assembly),
	})
	return archive, builtin, referenced
}

func TestGoSDKAssemblyActualAuxOnlyIndexedReference(t *testing.T) {
	_, compiler, _ := fixture(t)
	oracle := officialReaderForSource(t, compiler, sdkIndexedAuxReaderSource)
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			archive, builtin, referenced := indexedForeignArchiveFixture(t, arch)
			directory := t.TempDir()
			for name, data := range map[string][]byte{"original.a": archive, "atomic-original.a": referenced["sync/atomic"].Archive} {
				if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			raw := run(t, oracle, directory, fixtureEnv(t, "linux/"+arch),
				filepath.Join(directory, "original.a"), filepath.Join(directory, "atomic-original.a"))
			var original []indexedAuxOracleReference
			if err := json.Unmarshal(raw, &original); err != nil || len(original) == 0 {
				t.Fatal("independent actual indexed auxiliary references are missing", err)
			}
			retainTextArtifact(t, "linux/"+arch, "indexed-aux", map[string][]byte{"aux-sdk.json": raw})

			observed, err := ObserveX86SDKAssemblyArchiveReferences(archive, builtin, "linux/"+arch, []string{"entry.s"}, referenced)
			if err != nil || len(observed) != 3 {
				t.Fatal("actual Aux-only indexed type reference was rejected despite its complete SDK export object", err)
			}
			targets, err := sdkReferencedArchiveSymbols(referenced, "linux/"+arch)
			if err != nil {
				t.Fatal(err)
			}
			members, err := archiveMembers(archive)
			if err != nil {
				t.Fatal(err)
			}
			body, err := objectBody(members[1].data, "linux/"+arch)
			if err != nil {
				t.Fatal(err)
			}
			object, err := checkedObject(body, 16, false)
			if err != nil {
				t.Fatal(err)
			}
			auxOnly := 0
			for _, expected := range original {
				ordinal := object.indices[1][expected.OwnerIndex] + expected.AuxiliaryIndex
				raw := object.block(15)[int(ordinal)*9 : int(ordinal+1)*9]
				ref := TextReference{PackageIndex: binary.LittleEndian.Uint32(raw[1:]), SymbolIndex: binary.LittleEndian.Uint32(raw[5:])}
				ref.Package, err = object.stringAt(object.block(1)[int(ref.PackageIndex)*8 : int(ref.PackageIndex+1)*8])
				if err != nil || raw[0] != expected.Type || ref.PackageIndex != expected.PackageIndex ||
					ref.SymbolIndex != expected.SymbolIndex || ref.Package != expected.Package {
					t.Fatal("actual complete original Aux/index route differs from the independent SDK", err)
				}
				ref, err = resolveSDKIndexedReference(ref, expected.Name, expected.DiagnosticPresent, targets)
				if err != nil || ref.Name != expected.Name || ref.ABI != expected.ABI || ref.Kind != expected.Kind ||
					!ref.ABIKnown || !ref.KindKnown {
					t.Fatal("actual referenced compiler SymbolDefs differs from the independent SDK", ref, expected, err)
				}
				if !expected.DiagnosticPresent && expected.Type == 0 && expected.Name == "type:sync/atomic.Bool" {
					auxOnly++
				}
			}
			if auxOnly == 0 {
				t.Fatal("first-party fixture did not independently reproduce the AuxGotype-only reference")
			}
			if _, err := ObserveX86SDKAssemblyArchive(archive, builtin, "linux/"+arch, []string{"entry.s"}); err == nil {
				t.Fatal("SDK observer guessed an unresolved indexed type without actual referenced bytes")
			}
			if _, err := ObserveX86AssemblyArchive(archive, builtin, "linux/"+arch, []string{"entry.s"}); err == nil {
				t.Fatal("default owned observer inherited SDK referenced-object permissions")
			}
		})
	}
}
