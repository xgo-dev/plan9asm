//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func sdkFIPSOracleSymbol(value namespaceOracleDefinition) indexedObjectSymbol {
	return indexedObjectSymbol{Namespace: TextSymbolNamespace(value.Namespace), Relative: value.Relative,
		Index: value.Index, Name: value.Name, ABI: value.ABI, Kind: value.Kind,
		Flags: value.Flags, Flags2: value.Flags2, Size: value.Size, Align: value.Align,
		Hash: append([]byte(nil), value.Hash...)}
}

func TestGoSDKFIPSTextKindOriginalArchive(t *testing.T) {
	directory, driver, _ := fixture(t)
	oracle := officialReaderForSource(t, driver, sdkNamespaceReaderSource)
	root := filepath.Dir(filepath.Dir(driver))
	role := "src/cmd/internal/objabi/symkind.go"
	kinds, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(role)))
	if err != nil || digest(kinds) != formatSources[role] ||
		!bytes.Contains(kinds, []byte("return t == STEXT || t == STEXTFIPS")) {
		t.Fatal("actual current SDK SymKind schema differs from its independently pinned source", err)
	}
	builtin, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(builtinSourceRole)))
	if err != nil {
		t.Fatal(err)
	}
	const path = "crypto/internal/fips140/bigmod"
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			target := "linux/" + arch
			env := fixtureEnv(t, target)
			selection := run(t, driver, directory, env, "list", "-json", "-compiled", "-export", path)
			var selected struct {
				ImportPath, Dir, Root, Export string
				Standard, Goroot              bool
				SFiles                        []string
			}
			if err := json.Unmarshal(selection, &selected); err != nil || selected.ImportPath != path ||
				!selected.Standard || !selected.Goroot || selected.Root != root ||
				selected.Dir != filepath.Join(root, "src", filepath.FromSlash(path)) ||
				!reflect.DeepEqual(selected.SFiles, []string{"nat_" + arch + ".s"}) || selected.Export == "" {
				t.Fatal("actual stock FIPS package/source/archive prior differs", err)
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			assembly, err := os.ReadFile(filepath.Join(selected.Dir, selected.SFiles[0]))
			if err != nil {
				t.Fatal(err)
			}
			raw := run(t, oracle, directory, env, selected.Export)
			var actual []namespaceOracleMember
			if err := json.Unmarshal(raw, &actual); err != nil || len(actual) != len(selected.SFiles)+2 {
				t.Fatal("independent actual Go archive prior is incomplete", err)
			}
			members, err := archiveMembers(archive)
			if err != nil || len(members) != len(actual) {
				t.Fatal("whole original FIPS archive member prior differs", err)
			}
			observed := make([]ASMDataMember, len(members)-1)
			indexed := make([][]indexedObjectSymbol, len(observed))
			groups := make(map[string][]indexedObjectSymbol)
			for ordinal, member := range members {
				prior := actual[ordinal]
				if prior.Name != member.name || !bytes.Equal(prior.NameBytes, []byte(member.name)) ||
					prior.Offset != member.offset || prior.Size != int64(len(member.data)) {
					t.Fatal("original archive member/name-byte/extent identity differs", ordinal)
				}
				if ordinal == 0 {
					continue
				}
				flags := sdkCompilerObjectFlags(target)
				if ordinal != 1 {
					flags |= 4
				}
				if prior.Flags != flags {
					t.Fatal("actual compiler/assembler member flags differ from the current producer role", ordinal, prior.Flags)
				}
				reader := sdkObjectBody
				if ordinal != 1 {
					reader = objectBody
				}
				body, err := reader(member.data, target)
				if err != nil {
					t.Fatal(err)
				}
				object, err := checkedObject(body, prior.Flags, ordinal != 1)
				if err != nil {
					t.Fatal("original complete object precondition", err)
				}
				symbols, err := object.indexedSymbols()
				if err != nil || len(symbols) != len(prior.Definitions) {
					t.Fatal("original complete namespace inventory differs", err)
				}
				value := &observed[ordinal-1]
				value.Name, value.Ordinal, value.Flags = member.name, ordinal, prior.Flags
				for index, symbol := range symbols {
					if !reflect.DeepEqual(symbol, sdkFIPSOracleSymbol(prior.Definitions[index])) {
						t.Fatal("actual raw kind/ABI/namespace/index/hash/flags identity differs", ordinal, index)
					}
					if symbol.Namespace == TextSymbolNonpkgReference {
						continue
					}
					groups[symbol.Name] = append(groups[symbol.Name], symbol)
					// Use the independently observed current enum here, not a
					// production classifier or a FIPS package/name heuristic.
					if symbol.Kind == 1 || symbol.Kind == 2 {
						value.Texts = append(value.Texts, TextRecord{Name: symbol.Name, ABI: symbol.ABI,
							Kind: symbol.Kind, Namespace: symbol.Namespace, Index: symbol.Index,
							Relative: symbol.Relative, Flags: symbol.Flags, Flags2: symbol.Flags2,
							Size: int64(symbol.Size), Hash: append([]byte(nil), symbol.Hash...)})
					} else {
						value.Definitions = append(value.Definitions, ASMDataDefinition{Name: symbol.Name,
							ABI: symbol.ABI, Kind: symbol.Kind, Namespace: symbol.Namespace,
							Index: symbol.Index, Relative: symbol.Relative, Flags: symbol.Flags,
							Flags2: symbol.Flags2, Size: symbol.Size, Align: symbol.Align,
							Hash: append([]byte(nil), symbol.Hash...)})
					}
				}
				indexed[ordinal-1] = symbols
			}
			for _, name := range []string{"addMulVVW1024", "addMulVVW1536", "addMulVVW2048"} {
				entries := groups[path+"."+name]
				want := 1 // 386 has no register-ABI wrapper; do not invent ABI1 there.
				if arch == "amd64" {
					want = 2
				}
				seen := make(map[uint16]bool)
				for _, entry := range entries {
					if entry.Kind != 2 || entry.Size == 0 || entry.ABI > 1 || seen[entry.ABI] {
						t.Fatal("actual FIPS code prior is not distinct nonempty STEXTFIPS entries", name, entries)
					}
					seen[entry.ABI] = true
				}
				if len(entries) != want || !seen[0] || arch == "amd64" && !seen[1] {
					t.Fatal("actual original assembly/compiler ABI inventory differs", name, entries)
				}
			}
			storage := groups[path+".supportADX"]
			if len(storage) != 1 || storage[0].ABI != 0 || storage[0].Kind == 1 || storage[0].Kind == 2 {
				t.Fatal("the actual bool global, unlike the code, does not have multiple ABI identities", storage)
			}
			retainTextArtifact(t, target, "fips-text-kind", map[string][]byte{
				"original.a": archive, "selection.json": selection, "namespace-sdk.json": raw,
				"symkind.go": kinds, "source-" + selected.SFiles[0]: assembly,
			})
			t.Logf("ACTUAL_FIPS_ARCHIVE target=%s members=%d archiveSHA256=%s entries=3 wrapperABI=%t",
				target, len(members), digest(archive), arch == "amd64")
			t.Run("archive-classification", func(t *testing.T) {
				if err := validateASMDataArchiveNames(observed); err != nil {
					t.Fatal("actual FIPS code was classified as ambiguous storage", err)
				}
			})
			t.Run("named-classification", func(t *testing.T) {
				definitions := make(sdkAssemblyNamedDefinitions)
				for member, symbols := range indexed {
					for _, symbol := range symbols {
						if err := definitions.observe(symbol, member != 0); err != nil {
							t.Fatal("complete actual SDK text identities lost their original role", symbol.Name, err)
						}
					}
				}
			})
			t.Run("no-raw-owned-or-forged-role", func(t *testing.T) {
				if _, err := ObserveX86AssemblyArchive(archive, builtin, target, selected.SFiles); !errors.Is(err, ErrContext) {
					t.Fatal("FIPS classification granted an ordinary owned archive role", err)
				}
				if _, err := ObserveX86AssemblyText(members[2].data, builtin, target); !errors.Is(err, ErrContext) {
					t.Fatal("FIPS classification granted an ordinary standalone raw object role", err)
				}
				body, err := objectBody(members[2].data, target)
				if err != nil {
					t.Fatal(err)
				}
				for _, mutate := range []func([]byte){
					func(data []byte) { data[0] ^= 1 },
					func(data []byte) {
						start := binary.LittleEndian.Uint32(data[20+4*6:])
						data[start+10] = 26
					},
					func(data []byte) {
						end := binary.LittleEndian.Uint32(data[20+4*7:])
						binary.LittleEndian.PutUint32(data[20+4*7:], end-1)
					},
				} {
					changed := append([]byte(nil), body...)
					mutate(changed)
					if _, err := checkedObject(changed, actual[2].Flags, false); !errors.Is(err, ErrContext) {
						t.Fatal("raw magic/kind/namespace mutation acquired the current text observation role", err)
					}
				}
			})
		})
	}
}
