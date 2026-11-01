//go:build go1.27

package gostaticstorage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// This independent reader enumerates the official four definition namespaces
// and the separate NonPkgRefs block. It does not use plan9asm's object reader.
const sdkNamespaceReaderSource = `package main

import (
	"cmd/internal/archive"
	"cmd/internal/goobj"
	"encoding/json"
	"fmt"
	"os"
)

type Definition struct {
	Namespace int
	Relative, Index uint32
	Name string
	ABI uint16
	Kind, Flags, Flags2 uint8
	Size, Align uint32
	Hash []byte
}
type Member struct {
	Name string
	NameBytes []byte
	Offset, Size int64
	Flags uint32
	Counts [5]int
	Definitions []Definition
}

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil { panic(err) }
	defer f.Close()
	a, err := archive.Parse(f, false)
	if err != nil { panic(err) }
	var members []Member
	for _, entry := range a.Entries {
		member := Member{Name: entry.Name, NameBytes: []byte(entry.Name), Offset: entry.Offset, Size: entry.Size}
		if entry.Type != archive.EntryPkgDef && entry.Type != archive.EntryGoObj {
			panic("unexpected original archive member")
		}
		if entry.Type == archive.EntryGoObj {
			data := make([]byte, entry.Obj.Size)
			n, err := f.ReadAt(data, entry.Obj.Offset)
			if err != nil || n != len(data) { panic(fmt.Sprint(n, err)) }
			r := goobj.NewReaderFromBytes(data, false)
			if r == nil { panic("invalid original goobj") }
			member.Flags = r.Flags()
			member.Counts = [5]int{r.NSym(), r.NHashed64def(), r.NHasheddef(), r.NNonpkgdef(), r.NNonpkgref()}
			var index uint32
			for namespace, count := range member.Counts {
				for relative := 0; relative < count; relative++ {
					s := r.Sym(index)
					definition := Definition{Namespace: namespace, Relative: uint32(relative), Index: index,
						Name: s.Name(r), ABI: s.ABI(), Kind: s.Type(), Flags: s.Flag(), Flags2: s.Flag2(), Size: s.Siz(), Align: s.Align()}
					if namespace == 1 {
						hash := r.Hash64(uint32(relative))
						definition.Hash = make([]byte, 8)
						for byteIndex := range definition.Hash { definition.Hash[byteIndex] = byte(hash >> (8 * byteIndex)) }
					}
					if namespace == 2 { definition.Hash = append([]byte(nil), r.Hash(uint32(relative))[:]...) }
					member.Definitions = append(member.Definitions, definition)
					index++
				}
			}
		}
		members = append(members, member)
	}
	if err := json.NewEncoder(os.Stdout).Encode(members); err != nil { panic(err) }
}
`

type namespaceOracleDefinition struct {
	Namespace           int
	Relative, Index     uint32
	Name                string
	ABI                 uint16
	Kind, Flags, Flags2 uint8
	Size, Align         uint32
	Hash                []byte
}

type namespaceOracleMember struct {
	Name         string
	NameBytes    []byte
	Offset, Size int64
	Flags        uint32
	Counts       [5]int
	Definitions  []namespaceOracleDefinition
}

func TestGoSDKAssemblyIndexedOnceFuncFirstParty(t *testing.T) {
	directory, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkNamespaceReaderSource)
	textOracle := officialReaderForSource(t, binary, sdkTextReaderSource)
	consumer := filepath.Join(directory, "namespacefixture")
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	goSource := `package namespacefixture

import "sync"

var Counter byte
var First = sync.OnceFunc(func() { Counter++ })
var Second = sync.OnceFunc(func() { Counter += 2 })

func Read() byte
`
	assembly := "#include \"textflag.h\"\nTEXT ·Read(SB),NOSPLIT,$0-1\nMOVB ·Counter(SB),AL\nMOVB AL,ret+0(FP)\nRET\n"
	for name, data := range map[string]string{"value.go": goSource, "read.s": assembly} {
		if err := os.WriteFile(filepath.Join(consumer, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(binary)), "src", "cmd", "internal", "goobj", "builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			target := "linux/" + arch
			env := fixtureEnv(t, target)
			// The flags reproduce the SDK binary format, not SDK source identity.
			// The actual first-party package remains Standard=false.
			selection := run(t, binary, consumer, env, "list", "-json", "-compiled", "-export", "-mod=readonly",
				"-gcflags=-std", "-asmflags=-std", ".")
			var selected struct {
				Export   string
				SFiles   []string
				Standard bool
			}
			if err := json.Unmarshal(selection, &selected); err != nil || selected.Standard ||
				selected.Export == "" || !reflect.DeepEqual(selected.SFiles, []string{"read.s"}) {
				t.Fatal("actual first-party selection/role differs", err)
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			raw := run(t, oracle, consumer, env, selected.Export)
			textRaw := run(t, textOracle, consumer, env, selected.Export)
			var original []namespaceOracleMember
			var originalTexts []TextMember
			if err := json.Unmarshal(raw, &original); err != nil || len(original) != 3 {
				t.Fatal("actual namespace/hash oracle inventory differs", err)
			}
			if err := json.Unmarshal(textRaw, &originalTexts); err != nil || len(originalTexts) != len(original) {
				t.Fatal("actual whole TEXT oracle inventory differs", err)
			}
			members, err := archiveMembers(archive)
			if err != nil {
				t.Fatal(err)
			}
			for memberIndex, member := range members[1:] {
				body, err := objectBody(member.data, target)
				if err != nil {
					t.Fatal(err)
				}
				object, err := checkedObject(body, original[memberIndex+1].Flags, memberIndex != 0)
				if err != nil {
					t.Fatal(err)
				}
				symbols, err := object.indexedSymbols()
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(symbols)
				if err != nil {
					t.Fatal(err)
				}
				var observed []namespaceOracleDefinition
				if err := json.Unmarshal(encoded, &observed); err != nil || !reflect.DeepEqual(observed, original[memberIndex+1].Definitions) {
					t.Fatal("all original namespace/index/hash/flag records differ from the independent SDK", err)
				}
			}
			for namespace, count := range original[1].Counts {
				if count == 0 {
					t.Fatal("first-party original lacks a required namespace boundary", namespace)
				}
			}
			groups := make(map[string][]namespaceOracleDefinition)
			for _, definition := range original[1].Definitions {
				if definition.Namespace == 2 && definition.Kind == 1 && strings.HasPrefix(definition.Name, "sync.OnceFunc.func1") {
					groups[definition.Name] = append(groups[definition.Name], definition)
				}
			}
			duplicateGroups := 0
			for name, definitions := range groups {
				if len(definitions) < 2 {
					continue
				}
				duplicateGroups++
				for _, definition := range definitions {
					if definition.Flags != 0 || definition.Flags2 != 0 || definition.ABI != 1 || len(definition.Hash) != 16 {
						t.Fatal("actual repeated inline closure namespace/hash facts differ", definition)
					}
				}
				t.Logf("ACTUAL_HASHED_INLINE target=%s name=%s records=%d", target, name, len(definitions))
			}
			if duplicateGroups == 0 {
				t.Fatal("first-party source did not reproduce actual duplicate indexed TEXT")
			}
			retainTextArtifact(t, target, "indexed-oncefunc", map[string][]byte{
				"original.a": archive, "source-value.go": []byte(goSource), "source-read.s": []byte(assembly),
				"selection.json": selection, "namespace-sdk.json": raw, "text-sdk.json": textRaw,
			})
			observed, err := ObserveX86SDKAssemblyArchive(archive, builtin, target, selected.SFiles)
			if err != nil || !reflect.DeepEqual(observed, originalTexts) {
				t.Fatal("SDK-only indexed observation rejected legal first-party namespace or lost whole TEXT", err)
			}
			if _, err := ObserveX86AssemblyArchive(archive, builtin, target, selected.SFiles); err == nil {
				t.Fatal("ordinary owned observer acquired SDK binary flags/namespace permission")
			}
		})
	}
}
