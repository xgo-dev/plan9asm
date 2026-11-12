//go:build go1.27

package gostaticstorage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sdkIndexedCountsReaderSource = `package main

import (
	"cmd/internal/archive"
	"cmd/internal/goobj"
	"encoding/json"
	"fmt"
	"os"
)

type Member struct {
	Name string
	Offset, Size int64
	Flags uint32
	Counts [5]int
}

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	a, err := archive.Parse(f, false)
	if err != nil {
		panic(err)
	}
	var result []Member
	for _, entry := range a.Entries {
		member := Member{Name: entry.Name, Offset: entry.Offset, Size: entry.Size}
		if entry.Type == archive.EntryGoObj {
			data := make([]byte, entry.Obj.Size)
			n, err := f.ReadAt(data, entry.Obj.Offset)
			if err != nil || n != len(data) {
				panic(fmt.Sprint(n, err))
			}
			r := goobj.NewReaderFromBytes(data, false)
			if r == nil {
				panic("invalid original compiler object")
			}
			member.Flags = r.Flags()
			member.Counts = [5]int{r.NSym(), r.NHashed64def(), r.NHasheddef(), r.NNonpkgdef(), r.NNonpkgref()}
		}
		result = append(result, member)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
`

func TestGoSDKReferencedLargeHashedMetadataFirstParty(t *testing.T) {
	directory, compiler, _ := fixture(t)
	oracle := officialReaderForSource(t, compiler, sdkIndexedCountsReaderSource)
	consumer := filepath.Join(directory, "largehashed")
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	source.WriteString("package largehashed\nvar Values = []string{\n")
	for index := 0; index < symbolLimit+16; index++ {
		fmt.Fprintf(&source, "%q,\n", fmt.Sprintf("unique-%06d", index))
	}
	source.WriteString("}\n")
	if err := os.WriteFile(filepath.Join(consumer, "value.go"), []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			target := "linux/" + arch
			env := fixtureEnv(t, target)
			raw := run(t, compiler, consumer, env, "list", "-json", "-compiled", "-export", "-mod=readonly", "-gcflags=-std", ".")
			var selected struct {
				Export   string
				Standard bool
			}
			if err := json.Unmarshal(raw, &selected); err != nil || selected.Standard || selected.Export == "" {
				t.Fatal("actual first-party large hashed source role differs", err)
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			countsRaw := run(t, oracle, consumer, env, selected.Export)
			var counts []namespaceOracleMember
			if err := json.Unmarshal(countsRaw, &counts); err != nil || len(counts) != 2 ||
				counts[1].Flags != 16 || counts[1].Counts[0] > symbolLimit || counts[1].Counts[2] <= symbolLimit {
				t.Fatal("official large hashed/SymbolDefs counts differ", counts, err)
			}
			retainTextArtifact(t, target, "indexed-large-hashed", map[string][]byte{
				"original.a": archive, "counts-sdk.json": countsRaw, "selection.json": raw, "source-value.go": []byte(source.String()),
			})
			observed, err := sdkReferencedArchiveSymbols(map[string]SDKReferencedArchive{
				fixtureModule + "/largehashed": {PackagePath: fixtureModule + "/largehashed", Archive: archive},
			}, target)
			if err != nil || len(observed[fixtureModule+"/largehashed"]) != counts[1].Counts[0] {
				t.Fatal("SDK referenced-only metadata allocated/rejected unrelated hashed bodies", err)
			}
			members, err := archiveMembers(archive)
			if err != nil {
				t.Fatal(err)
			}
			body, err := objectBody(members[1].data, target)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := checkedObject(body, 16, false); !errors.Is(err, ErrContext) {
				t.Fatal("metadata-only role enlarged complete TEXT/body budget", err)
			}
		})
	}
}

func TestGoSDKReferencedActualRuntimeNamespaceCounts(t *testing.T) {
	directory, compiler, _ := fixture(t)
	oracle := officialReaderForSource(t, compiler, sdkIndexedCountsReaderSource)
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			env := fixtureEnv(t, "linux/"+arch)
			raw := run(t, compiler, directory, env, "list", "-json", "-compiled", "-export", "-mod=readonly", "runtime")
			var selected struct {
				ImportPath, Export string
				SFiles             []string
				Standard           bool
			}
			if err := json.Unmarshal(raw, &selected); err != nil || !selected.Standard || selected.ImportPath != "runtime" || selected.Export == "" {
				t.Fatal("actual SDK runtime export/source role differs", err)
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			countsRaw := run(t, oracle, directory, env, selected.Export)
			var counts []namespaceOracleMember
			if err := json.Unmarshal(countsRaw, &counts); err != nil || len(counts) != len(selected.SFiles)+2 || counts[1].Flags != 16 {
				t.Fatal("official actual runtime member/namespace counts differ", err)
			}
			retainTextArtifact(t, "linux/"+arch, "indexed-runtime", map[string][]byte{
				"original.a": archive, "counts-sdk.json": countsRaw, "selection.json": raw,
			})
			t.Logf("ACTUAL_SDK_RUNTIME_COUNTS %s compiler=%v archive_bytes=%d", arch, counts[1].Counts, len(archive))
		})
	}
}
