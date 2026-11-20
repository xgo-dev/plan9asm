//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is an offline full-body parse of actual SDK compiler output, not an
// SDK/frame/source certificate. All referenced archives keep their separate
// metadata-only role; the selected compiler member retains full TEXT/DATA.
func TestGoSDKRuntimeFullCompilerBody(t *testing.T) {
	directory, compiler, _ := fixture(t)
	// Keep the original SDK oracle output bounded: it visits every original
	// definition and payload, returning counts rather than megabytes of JSON
	// names. Existing small-fixture tests compare individual complete records.
	oracleSource := strings.Replace(sdkIndexedCountsReaderSource, "Counts [5]int", "Counts [5]int\nDataBytes, Relocations, AuxRecords int\nKinds, AuxKinds map[uint8]int", 1)
	oracleSource = strings.Replace(oracleSource, "result = append(result, member)", `
		if entry.Type == archive.EntryGoObj {
			data := make([]byte, entry.Obj.Size)
			if _, err := f.ReadAt(data, entry.Obj.Offset); err != nil { panic(err) }
			r := goobj.NewReaderFromBytes(data, false)
			member.Kinds = make(map[uint8]int)
			member.AuxKinds = make(map[uint8]int)
			for i := 0; i < r.NSym()+r.NHashed64def()+r.NHasheddef()+r.NNonpkgdef(); i++ {
				member.DataBytes += len(r.Data(uint32(i)))
				member.Relocations += r.NReloc(uint32(i))
				member.Kinds[r.Sym(uint32(i)).Type()]++
				for j := 0; j < r.NAux(uint32(i)); j++ {
					member.AuxRecords++
					member.AuxKinds[r.Aux(uint32(i), j).Type()]++
				}
			}
		}
		result = append(result, member)`, 1)
	oracle := officialReaderForSource(t, compiler, oracleSource)
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(compiler)), "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			target := "linux/" + arch
			env := fixtureEnv(t, target)
			raw := run(t, compiler, directory, env, "list", "-deps", "-json", "-compiled", "-export", "-mod=readonly", "runtime")
			decoder := json.NewDecoder(bytes.NewReader(raw))
			referenced := make(map[string]SDKReferencedArchive)
			var archive []byte
			for {
				var selected struct {
					ImportPath, Export string
					SFiles             []string
				}
				if err := decoder.Decode(&selected); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if selected.ImportPath == "unsafe" {
					continue
				}
				data, err := os.ReadFile(selected.Export)
				if err != nil {
					t.Fatal(err)
				}
				if selected.ImportPath == "runtime" {
					archive = data
				} else {
					referenced[selected.ImportPath] = SDKReferencedArchive{PackagePath: selected.ImportPath, Sources: selected.SFiles, Archive: data}
				}
			}
			if len(archive) == 0 {
				t.Fatal("actual SDK runtime compiler archive was not selected")
			}
			members, err := archiveMembers(archive)
			if err != nil || len(members) < 2 || members[1].name != "_go_.o" {
				t.Fatal("actual compiler member inventory", err)
			}
			filename := filepath.Join(t.TempDir(), "runtime.a")
			if err := os.WriteFile(filename, archive, 0600); err != nil {
				t.Fatal(err)
			}
			var expected []struct {
				Name                               string
				Counts                             [5]int
				DataBytes, Relocations, AuxRecords int
				Kinds, AuxKinds                    map[uint8]int
			}
			if err := json.Unmarshal(run(t, oracle, directory, env, filename), &expected); err != nil || len(expected) != len(members) {
				t.Fatal("original SDK full definition oracle", err)
			}
			symbols, err := sdkReferencedArchiveSymbols(referenced, target)
			if err != nil {
				t.Fatal("actual complete referenced namespaces", err)
			}
			member, err := observeASMDataObject(members[1].data, builtin, target, sdkCompilerObjectFlags(target), symbols)
			if err != nil {
				t.Fatal("actual SDK compiler full TEXT/DATA/reloc body rejected", err)
			}
			want := expected[1]
			// Read Aux through the checked full-body structure and its N+1
			// indexes, without inventing a public DATA/Aux observation role.
			body, err := sdkObjectBody(members[1].data, target)
			if err != nil {
				t.Fatal(err)
			}
			object, err := checkedSDKObject(body, sdkCompilerObjectFlags(target), false)
			if err != nil {
				t.Fatal("actual SDK Aux structure was not completely checked", err)
			}
			auxBlock := object.block(15)
			auxRecords := 0
			auxKinds := make(map[uint8]int)
			for index := 0; index < object.count; index++ {
				start, end := object.indices[1][index], object.indices[1][index+1]
				for ordinal := start; ordinal < end; ordinal++ {
					auxRecords++
					auxKinds[auxBlock[int(ordinal)*9]]++
				}
			}
			if auxRecords != want.AuxRecords || len(auxKinds) != len(want.AuxKinds) {
				t.Fatal("complete compiler Aux inventory differs from original SDK reader", auxRecords, auxKinds, want)
			}
			for kind, count := range want.AuxKinds {
				if auxKinds[kind] != count {
					t.Fatal("compiler Aux kind inventory differs", kind, count, auxKinds[kind])
				}
			}
			count := want.Counts[0] + want.Counts[1] + want.Counts[2] + want.Counts[3]
			if len(member.Texts)+len(member.Definitions) != count {
				t.Fatal("full compiler body discarded definitions", len(member.Texts), len(member.Definitions), count)
			}
			seen := make([]bool, count)
			kinds := make(map[uint8]int)
			bytes, relocations := 0, 0
			check := func(index uint32, kind uint8, size, relocs int) {
				if int(index) >= count || seen[index] {
					t.Fatal("compiler definition index escaped/duplicated actual original inventory", index)
				}
				seen[index] = true
				kinds[kind]++
				bytes += size
				relocations += relocs
			}
			for _, text := range member.Texts {
				check(text.Index, text.Kind, len(text.Code), len(text.Relocations))
			}
			for _, data := range member.Definitions {
				check(data.Index, data.Kind, len(data.Data), len(data.Relocations))
			}
			if bytes != want.DataBytes || relocations != want.Relocations || len(kinds) != len(want.Kinds) {
				t.Fatal("full compiler payload differs from independent SDK reader", bytes, relocations, want)
			}
			for kind, count := range want.Kinds {
				if kinds[kind] != count {
					t.Fatal("compiler full-body symbol kind inventory differs", kind, count, kinds[kind])
				}
			}
		})
	}
}
