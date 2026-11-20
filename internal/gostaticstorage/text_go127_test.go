//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func retainTextArtifact(t *testing.T, target, role string, files map[string][]byte) {
	t.Helper()
	if artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); artifact != "" {
		folder := filepath.Join(artifact, strings.ReplaceAll(target, "/", "-"), role)
		if err := os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(folder, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// This reader uses the selected SDK's binary readers and PCToLine. It does not
// call the production parser or derive a source read/native-entry permission.
const sdkTextReaderSource = `package main

import (
	"cmd/internal/archive"
	"cmd/internal/goobj"
	"cmd/internal/objfile"
	"encoding/json"
	"fmt"
	"os"
)

type Ref struct {
	PackageIndex, SymbolIndex uint32
	Package, Name             string
	ABI                       uint16
	ABIKnown                  bool
	// This reader observes the existing default TEXT role, which does not
	// admit referenced-archive kind metadata. Keep that provenance explicit.
	Kind                      uint8
	KindKnown                 bool
}
type Reloc struct {
	Offset, Size int64
	Type         uint16
	Add          int64
	Target       Ref
}
type Aux struct {
	Type   uint8
	Target Ref
}
type Position struct {
	Start, End int64
	File       string
	Line       int32
}
type Text struct {
	Index         uint32
	Namespace     uint8
	Relative      uint32
	Hash          []byte
	Name          string
	ABI           uint16
	Kind          uint8
	Flags, Flags2 uint8
	Size          int64
	Code          []byte
	Relocations   []Reloc
	Auxiliary     []Aux
	PCFile, PCLine []byte
	Positions     []Position
}
type Member struct {
	Name         string
	Offset, Size int64
	Flags        uint32
	Texts        []Text
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
	o, err := objfile.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer o.Close()
	entries := map[string]*objfile.Entry{}
	for _, e := range o.Entries() {
		if entries[e.Name()] != nil {
			panic("duplicate entry")
		}
		entries[e.Name()] = e
	}
	result := []Member{}
	for _, e := range a.Entries {
		m := Member{Name: e.Name, Offset: e.Offset, Size: e.Size}
		if e.Type != archive.EntryPkgDef && e.Type != archive.EntryGoObj {
			panic("unknown member")
		}
		if e.Type == archive.EntryGoObj {
			data := make([]byte, e.Obj.Size)
			n, err := f.ReadAt(data, e.Obj.Offset)
			if err != nil || n != len(data) {
				panic(fmt.Sprint(n, err))
			}
			r := goobj.NewReaderFromBytes(data, false)
			if r == nil {
				panic("goobj")
			}
			m.Flags = r.Flags()
			refs := map[goobj.SymRef]string{}
			for i := 0; i < r.NRefName(); i++ {
				q := r.RefName(i)
				refs[q.Sym()] = q.Name(r)
			}
			resolve := func(q goobj.SymRef) Ref {
				v := Ref{PackageIndex: q.PkgIdx, SymbolIndex: q.SymIdx}
				var index uint32
				switch q.PkgIdx {
				case goobj.PkgIdxInvalid:
					return v
				case goobj.PkgIdxSelf:
					index = q.SymIdx
				case goobj.PkgIdxHashed64:
					index = q.SymIdx + uint32(r.NSym())
				case goobj.PkgIdxHashed:
					index = q.SymIdx + uint32(r.NSym()+r.NHashed64def())
				case goobj.PkgIdxNone:
					index = q.SymIdx + uint32(r.NSym()+r.NHashed64def()+r.NHasheddef())
				case goobj.PkgIdxBuiltin:
					name, abi := goobj.BuiltinName(int(q.SymIdx))
					v.Name = name
					v.ABI = uint16(abi)
					v.ABIKnown = true
					return v
				default:
					v.Package = r.Pkg(int(q.PkgIdx))
					v.Name = refs[q]
					return v
				}
				s := r.Sym(index)
				v.Name = s.Name(r)
				v.ABI = s.ABI()
				v.ABIKnown = true
				return v
			}
			entry := entries[e.Name]
			if entry == nil {
				panic("missing objfile entry")
			}
			liner, err := entry.PCLineTable()
			if err != nil {
				panic(err)
			}
			count := r.NSym() + r.NHashed64def() + r.NHasheddef() + r.NNonpkgdef()
			for i := 0; i < count; i++ {
				s := r.Sym(uint32(i))
				if s.Type() != 1 && s.Type() != 2 {
					continue
				}
				v := Text{Index: uint32(i), Name: s.Name(r), ABI: s.ABI(), Kind: s.Type(), Flags: s.Flag(), Flags2: s.Flag2(), Size: int64(s.Siz()), Code: r.Data(uint32(i))}
				start := 0
				for namespace, count := range []int{r.NSym(), r.NHashed64def(), r.NHasheddef(), r.NNonpkgdef()} {
					if i < start + count {
						v.Namespace = uint8(namespace)
						v.Relative = uint32(i - start)
						break
					}
					start += count
				}
				if v.Namespace == 1 {
					hash := r.Hash64(v.Relative)
					v.Hash = make([]byte, 8)
					for index := range v.Hash {
						v.Hash[index] = byte(hash >> (8 * index))
					}
				}
				if v.Namespace == 2 {
					v.Hash = append([]byte(nil), r.Hash(v.Relative)[:]...)
				}
				for j := 0; j < r.NReloc(uint32(i)); j++ {
					q := r.Reloc(uint32(i), j)
					v.Relocations = append(v.Relocations, Reloc{int64(q.Off()), int64(q.Siz()), q.Type(), q.Add(), resolve(q.Sym())})
				}
				for j := 0; j < r.NAux(uint32(i)); j++ {
					q := r.Aux(uint32(i), j)
					v.Auxiliary = append(v.Auxiliary, Aux{q.Type(), resolve(q.Sym())})
					if q.Type() == goobj.AuxPcfile || q.Type() == goobj.AuxPcline {
						ref := q.Sym()
						if ref.PkgIdx != goobj.PkgIdxHashed {
							panic("unexpected original PC data role")
						}
						data := r.Data(ref.SymIdx + uint32(r.NSym()+r.NHashed64def()))
						if q.Type() == goobj.AuxPcfile {
							v.PCFile = data
						} else {
							v.PCLine = data
						}
					}
				}
				for pc := int64(0); pc < int64(s.Siz()); pc++ {
					file, line, _ := liner.PCToLine(uint64(r.DataOff(uint32(i))) + uint64(pc))
					k := len(v.Positions) - 1
					if k >= 0 && v.Positions[k].File == file && v.Positions[k].Line == int32(line) {
						v.Positions[k].End = pc + 1
					} else {
						v.Positions = append(v.Positions, Position{pc, pc + 1, file, int32(line)})
					}
				}
				m.Texts = append(m.Texts, v)
			}
		}
		result = append(result, m)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
`

func TestGoStaticStorageTEXTActualSourceReport(t *testing.T) {
	dir, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkTextReaderSource)
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			_, report := captured(t, request(t, dir, binary, target))
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &envelope); err != nil {
				t.Fatal(err)
			}
			var recorded map[string]json.RawMessage
			if err := json.Unmarshal(envelope["TextArchives"], &recorded); err != nil {
				// Keep observing the real original object before reporting RED.
				recorded = nil
			}
			packages, err := reportPackages(report, dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{fixtureModule, fixtureModule + "/dep"} {
				raw := run(t, oracle, dir, fixtureEnv(t, target), packages[path].Export)
				var original []map[string]json.RawMessage
				if err := json.Unmarshal(raw, &original); err != nil || len(original) != 2 {
					t.Fatalf("actual original archive oracle failed: %v", err)
				}
				if artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); artifact != "" {
					folder := filepath.Join(artifact, strings.ReplaceAll(target, "/", "-"), strings.TrimPrefix(path, fixtureModule))
					if err := os.MkdirAll(folder, 0700); err != nil {
						t.Fatal(err)
					}
					for name, data := range map[string][]byte{"text-sdk.json": raw, "text-report.json": encoded, "text-original.a": report.Archives[path]} {
						if err := os.WriteFile(filepath.Join(folder, name), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				t.Logf("ORIGINAL_TEXT %s %s archiveSHA256=%s members=%d", target, path, report.ArchiveSHA256[path], len(original))
				var actual any
				if err := json.Unmarshal(raw, &actual); err != nil {
					t.Fatal(err)
				}
				var claimed any
				if err := json.Unmarshal(recorded[path], &claimed); err != nil || !reflect.DeepEqual(actual, claimed) {
					t.Errorf("actual selected source/archive lacks complete TEXT relocation Add/Sym/Aux/source-PC readback: %s", path)
				}
			}
		})
	}
}

func TestGoSDKStaticStorageTEXTAllOriginalMembers(t *testing.T) {
	_, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkTextReaderSource)
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			_, report := sdkCaptured(t, sdkRequest(t, binary, target))
			packages, err := sdkCPUPackages(report)
			if err != nil {
				t.Fatal(err)
			}
			raw := run(t, oracle, report.CommandDirectory, fixtureEnv(t, target), packages["internal/cpu"].Export)
			var original []TextMember
			if err := json.Unmarshal(raw, &original); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(original, report.TextArchives["internal/cpu"]) {
				t.Fatal("complete original SDK member/TEXT/relocation/PC identity differs")
			}
			if target == "linux/386" || target == "linux/amd64" {
				observed, err := ObserveX86SDKAssemblyArchive(report.Archives["internal/cpu"], report.TextBuiltinSource,
					target, packages["internal/cpu"].SFiles)
				if err != nil || !reflect.DeepEqual(observed, original) {
					t.Fatal("SDK-only x86 archive observation differs from the independent complete SDK reader", err)
				}
			}
			encoded, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			retainTextArtifact(t, target, "sdk-text", map[string][]byte{
				"text-sdk.json": raw, "text-report.json": encoded, "text-original.a": report.Archives["internal/cpu"],
			})
			t.Logf("SDK_ORIGINAL_TEXT %s archiveSHA256=%s members=%d", target, report.ArchiveSHA256["internal/cpu"], len(original))
		})
	}
}

func TestGoStaticStorageTEXTX86ActualRelocationAddend(t *testing.T) {
	dir, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkTextReaderSource)
	for _, target := range []string{"linux/386", "linux/amd64"} {
		t.Run(target, func(t *testing.T) {
			_, owner := sdkCaptured(t, sdkRequest(t, binary, target))
			var offset int64 = -1
			for _, variable := range owner.Variables {
				if variable.Name == "X86" && len(variable.Numerical) == 1 {
					offset = variable.Numerical[0].Offset
				}
			}
			if offset < 0 {
				t.Fatal("missing actual target numerical CPU field span")
			}
			// This is an object-format counterexample, not a read permission.
			// CPU's first numerical field is HasAES; raw Add alone is not its
			// source offset when the instruction has trailing immediate bytes.
			source := "#include \"textflag.h\"\nTEXT ·Witness(SB),NOSPLIT,$0-0\n" +
				"CMPB internal∕cpu·X86+" + strconv.FormatInt(offset, 10) + "(SB), $1\n" +
				"MOVB internal∕cpu·X86+" + strconv.FormatInt(offset+1, 10) + "(SB), AL\nRET\n"
			file := filepath.Join(dir, "witness.s")
			object := filepath.Join(dir, "witness.o")
			if err := os.WriteFile(file, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			env := fixtureEnv(t, target)
			listing := run(t, binary, dir, env, "tool", "asm", "-S", "-p", fixtureModule,
				"-I", filepath.Join(filepath.Dir(filepath.Dir(binary)), "pkg", "include"), "-o", object, file)
			data, err := os.ReadFile(object)
			if err != nil {
				t.Fatal(err)
			}
			raw := run(t, oracle, dir, env, object)
			var original []TextMember
			if err := json.Unmarshal(raw, &original); err != nil || len(original) != 1 || len(original[0].Texts) != 1 {
				t.Fatalf("actual standalone Go TEXT oracle differs: %v", err)
			}
			body, err := objectBody(data, target)
			if err != nil {
				t.Fatal(err)
			}
			builtins, err := textBuiltins(owner.TextBuiltinSource)
			if err != nil {
				t.Fatal(err)
			}
			texts, err := readTextObject(body, target, 4, false, builtins)
			if err != nil || !reflect.DeepEqual(texts, original[0].Texts) {
				t.Fatalf("actual Go source/code/relocation/PC readback differs: %v", err)
			}
			value := texts[0]
			if len(value.Relocations) != 2 || len(value.Positions) != 3 || value.Positions[0].Line != 3 || value.Positions[1].Line != 4 || value.Positions[2].Line != 5 {
				t.Fatalf("instruction source-PC witness is not exact: %+v", value)
			}
			for index, relocation := range value.Relocations {
				if relocation.Target.Name != "internal/cpu.X86" || relocation.Target.ABI != 0 || relocation.Size != 4 {
					t.Fatal("real Go relocation target/width differs", relocation)
				}
				want := offset + int64(index)
				if target == "linux/amd64" {
					if relocation.Type != 14 {
						t.Fatal("actual AMD64 relocation is not R_PCREL", relocation)
					}
					tail := value.Positions[index].End - relocation.Offset - relocation.Size
					if relocation.Add+tail != want || index == 0 && (tail != 1 || relocation.Add == want) {
						t.Fatal("CMP immediate tail/addend counterexample was lost", relocation, tail)
					}
				} else if relocation.Type != 1 || relocation.Add != want {
					t.Fatal("actual 386 absolute source relocation differs", relocation)
				}
			}
			retainTextArtifact(t, target, "asm-text", map[string][]byte{
				"text-sdk.json": raw, "text-original.o": data, "text-source.s": []byte(source), "text-listing.txt": listing,
			})
			// Querying a standalone object never relaxes ordinary Capture's
			// no-assembly source role or creates a token from these bytes.
			if observed, err := Capture(context.Background(), request(t, dir, binary, target)); err == nil {
				observed.Close()
				t.Fatal("TEXT metadata silently expanded ordinary source admission")
			}
			if !bytes.Contains(listing, []byte("internal/cpu.X86")) {
				t.Fatal("actual Go did not consume the specified native source symbol")
			}
		})
	}
}

func TestGoStaticStorageTEXTActualZeroPC(t *testing.T) {
	_, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkTextReaderSource)
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir()) // Only this fresh owned output.
			if err != nil {
				t.Fatal(err)
			}
			source := []byte("#include \"textflag.h\"\nTEXT ·Empty(SB),NOSPLIT,$0-0\n")
			file, object := filepath.Join(dir, "empty.s"), filepath.Join(dir, "empty.o")
			if err := os.WriteFile(file, source, 0600); err != nil {
				t.Fatal(err)
			}
			env := fixtureEnv(t, target)
			listing := run(t, binary, dir, env, "tool", "asm", "-S", "-p", fixtureModule,
				"-I", filepath.Join(filepath.Dir(filepath.Dir(binary)), "pkg", "include"), "-o", object, file)
			original, err := os.ReadFile(object)
			if err != nil {
				t.Fatal(err)
			}
			raw := run(t, oracle, dir, env, object)
			var members []TextMember
			if err := json.Unmarshal(raw, &members); err != nil || len(members) != 1 || len(members[0].Texts) != 1 {
				t.Fatal("original zero-PC SDK reader differs", err)
			}
			body, err := objectBody(original, target)
			if err != nil {
				t.Fatal(err)
			}
			builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(binary)), builtinSourceRole))
			if err != nil {
				t.Fatal(err)
			}
			builtins, err := textBuiltins(builtin)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := readTextObject(body, target, 4, false, builtins)
			if err != nil || !reflect.DeepEqual(observed, members[0].Texts) {
				t.Fatal("actual zero-PC object/code/AUX role was rejected", err)
			}
			retainTextArtifact(t, target, "zero-text", map[string][]byte{
				"text-source.s": source, "text-original.o": original, "text-sdk.json": raw, "text-listing.txt": listing,
			})
			if target == "js/wasm" {
				if observed[0].Size != 1 || len(observed[0].Code) <= 1 {
					t.Fatal("actual wasm TEXT-only virtual/physical axes differ", observed[0])
				}
			} else if observed[0].Size != 0 || observed[0].Positions != nil || !bytes.Equal(observed[0].PCFile, []byte{2, 0, 0}) || !bytes.Equal(observed[0].PCLine, []byte{6, 0, 0}) {
				t.Fatal("actual TEXT-only zero-PC value/distance/terminator role differs", observed[0])
			}
			t.Logf("actual zero-PC %s logical=%d physical=%d", target, observed[0].Size, len(observed[0].Code))
		})
	}
}
