//go:build go1.27

package gostaticstorage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// This independently compiled SDK reader preserves every object-local DATA
// identity, exact data interval and ordered relocation. It does not call our
// parser, combine definitions by name, or infer initialized storage authority.
const sdkASMDataReaderSource = `package main

import (
	"cmd/internal/archive"
	"cmd/internal/goobj"
	"encoding/json"
	"fmt"
	"os"
)

type Reference struct {
	PackageIndex, SymbolIndex uint32
	Package, Name string
	ABI uint16
	ABIKnown bool
	Kind uint8
	KindKnown bool
}
type Relocation struct {
	Offset, Size int64
	Type uint16
	Add int64
	Target Reference
}
type Definition struct {
	Namespace int
	Relative, Index uint32
	Name string
	ABI uint16
	Kind, Flags, Flags2 uint8
	Size, Align uint32
	Hash []byte
	DataOffset uint32
	Data []byte
	Relocations []Relocation
}
type Member struct {
	Name string
	NameBytes []byte
	Ordinal int
	Offset, Size int64
	ObjectOffset int64
	Flags uint32
	Definitions []Definition
}

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil { panic(err) }
	defer f.Close()
	a, err := archive.Parse(f, false)
	if err != nil { panic(err) }
	var members []Member
	for ordinal, entry := range a.Entries {
		member := Member{Name: entry.Name, NameBytes: []byte(entry.Name), Ordinal: ordinal,
			Offset: entry.Offset, Size: entry.Size}
		if entry.Type != archive.EntryPkgDef && entry.Type != archive.EntryGoObj {
			panic("unexpected original archive member")
		}
		if entry.Type == archive.EntryGoObj {
			member.ObjectOffset = entry.Obj.Offset
			data := make([]byte, entry.Obj.Size)
			n, err := f.ReadAt(data, entry.Obj.Offset)
			if err != nil || n != len(data) { panic(fmt.Sprint(n, err)) }
			r := goobj.NewReaderFromBytes(data, false)
			if r == nil { panic("invalid original goobj") }
			member.Flags = r.Flags()
			counts := [5]int{r.NSym(), r.NHashed64def(), r.NHasheddef(), r.NNonpkgdef(), r.NNonpkgref()}
			resolve := func(ref goobj.SymRef) Reference {
				v := Reference{PackageIndex: ref.PkgIdx, SymbolIndex: ref.SymIdx}
				var index uint32
				switch ref.PkgIdx {
				case goobj.PkgIdxSelf:
					index = ref.SymIdx
				case goobj.PkgIdxHashed64:
					index = uint32(counts[0]) + ref.SymIdx
				case goobj.PkgIdxHashed:
					index = uint32(counts[0] + counts[1]) + ref.SymIdx
				case goobj.PkgIdxNone:
					index = uint32(counts[0] + counts[1] + counts[2]) + ref.SymIdx
				default:
					panic("fixture unexpectedly acquired a foreign DATA relocation")
				}
				s := r.Sym(index)
				v.Name, v.ABI, v.ABIKnown = s.Name(r), s.ABI(), true
				return v
			}
			var index uint32
			for namespace, count := range counts {
				for relative := 0; relative < count; relative++ {
					s := r.Sym(index)
					if namespace != 4 && s.Type() != 1 && s.Type() != 2 {
						definition := Definition{Namespace: namespace, Relative: uint32(relative), Index: index,
							Name: s.Name(r), ABI: s.ABI(), Kind: s.Type(), Flags: s.Flag(), Flags2: s.Flag2(),
							Size: s.Siz(), Align: s.Align(), DataOffset: r.DataOff(index), Data: r.Data(index)}
						if namespace == 1 {
							hash := r.Hash64(uint32(relative))
							definition.Hash = make([]byte, 8)
							for byteIndex := range definition.Hash { definition.Hash[byteIndex] = byte(hash >> (8 * byteIndex)) }
						}
						if namespace == 2 { definition.Hash = append([]byte(nil), r.Hash(uint32(relative))[:]...) }
						for j := 0; j < r.NReloc(index); j++ {
							q := r.Reloc(index, j)
							definition.Relocations = append(definition.Relocations, Relocation{
								Offset: int64(q.Off()), Size: int64(q.Siz()), Type: q.Type(), Add: q.Add(), Target: resolve(q.Sym())})
						}
						member.Definitions = append(member.Definitions, definition)
					}
					index++
				}
			}
		}
		members = append(members, member)
	}
	if err := json.NewEncoder(os.Stdout).Encode(members); err != nil { panic(err) }
}
`

const asmDataIndependentGlobals = 512

func asmDataFixtureSource(arch string) string {
	width := 8
	if arch == "386" {
		width = 4
	}
	source := fmt.Sprintf(`TEXT ·Entry(SB),4,$0-0
RET
DATA integers<>+0(SB)/1,$-1
DATA integers<>+1(SB)/2,$0x12345
DATA integers<>+3(SB)/4,$(1<<32)+7
DATA integers<>+7(SB)/8,$~0
GLOBL integers<>(SB),8,$24
DATA floats<>+0(SB)/4,$1.25
DATA floats<>+4(SB)/8,$-(3.5)
GLOBL floats<>(SB),8,$20
DATA strings<>+0(SB)/8,$"A\x00B"
DATA strings<>+8(SB)/0,$""
GLOBL strings<>(SB),8,$16
DATA sparse<>+2(SB)/1,$'世'
DATA sparse<>+6(SB)/2,$17/3
GLOBL sparse<>(SB),8,$20
DATA pointers<>+0(SB)/%d,$anchor<>+1(SB)
GLOBL pointers<>(SB),$%d
GLOBL anchor<>(SB),16,$8
GLOBL mutable<>(SB),$32
GLOBL tls<>(SB),256,$%d
DATA shortened<>+10(SB)/8,$0x0102030405060708
GLOBL shortened<>(SB),8,$1
DATA shared+0(SB)/1,$7
GLOBL shared(SB),2|8,$1
`, width, width, width)
	for index, test := range asmDataGrammarCases {
		source += fmt.Sprintf("DATA complete_%d<>+0(SB)/%d,$%s\nGLOBL complete_%d<>(SB),8,$16\n", index, test.width, test.value, index)
	}
	source += "GLOBL before<>(SB),16,$1\nDATA before<>+2(SB)/4,$7\n"
	source += "DATA noptr<>(SB)/1,$7\nGLOBL noptr<>(SB),16,$1\n"
	source += "DATA priority<>(SB)/1,$7\nGLOBL priority<>(SB),8|16|256,$1\n"
	source += "DATA ignored<>(SB)/1,$7\nGLOBL ignored<>(SB),1|4|32|64|512|1024|2048|4096,$1\n"
	source += "DATA ·Visible(SB)/1,$7\nGLOBL ·Visible(SB),8,$1\n"
	source += fmt.Sprintf("DATA addresses<>+0(SB)/%d,$anchor<>-1(SB)\n", width)
	source += fmt.Sprintf("DATA addresses<>+%d(SB)/%d,$·Visible+(1+2)(SB)\n", width, width)
	source += fmt.Sprintf("DATA addresses<>+%d(SB)/%d,$foreign∕pkg·Symbol+5(SB)\n", width*2, width)
	source += fmt.Sprintf("GLOBL addresses<>(SB),$%d\n", width*3)
	for index := 0; index < asmDataIndependentGlobals; index++ {
		source += fmt.Sprintf("DATA independent_%d<>(SB)/1,$%d\nGLOBL independent_%d<>(SB),8,$1\n",
			index, index&255, index)
	}
	return source
}

func TestGoSDKASMDataFirstParty(t *testing.T) {
	directory, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkASMDataReaderSource)
	textOracle := officialReaderForSource(t, binary, sdkTextReaderSource)
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(binary)), "src", "cmd", "internal", "goobj", "builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			target := "linux/" + arch
			env := fixtureEnv(t, target)
			consumer := filepath.Join(directory, "datafixture."+arch)
			if err := os.Mkdir(consumer, 0700); err != nil {
				t.Fatal(err)
			}
			goSource := "package datafixture\nfunc Entry()\n"
			assembly := asmDataFixtureSource(arch)
			second := "DATA shared+0(SB)/1,$7\nGLOBL shared(SB),2|8,$1\nDATA integers<>+0(SB)/1,$9\nGLOBL integers<>(SB),8,$1\n"
			for name, data := range map[string]string{"data.go": goSource, "data.s": assembly, "second.s": second} {
				if err := os.WriteFile(filepath.Join(consumer, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			selection := run(t, binary, consumer, env, "list", "-json", "-compiled", "-export", "-mod=readonly", "-gcflags=-std", "-asmflags=-std", ".")
			var selected struct {
				ImportPath, Export string
				SFiles             []string
				Standard           bool
			}
			if err := json.Unmarshal(selection, &selected); err != nil || selected.Standard ||
				!reflect.DeepEqual(selected.SFiles, []string{"data.s", "second.s"}) {
				t.Fatal("actual first-party source inventory differs", err)
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			raw := run(t, oracle, consumer, env, selected.Export)
			textRaw := run(t, textOracle, consumer, env, selected.Export)
			var original []ASMDataMember
			var originalTexts []TextMember
			if err := json.Unmarshal(raw, &original); err != nil || len(original) != 4 {
				t.Fatal("independent original DATA inventory differs", err)
			}
			if err := json.Unmarshal(textRaw, &originalTexts); err != nil || len(originalTexts) != 4 {
				t.Fatal("independent original whole TEXT inventory differs", err)
			}
			request := SDKASMDataObservationRequest{PackagePath: selected.ImportPath, Target: target, Archive: archive, BuiltinSource: builtin}
			artifacts := map[string][]byte{"original.a": archive, "selection.json": selection,
				"data-sdk.json": raw, "text-sdk.json": textRaw, "source-data.go": []byte(goSource)}
			for index, name := range selected.SFiles {
				source, err := os.ReadFile(filepath.Join(consumer, name))
				if err != nil {
					t.Fatal(err)
				}
				// Keep actual physical source lines stable for the initial whole
				// object join. Distinct raw spacing is still retained and hashed.
				expanded := []byte(strings.ReplaceAll(string(source), ",", ", "))
				expandedName := fmt.Sprintf("expanded-%d.asm", index)
				if err := os.WriteFile(filepath.Join(consumer, expandedName), expanded, 0600); err != nil {
					t.Fatal(err)
				}
				input := SDKASMDataSource{Name: name, Original: source, Expanded: expanded}
				for role, sourceName := range map[string]string{"original": name, "expanded": expandedName} {
					objectName := fmt.Sprintf("%s-%d.o", role, index)
					run(t, binary, consumer, env, "tool", "asm", "-std", "-p", selected.ImportPath, "-o", objectName, sourceName)
					object, err := os.ReadFile(filepath.Join(consumer, objectName))
					if err != nil {
						t.Fatal(err)
					}
					if role == "original" {
						input.OriginalObject = object
					} else {
						input.ExpandedObject = object
					}
					artifacts[objectName] = object
					artifacts[objectName+".sdk.json"] = run(t, oracle, consumer, env, objectName)
				}
				artifacts["source-"+name] = source
				artifacts[expandedName] = expanded
				request.Sources = append(request.Sources, input)
			}
			retainTextArtifact(t, target, "asm-data-first-party", artifacts)
			observation, err := ObserveX86SDKASMData(request)
			if err != nil || observation == nil {
				t.Fatal("typed DATA source/object observation rejected actual Go input", err)
			}
			if observation.Protocol != ASMDataProtocol || observation.Target != target || observation.PackagePath != selected.ImportPath || len(observation.Sources) != 2 {
				t.Fatal("whole source/member observation lost its metadata boundary")
			}
			for index := range original {
				original[index].Texts = originalTexts[index].Texts
			}
			observedJSON, err := json.MarshalIndent(observation, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			retainTextArtifact(t, target, "asm-data-first-party", map[string][]byte{"observation.json": observedJSON})
			if !reflect.DeepEqual(observation.Members, original) {
				t.Fatal("complete namespace/index/data/relocation/TEXT observation differs from actual SDK")
			}
			if len(observation.Sources[0].Layouts) != 16+len(asmDataGrammarCases)+asmDataIndependentGlobals || len(observation.Sources[1].Layouts) != 2 {
				t.Fatal("typed DATA/GLOBL grammar lost source declarations")
			}
			if _, err := ObserveX86SDKAssemblyArchive(archive, builtin, target, selected.SFiles); err == nil || !strings.Contains(err.Error(), "assembly DATA definition") {
				t.Fatal("offline DATA observation widened the unchanged SDK TEXT permission", err)
			}
			t.Run("input-guards", func(t *testing.T) { checkASMDataInputGuards(t, request) })
			t.Run("binary-guards", func(t *testing.T) { checkASMDataBinaryGuards(t, request) })
		})
	}
}
