package gostaticstorage

import (
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func generatedFuncdataFixture(t *testing.T) ([]byte, ASMDataMember) {
	t.Helper()
	hash, err := hex.DecodeString("b7518df6dd275dfd7c0f147d0194c737")
	if err != nil {
		t.Fatal(err)
	}
	definition := ASMDataDefinition{Namespace: TextSymbolHashed, Index: 0, Relative: 0,
		Name: "gclocals·J26BEvPExEQhJvjp9E8Whg==", ABI: 0, Kind: 3, Flags: 1,
		Size: 8, Align: 4, Hash: hash, Data: []byte{2, 0, 0, 0, 0, 0, 0, 0}}
	member := ASMDataMember{Flags: sdkAssemblyObjectFlags("linux/386"), Definitions: []ASMDataDefinition{definition}}
	var source strings.Builder
	for index, name := range []string{"first", "independent"} {
		source.WriteString("TEXT ·" + name + "(SB),4,$0-0\nFUNCDATA $1,no_pointers_stackmap(SB)\nRET\n")
		member.Texts = append(member.Texts, TextRecord{Namespace: TextSymbolNonpkgDefinition, Relative: uint32(index), Index: uint32(index + 1),
			Name: "fixture." + name, ABI: 0, Kind: 1, Auxiliary: []TextAuxiliary{
				{Type: 1}, {Type: 2}, {Type: 2, Target: TextReference{PackageIndex: 2147483645, SymbolIndex: 0, Name: definition.Name, ABI: 0, ABIKnown: true}},
			}})
	}
	return []byte(source.String()), member
}

func TestASMGeneratedFuncdataNeverCreatesDataOrLiteralLayout(t *testing.T) {
	source, member := generatedFuncdataFixture(t)
	metadata, err := generatedASMFuncdata(source, "fixture", member)
	if err != nil {
		t.Fatal(err)
	}
	if layouts, err := joinASMDataLayouts(nil, member); !errors.Is(err, ErrContext) || layouts != nil {
		t.Fatal("the existing DATA join stopped rejecting unconsumed definitions", err)
	}
	partition := asmDataWithoutGeneratedFuncdata(member, metadata)
	if layouts, err := joinASMDataLayouts(nil, partition); err != nil || len(layouts) != 0 || len(member.Definitions) != 1 {
		t.Fatal("metadata partition invented a DATA layout or removed its complete object record", err)
	}
	partition.Definitions = append(partition.Definitions, ASMDataDefinition{Name: "unproved", Kind: 3, Namespace: TextSymbolSelf})
	if _, err := joinASMDataLayouts(nil, partition); !errors.Is(err, ErrContext) {
		t.Fatal("another unconsumed DATA definition inherited the metadata exception", err)
	}
	member.Name, member.NameBytes, member.Ordinal = "metadata.o", []byte("metadata.o"), 2
	observation := &SDKASMDataObservation{Protocol: ASMDataCPPProtocol, PackagePath: "fixture", Target: "linux/386",
		Members: []ASMDataMember{{Name: "__.PKGDEF"}, {Name: "_go_.o"}, member},
		Sources: []ASMDataSourceObservation{{Name: "metadata.s", Original: member, Expanded: member, GeneratedFuncdata: metadata}}}
	if images, err := ReadonlyLiteralDataInitializers(observation); !errors.Is(err, ErrContext) || images != nil {
		t.Fatal("generated metadata entered the private literal/initializer directory", images, err)
	}
	withoutRole := []byte(strings.ReplaceAll(string(source), "FUNCDATA $1,no_pointers_stackmap(SB)", "NOP"))
	if records, err := generatedASMFuncdata(withoutRole, "fixture", member); err != nil || len(records) != 0 {
		t.Fatal("a generated-looking name/hash/payload supplied its own missing source role", records, err)
	}
}

func TestASMGeneratedFuncdataWholeSourceOwnerAndNilSlot(t *testing.T) {
	source, member := generatedFuncdataFixture(t)
	before := append([]byte(nil), source...)
	metadata, err := generatedASMFuncdata(source, "fixture", member)
	if err != nil || len(metadata) != 1 || len(metadata[0].Owners) != 2 || !reflect.DeepEqual(metadata[0].Definition, member.Definitions[0]) {
		t.Fatal("complete source-owned metadata was not independently classified", metadata, err)
	}
	for index, owner := range metadata[0].Owners {
		if owner.Slot != 1 || owner.TextSourceOrdinal != index || owner.TextObjectOrdinal != index || owner.TextNamespace != TextSymbolNonpkgDefinition || owner.TextIndex != uint32(index+1) {
			t.Fatal("nil funcdata slot or exact source/object owner was lost", owner)
		}
	}
	if !reflect.DeepEqual(source, before) {
		t.Fatal("classification modified source bytes")
	}
}

func TestASMGeneratedFuncdataRejectsPermissionAndIdentityChanges(t *testing.T) {
	for name, mutate := range map[string]func(*ASMDataMember){
		"namespace":      func(m *ASMDataMember) { m.Definitions[0].Namespace = TextSymbolSelf },
		"relative-index": func(m *ASMDataMember) { m.Definitions[0].Relative++ },
		"ABI":            func(m *ASMDataMember) { m.Definitions[0].ABI = 1 },
		"kind":           func(m *ASMDataMember) { m.Definitions[0].Kind = 5 },
		"flags":          func(m *ASMDataMember) { m.Definitions[0].Flags = 0 },
		"flags2":         func(m *ASMDataMember) { m.Definitions[0].Flags2 = 1 },
		"size":           func(m *ASMDataMember) { m.Definitions[0].Size++ },
		"alignment":      func(m *ASMDataMember) { m.Definitions[0].Align = 8 },
		"payload":        func(m *ASMDataMember) { m.Definitions[0].Data[0] = 1 },
		"hash":           func(m *ASMDataMember) { m.Definitions[0].Hash[0] ^= 1 },
		"generated-name": func(m *ASMDataMember) { m.Definitions[0].Name += "forged" },
		"data-relocation": func(m *ASMDataMember) {
			m.Definitions[0].Relocations = []TextRelocation{{Target: m.Texts[0].Auxiliary[2].Target}}
		},
		"ordinary-TEXT-relocation": func(m *ASMDataMember) {
			m.Texts[0].Relocations = []TextRelocation{{Target: m.Texts[0].Auxiliary[2].Target}}
		},
		"ordinary-DATA-relocation": func(m *ASMDataMember) {
			m.Definitions = append(m.Definitions, ASMDataDefinition{Name: "ordinary", Kind: 5,
				Relocations: []TextRelocation{{Target: m.Texts[0].Auxiliary[2].Target}}})
		},
		"extra-aux-owner": func(m *ASMDataMember) { m.Texts[0].Auxiliary = append(m.Texts[0].Auxiliary, m.Texts[0].Auxiliary[2]) },
		"wrong-aux-kind":  func(m *ASMDataMember) { m.Texts[0].Auxiliary[2].Type = 3 },
		"nil-slot-removed": func(m *ASMDataMember) {
			m.Texts[0].Auxiliary = append(m.Texts[0].Auxiliary[:1], m.Texts[0].Auxiliary[2:]...)
		},
		"owner-reference-namespace": func(m *ASMDataMember) { m.Texts[0].Auxiliary[2].Target.PackageIndex-- },
		"owner-reference-index":     func(m *ASMDataMember) { m.Texts[0].Auxiliary[2].Target.SymbolIndex++ },
		"owner-reference-ABI":       func(m *ASMDataMember) { m.Texts[0].Auxiliary[2].Target.ABI = 1 },
		"unassociated-second-TEXT":  func(m *ASMDataMember) { m.Texts[1].Name = "fixture.unrelated" },
	} {
		t.Run(name, func(t *testing.T) {
			source, member := generatedFuncdataFixture(t)
			mutate(&member)
			if metadata, err := generatedASMFuncdata(source, "fixture", member); err == nil || len(metadata) != 0 {
				t.Fatal("changed metadata/source/object authority was accepted", metadata, err)
			}
		})
	}
	for _, suffix := range []string{
		"\nGLOBL no_pointers_stackmap(SB),8,$8\n", "\nDATA no_pointers_stackmap+0(SB)/8,$2\n",
		"\nLEAL no_pointers_stackmap(SB),AX\n", "\nMOVL $no_pointers_stackmap(SB),AX\n",
		"\nLEAL gclocals·J26BEvPExEQhJvjp9E8Whg==(SB),AX\n",
		"\nMOVL $\"gclocals·J26BEvPExEQhJvjp9E8Whg==\"(SB),AX\n",
		"\nLEAL \"gclocals·J26BEvPExEQhJvjp9E8Whg==\"+4(SB),AX\n",
		"\nGLOBL \"gclocals·J26BEvPExEQhJvjp9E8Whg==\"(SB),8,$8\n",
	} {
		t.Run(suffix, func(t *testing.T) {
			source, member := generatedFuncdataFixture(t)
			if metadata, err := generatedASMFuncdata(append(source, []byte(suffix)...), "fixture", member); err == nil || len(metadata) != 0 {
				t.Fatal("explicit storage/address use acquired a generated-only metadata role", metadata, err)
			}
		})
	}
	for _, body := range []string{
		"FUNCDATA $1,no_pointers_stackmap(SB)\nFUNCDATA $1,no_pointers_stackmap(SB)",
		"FUNCDATA $0,no_pointers_stackmap(SB)",
	} {
		t.Run(body, func(t *testing.T) {
			source, member := generatedFuncdataFixture(t)
			source = []byte(strings.Replace(string(source), "FUNCDATA $1,no_pointers_stackmap(SB)", body, 1))
			if metadata, err := generatedASMFuncdata(source, "fixture", member); err == nil || len(metadata) != 0 {
				t.Fatal("duplicate source owner/slot or wrong reserved slot acquired metadata", metadata, err)
			}
		})
	}
}

func TestASMGeneratedFuncdataRejectsChangedTextOrder(t *testing.T) {
	for name, mutate := range map[string]func([]ASMSourceText) []ASMSourceText{
		"missing":        func(_ []ASMSourceText) []ASMSourceText { return nil },
		"index":          func(values []ASMSourceText) []ASMSourceText { values[0].ObjectOrdinal = -1; return values },
		"source-ordinal": func(values []ASMSourceText) []ASMSourceText { values[0].SourceOrdinal++; return values },
		"namespace":      func(values []ASMSourceText) []ASMSourceText { values[0].Namespace = TextSymbolSelf; return values },
		"symbol":         func(values []ASMSourceText) []ASMSourceText { values[0].Name = "unrelated"; return values },
		"ABI":            func(values []ASMSourceText) []ASMSourceText { values[0].ABI++; return values },
		"relative":       func(values []ASMSourceText) []ASMSourceText { values[0].Relative++; return values },
		"physical-index": func(values []ASMSourceText) []ASMSourceText { values[0].Index++; return values },
		"duplicate": func(values []ASMSourceText) []ASMSourceText {
			values[1].ObjectOrdinal = values[0].ObjectOrdinal
			return values
		},
	} {
		t.Run(name, func(t *testing.T) {
			source, member := generatedFuncdataFixture(t)
			order, err := ASMSourceTextOrder(source, "fixture", member)
			if err != nil {
				t.Fatal(err)
			}
			if metadata, err := generatedASMFuncdataWithTextOrder(source, "fixture", member, mutate(order)); err == nil || len(metadata) != 0 {
				t.Fatal("a different source/TEXT mapping was accepted", metadata, err)
			}
		})
	}
}

func TestASMGeneratedFuncdataProducerSourcesFailClosed(t *testing.T) {
	for _, version := range []string{"", "go1.20.14", "go1.26.2", "go1.27.4"} {
		called := false
		err := GeneratedFuncdataSources(version, func(string) ([]byte, error) { called = true; return nil, nil })
		if !errors.Is(err, ErrContext) || called {
			t.Fatal("unregistered metadata schema read or gained a source role", version, called, err)
		}
	}
	if err := GeneratedFuncdataSources("go1.27.2", nil); !errors.Is(err, ErrContext) {
		t.Fatal("a missing guarded reader acquired a metadata source role", err)
	}
	if err := GeneratedFuncdataSources("go1.27.2", func(string) ([]byte, error) { return []byte("different actual source"), nil }); !errors.Is(err, ErrContext) {
		t.Fatal("changed actual producer source acquired a metadata source role", err)
	}
	want := errors.New("guarded source unavailable")
	if err := GeneratedFuncdataSources("go1.27.2", func(string) ([]byte, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatal("a guarded reader failure was hidden", err)
	}
}
