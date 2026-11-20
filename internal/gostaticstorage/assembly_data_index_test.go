package gostaticstorage

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// This model exercises candidate selection and collision rules only. The
// actual Go archives in TestGoSDKASMDataFirstParty establish binary provenance.
func asmDataIndexedFixture(count int) ([]asmDataLayoutState, ASMDataMember) {
	states := make([]asmDataLayoutState, count)
	member := ASMDataMember{Definitions: make([]ASMDataDefinition, count)}
	for index := range states {
		name := fmt.Sprintf("global%d", index)
		data := []byte{byte(index)}
		states[index] = asmDataLayoutState{layout: ASMGlobalLayout{Name: name},
			global: true, kind: 3, actualSize: 1, data: data}
		member.Definitions[index] = ASMDataDefinition{Namespace: TextSymbolNonpkgDefinition,
			Relative: uint32(index), Index: uint32(index), Name: name, Kind: 3, Size: 1, Data: data}
	}
	return states, member
}

func TestASMDataIndexedCandidateIdentity(t *testing.T) {
	states, member := asmDataIndexedFixture(16384)
	layouts, err := joinASMDataLayouts(states, member)
	if err != nil || len(layouts) != len(states) {
		t.Fatal("complete independent global inventory did not join", err)
	}
	for index, layout := range layouts {
		if layout.Definition.Index != uint32(index) || layout.Definition.Relative != uint32(index) {
			t.Fatal("candidate index selected a different object-local identity", index)
		}
	}
	for name, mutate := range map[string]func(*ASMDataMember){
		"same-body-different-namespace": func(m *ASMDataMember) {
			copy := m.Definitions[0]
			copy.Namespace, copy.Index = TextSymbolSelf, uint32(len(m.Definitions))
			m.Definitions = append(m.Definitions, copy)
		},
		"same-body-same-namespace": func(m *ASMDataMember) {
			copy := m.Definitions[0]
			copy.Relative, copy.Index = uint32(len(m.Definitions)), uint32(len(m.Definitions))
			m.Definitions = append(m.Definitions, copy)
		},
		"different-kind-candidate": func(m *ASMDataMember) {
			copy := m.Definitions[0]
			copy.Kind, copy.Index = 9, uint32(len(m.Definitions))
			m.Definitions = append(m.Definitions, copy)
		},
		"wrong-ABI":                func(m *ASMDataMember) { m.Definitions[0].ABI = 1 },
		"missing-definition":       func(m *ASMDataMember) { m.Definitions = m.Definitions[1:] },
		"reused-combined-index":    func(m *ASMDataMember) { m.Definitions[1].Index = 0 },
		"reordered-relative-index": func(m *ASMDataMember) { m.Definitions[1].Relative = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			states, member := asmDataIndexedFixture(8)
			mutate(&member)
			if _, err := joinASMDataLayouts(states, member); !errors.Is(err, ErrContext) {
				t.Fatal("candidate membership became body-selection authority", err)
			}
		})
	}
}

func TestASMDataNamedCollisionGroups(t *testing.T) {
	definition := func(name string, abi uint16, kind, flags uint8) ASMDataDefinition {
		return ASMDataDefinition{Name: name, ABI: abi, Namespace: TextSymbolSelf, Kind: kind, Flags: flags}
	}
	text := func(abi uint16, flags uint8) TextRecord {
		return TextRecord{Name: "entry", ABI: abi, Namespace: TextSymbolSelf, Kind: 1, Flags: flags}
	}
	for _, test := range []struct {
		name    string
		members []ASMDataMember
		valid   bool
	}{
		{"all-DUPok", []ASMDataMember{{Definitions: []ASMDataDefinition{definition("value", 0, 3, 1)}},
			{Definitions: []ASMDataDefinition{definition("value", 0, 3, 1)}}}, true},
		{"one-non-DUPok", []ASMDataMember{{Definitions: []ASMDataDefinition{definition("value", 0, 3, 1)}},
			{Definitions: []ASMDataDefinition{definition("value", 0, 3, 0)}},
			{Definitions: []ASMDataDefinition{definition("value", 0, 3, 1)}}}, true},
		{"two-non-DUPok", []ASMDataMember{{Definitions: []ASMDataDefinition{definition("value", 0, 3, 0)}},
			{Definitions: []ASMDataDefinition{definition("value", 0, 3, 1)}},
			{Definitions: []ASMDataDefinition{definition("value", 0, 3, 0)}}}, false},
		{"same-member-DUPok", []ASMDataMember{{Definitions: []ASMDataDefinition{
			definition("value", 0, 3, 1), definition("value", 0, 3, 1)}}}, false},
		{"storage-ABI", []ASMDataMember{{Definitions: []ASMDataDefinition{definition("value", 0, 3, 1)}},
			{Definitions: []ASMDataDefinition{definition("value", 1, 3, 1)}}}, false},
		{"storage-kind", []ASMDataMember{{Definitions: []ASMDataDefinition{definition("value", 0, 3, 1)}},
			{Definitions: []ASMDataDefinition{definition("value", 0, 9, 1)}}}, false},
		{"TEXT-storage-kind", []ASMDataMember{{Definitions: []ASMDataDefinition{definition("entry", 0, 3, 1)}},
			{Texts: []TextRecord{text(0, 1)}}}, false},
		{"TEXT-distinct-ABI", []ASMDataMember{{Texts: []TextRecord{text(0, 0), text(1, 0)}}}, true},
		{"TEXT-same-ABI-non-DUPok", []ASMDataMember{{Texts: []TextRecord{text(0, 0)}},
			{Texts: []TextRecord{text(0, 0)}}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateASMDataArchiveNames(test.members)
			if test.valid && err != nil || !test.valid && !errors.Is(err, ErrContext) {
				t.Fatal("complete named collision class differs", err)
			}
		})
	}
}

// Nonpackage DUPok definitions may occur several times in one Go compiler
// member. This validates collision classes, not a linked winning body or source
// role; the actual SDK runtime factory independently exercises the real archive.
func TestASMDataSameMemberNonpkgDUPokKeepsIndexedIdentities(t *testing.T) {
	fixture := func() []ASMDataMember {
		return []ASMDataMember{{Definitions: []ASMDataDefinition{
			{Name: "fixture.funcval", Namespace: TextSymbolNonpkgDefinition, Index: 10,
				Relative: 0, Kind: 3, Flags: 1, Size: 8, Data: []byte{1}},
			{Name: "fixture.funcval", Namespace: TextSymbolNonpkgDefinition, Index: 11,
				Relative: 1, Kind: 3, Flags: 1, Size: 8, Data: []byte{2}},
		}}}
	}
	for _, mutation := range []string{"none", "third-index", "duplicate-index", "duplicate-relative", "self", "mixed-namespace",
		"one-non-DUPok", "non-DUPok-first", "two-non-DUPok", "kind", "ABI"} {
		t.Run(mutation, func(t *testing.T) {
			members := fixture()
			definitions := members[0].Definitions
			switch mutation {
			case "third-index":
				third := definitions[1]
				third.Index, third.Relative = 12, 2
				members[0].Definitions = append(definitions, third)
			case "duplicate-index":
				definitions[1].Index = definitions[0].Index
			case "duplicate-relative":
				definitions[1].Relative = definitions[0].Relative
			case "self":
				definitions[0].Namespace, definitions[1].Namespace = TextSymbolSelf, TextSymbolSelf
			case "mixed-namespace":
				definitions[1].Namespace = TextSymbolSelf
			case "one-non-DUPok":
				definitions[1].Flags = 0
			case "non-DUPok-first":
				definitions[0].Flags = 0
			case "two-non-DUPok":
				definitions[0].Flags, definitions[1].Flags = 0, 0
			case "kind":
				definitions[1].Kind = 7
			case "ABI":
				definitions[1].ABI = 1
			}
			before := fmt.Sprintf("%#v", members)
			err := validateASMDataArchiveNames(members)
			valid := mutation == "none" || mutation == "third-index" || mutation == "one-non-DUPok" || mutation == "non-DUPok-first"
			if valid && err != nil || !valid && !errors.Is(err, ErrContext) {
				t.Fatal("original nonpackage DUPok/index collision class differs", err)
			}
			if before != fmt.Sprintf("%#v", members) {
				t.Fatal("collision validation changed an original definition")
			}
			if mutation == "none" && !reflect.DeepEqual(members, fixture()) {
				t.Fatal("collision checking selected or merged a DUPok body")
			}
		})
	}
}

func TestASMDataCompleteInputGraphBound(t *testing.T) {
	request := SDKASMDataObservationRequest{Target: "linux/amd64", PackagePath: "example.invalid/fixture",
		Archive: []byte("archive"), BuiltinSource: make([]byte, 64<<20),
		Sources: []SDKASMDataSource{{Name: "data.s", Original: []byte("source"), Expanded: []byte("source"),
			OriginalObject: []byte("object"), ExpandedObject: []byte("object")}}}
	if _, err := ObserveX86SDKASMData(request); !errors.Is(err, ErrContext) ||
		!strings.Contains(err.Error(), "whole input graph") {
		t.Fatal("BuiltinSource was omitted from the complete input graph budget", err)
	}
}

func BenchmarkASMDataIndexedJoin(b *testing.B) {
	for _, count := range []int{1024, 4096, 16384} {
		b.Run(fmt.Sprintf("globals-%d", count), func(b *testing.B) {
			states, member := asmDataIndexedFixture(count)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := joinASMDataLayouts(states, member); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkASMDataNamedDUPokGroups(b *testing.B) {
	for _, count := range []int{1024, 4096, 16384} {
		b.Run(fmt.Sprintf("members-%d", count), func(b *testing.B) {
			members := make([]ASMDataMember, count)
			for index := range members {
				members[index].Definitions = []ASMDataDefinition{{Name: "shared", Kind: 3, Flags: 1,
					Namespace: TextSymbolSelf}}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := validateASMDataArchiveNames(members); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
