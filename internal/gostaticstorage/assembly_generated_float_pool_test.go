package gostaticstorage

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

// Synthetic metadata unit fixture only: the Go1.27 whole-family test supplies
// independently assembled and stock-reader-observed source/object evidence.
func generatedFloatPoolUnitFixture(t *testing.T) ([]byte, ASMDataMember, []ASMSourceText) {
	t.Helper()
	source := []byte("TEXT ·value(SB),4,$0-0\nMOVSS $-0.0,X0\nRET\n")
	definition := ASMDataDefinition{Namespace: TextSymbolHashed64, Name: "$f32.80000000", Kind: 3, Flags: 2,
		Size: 4, Align: 4, Data: []byte{0, 0, 0, 0x80}, Hash: []byte{0, 0, 0, 0x80, 0, 0, 0, 0}}
	text := TextRecord{Namespace: TextSymbolNonpkgDefinition, Index: 1, Name: "fixture.value", Kind: 1, Size: 9,
		Code:      []byte{0xf3, 0x0f, 0x10, 0x05, 0, 0, 0, 0, 0xc3},
		Positions: []TextPosition{{Start: 0, End: 8, File: "pool.s", Line: 2}, {Start: 8, End: 9, File: "pool.s", Line: 3}},
		Relocations: []TextRelocation{{Offset: 4, Size: 4, Type: 14,
			Target: TextReference{PackageIndex: 2147483646, Name: definition.Name, ABIKnown: true}}}}
	member := ASMDataMember{Flags: sdkAssemblyObjectFlags("linux/amd64"),
		Definitions: []ASMDataDefinition{definition}, Texts: []TextRecord{text}}
	order, err := ASMSourceTextOrder(source, "fixture", member)
	if err != nil {
		t.Fatal(err)
	}
	return source, member, order
}

func TestASMGeneratedFloatPoolMetadataOnlyAndCompleteOwners(t *testing.T) {
	source, member, texts := generatedFloatPoolUnitFixture(t)
	pools, err := generatedASMFloatPools(source, "linux/amd64", member, texts)
	if err != nil || len(pools) != 1 || len(pools[0].Owners) != 1 || !reflect.DeepEqual(pools[0].Definition, member.Definitions[0]) {
		t.Fatal("a complete synthetic source/object metadata association was lost", pools, err)
	}
	owner := pools[0].Owners[0]
	if owner.StatementOrdinal != 1 || owner.TextSourceOrdinal != 0 || owner.TextObjectOrdinal != 0 ||
		owner.TextNamespace != TextSymbolNonpkgDefinition || owner.TextIndex != 1 || owner.Opcode != "MOVSS" ||
		owner.SourceFloat64Bits != 0x8000000000000000 || owner.RelocationOrdinal != 0 || !reflect.DeepEqual(owner.Relocation, member.Texts[0].Relocations[0]) {
		t.Fatal("the source, original IEEE value and complete physical owner were not retained", owner)
	}
	if _, err := joinASMDataLayouts(nil, member); !errors.Is(err, ErrContext) {
		t.Fatal("ordinary DATA became permissive for an unconsumed generated definition", err)
	}
	partition := asmDataWithoutGeneratedFloatPools(member, pools)
	if layouts, err := joinASMDataLayouts(nil, partition); err != nil || len(layouts) != 0 || len(member.Definitions) != 1 {
		t.Fatal("metadata partition created a source DATA layout or removed the complete observation", err)
	}
	partition.Definitions = append(partition.Definitions, ASMDataDefinition{Name: "$f32.unknown", Kind: 3, Namespace: TextSymbolHashed64})
	if _, err := joinASMDataLayouts(nil, partition); !errors.Is(err, ErrContext) {
		t.Fatal("unknown prefixed DATA inherited a metadata partition", err)
	}
	changed := []byte(strings.Replace(string(source), "MOVSS $-0.0,X0", "MOVSS \"$f32.80000000\"(SB),X0", 1))
	withoutProducer, err := generatedASMFloatPools(changed, "linux/amd64", member, texts)
	if err != nil || len(withoutProducer) != 0 {
		t.Fatal("a generated-looking name supplied its own absent FCONST producer", withoutProducer, err)
	}
	if _, err := joinASMDataLayouts(nil, asmDataWithoutGeneratedFloatPools(member, withoutProducer)); !errors.Is(err, ErrContext) {
		t.Fatal("a non-FCONST prefix obtained a complete DATA observation", err)
	}
}

func TestASMGeneratedFloatPoolRejectsUnassociatedReferences(t *testing.T) {
	for name, change := range map[string]func(*ASMDataMember, []ASMSourceText){
		"extra-TEXT": func(member *ASMDataMember, _ []ASMSourceText) {
			member.Texts[0].Relocations = append(member.Texts[0].Relocations, member.Texts[0].Relocations[0])
		},
		"DATA": func(member *ASMDataMember, _ []ASMSourceText) {
			member.Definitions = append(member.Definitions, ASMDataDefinition{Name: "ordinary", Kind: 5,
				Relocations: append([]TextRelocation(nil), member.Texts[0].Relocations...)})
		},
		"auxiliary": func(member *ASMDataMember, _ []ASMSourceText) {
			member.Texts[0].Auxiliary = []TextAuxiliary{{Type: 2, Target: member.Texts[0].Relocations[0].Target}}
		},
		"missing-relocation": func(member *ASMDataMember, _ []ASMSourceText) { member.Texts[0].Relocations = nil },
		"missing-PC":         func(member *ASMDataMember, _ []ASMSourceText) { member.Texts[0].Positions = nil },
		"changed-PC":         func(member *ASMDataMember, _ []ASMSourceText) { member.Texts[0].Relocations[0].Offset++ },
		"source-order":       func(_ *ASMDataMember, order []ASMSourceText) { order[0].SourceOrdinal++ },
		"object-order":       func(_ *ASMDataMember, order []ASMSourceText) { order[0].ObjectOrdinal++ },
		"text-namespace":     func(_ *ASMDataMember, order []ASMSourceText) { order[0].Namespace = TextSymbolSelf },
		"text-name":          func(_ *ASMDataMember, order []ASMSourceText) { order[0].Name += "changed" },
	} {
		t.Run(name, func(t *testing.T) {
			source, member, order := generatedFloatPoolUnitFixture(t)
			change(&member, order)
			if pools, err := generatedASMFloatPools(source, "linux/amd64", member, order); !errors.Is(err, ErrContext) || pools != nil {
				t.Fatal("an unassociated object/source reference acquired a pool observation", pools, err)
			}
		})
	}
}

func TestASMGeneratedFloatPoolFloatExpressionGrammar(t *testing.T) {
	for _, literal := range []string{"1.25", "(+1.25)", "-(-1.25)", "0x1.4p+0", "1.2_5"} {
		t.Run(literal, func(t *testing.T) {
			statements, err := asmDataStatements([]byte(literal))
			if err != nil || len(statements) != 1 {
				t.Fatal("float grammar fixture", err)
			}
			value, floating, err := asmGeneratedFloatPoolConstant(statements[0])
			if err != nil || !floating || math.Float64bits(value) != 0x3ff4000000000000 {
				t.Fatal("official recursive float grammar lost its exact original value", value, floating, err)
			}
		})
	}
	for _, literal := range []string{"1", "(1)", "1.0+0.0", "1.0*0.0", "(1+0.0)", strings.Repeat("(", 257) + "1.0" + strings.Repeat(")", 257)} {
		t.Run(literal, func(t *testing.T) {
			statements, err := asmDataStatements([]byte(literal))
			if err != nil || len(statements) != 1 {
				t.Fatal("negative float grammar fixture", err)
			}
			if _, floating, err := asmGeneratedFloatPoolConstant(statements[0]); err == nil && floating {
				t.Fatal("integer, binary or unbounded float grammar acquired FCONST metadata")
			}
		})
	}
}

func TestASMGeneratedFloatPoolProducerSourcesFailClosed(t *testing.T) {
	for _, version := range []string{"", "go1.20.14", "go1.26.2", "go1.27.4"} {
		called := false
		err := GeneratedFloatPoolSources(version, func(string) ([]byte, error) { called = true; return nil, nil })
		if !errors.Is(err, ErrContext) || called {
			t.Fatal("unregistered pool schema used a source reader", version, called, err)
		}
	}
	if err := GeneratedFloatPoolSources("go1.27.2", nil); !errors.Is(err, ErrContext) {
		t.Fatal("a missing guarded reader acquired pool source identity", err)
	}
	if err := GeneratedFloatPoolSources("go1.27.2", func(string) ([]byte, error) { return []byte("changed actual source"), nil }); !errors.Is(err, ErrContext) {
		t.Fatal("a changed producer source acquired pool source identity", err)
	}
	want := errors.New("unavailable guarded source")
	if err := GeneratedFloatPoolSources("go1.27.2", func(string) ([]byte, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatal("a guarded source failure was hidden", err)
	}
}
