package gostaticstorage

import (
	"encoding/json"
	"errors"
	"testing"
)

// This is a pure rule model, not an SDK source, owner or object-byte oracle.
// ActualGoObjects independently checks every literal class and linked padding.
func readonlyLiteralModel() *SDKASMDataObservation {
	definition := ASMDataDefinition{Namespace: TextSymbolSelf, Name: "literal", ABI: 65535,
		Kind: 3, Size: 8, Data: []byte{0, 255}, DataOffset: 100}
	fragment := ASMDataFragment{Ordinal: 0, Line: 1, Offset: 1, Width: 1, Kind: ASMDataInteger, Bits: 255}
	layout := ASMGlobalLayout{Ordinal: 1, Line: 2, Name: definition.Name, Static: true, ABI: 65535,
		Flags: 24, DeclaredSize: 8, Fragments: []ASMDataFragment{fragment}, Definition: definition}
	member := ASMDataMember{Name: "table.o", NameBytes: []byte("table.o"), Ordinal: 2, Flags: 20,
		Definitions: []ASMDataDefinition{definition}}
	return &SDKASMDataObservation{Protocol: ASMDataCPPProtocol, PackagePath: "model", Target: "linux/amd64",
		Members: []ASMDataMember{{Name: "__.PKGDEF"}, {Name: "_go_.o"}, member},
		Sources: []ASMDataSourceObservation{{Name: "table.s", Original: member, Expanded: member, ExpandedLayouts: []ASMGlobalLayout{layout}}}}
}

func readonlyLiteralClone(t *testing.T, observation *SDKASMDataObservation) *SDKASMDataObservation {
	t.Helper()
	data, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var copied SDKASMDataObservation
	if err := json.Unmarshal(data, &copied); err != nil {
		t.Fatal(err)
	}
	return &copied
}

func TestReadonlyLiteralDataModelAndOwnership(t *testing.T) {
	observation := readonlyLiteralModel()
	images, err := ReadonlyLiteralDataInitializers(observation)
	if err != nil || len(images) != 1 || len(images[0].Initial) != 8 || images[0].Initial[1] != 255 {
		t.Fatal("exact sparse/tail model was rejected", err)
	}
	images[0].Initial[1] = 0
	images[0].Definition.Data[1] = 0
	images[0].Fragments[0].Bits = 0
	if observation.Sources[0].ExpandedLayouts[0].Fragments[0].Bits != 255 || observation.Members[2].Definitions[0].Data[1] != 255 {
		t.Fatal("pure returned plan aliases the complete original observation")
	}
}

func TestReadonlyLiteralDataOrdinaryAndFIPSKinds(t *testing.T) {
	for _, kind := range []uint8{1, 2, 3, 4, 5, 6, 7, 8, 9, 25} {
		observation := readonlyLiteralClone(t, readonlyLiteralModel())
		observation.Members[2].Definitions[0].Kind = kind
		observation.Sources[0].Original.Definitions[0].Kind = kind
		observation.Sources[0].Expanded.Definitions[0].Kind = kind
		observation.Sources[0].ExpandedLayouts[0].Definition.Kind = kind
		images, err := ReadonlyLiteralDataInitializers(observation)
		if kind == 3 || kind == 4 {
			if err != nil || len(images) != 1 || images[0].Definition.Kind != kind || images[0].Initial[1] != 255 {
				t.Fatalf("readonly kind %d lost original kind or bytes: %v", kind, err)
			}
		} else if !errors.Is(err, ErrContext) || images != nil {
			t.Fatalf("non-readonly kind %d acquired a literal initializer: %v", kind, err)
		}
	}
}

func TestReadonlyLiteralDataRoleAndIdentityNegatives(t *testing.T) {
	cases := map[string]func(*SDKASMDataObservation){
		"protocol":             func(o *SDKASMDataObservation) { o.Protocol = "public-json" },
		"target":               func(o *SDKASMDataObservation) { o.Target = "linux/arm64" },
		"package":              func(o *SDKASMDataObservation) { o.PackagePath = "" },
		"empty-source":         func(o *SDKASMDataObservation) { o.Sources = nil },
		"missing-member":       func(o *SDKASMDataObservation) { o.Members = o.Members[:2] },
		"source-route":         func(o *SDKASMDataObservation) { o.Sources[0].Name = "foreign.s" },
		"member-route":         func(o *SDKASMDataObservation) { o.Members[2].Name = "foreign.o" },
		"member-bytes":         func(o *SDKASMDataObservation) { o.Members[2].NameBytes[0] ^= 1 },
		"member-ordinal":       func(o *SDKASMDataObservation) { o.Members[2].Ordinal++ },
		"member-flags":         func(o *SDKASMDataObservation) { o.Members[2].Flags = 4 },
		"expanded-object":      func(o *SDKASMDataObservation) { o.Sources[0].Expanded.Definitions[0].Data[0] = 1 },
		"original-object":      func(o *SDKASMDataObservation) { o.Sources[0].Original.Definitions[0].Index++ },
		"compiler-object":      func(o *SDKASMDataObservation) { o.Members[2].Definitions[0].Relative++ },
		"borrowed-raw-program": func(o *SDKASMDataObservation) { o.Sources[0].OriginalProgramSHA256 = "same-code" },
		"borrowed-raw-layout":  func(o *SDKASMDataObservation) { o.Sources[0].Layouts = o.Sources[0].ExpandedLayouts },
		"missing-layout":       func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts = nil },
		"repeated-layout": func(o *SDKASMDataObservation) {
			o.Sources[0].ExpandedLayouts = append(o.Sources[0].ExpandedLayouts, o.Sources[0].ExpandedLayouts[0])
		},
		"layout-index": func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].Definition.Index++ },
		"layout-namespace": func(o *SDKASMDataObservation) {
			o.Sources[0].ExpandedLayouts[0].Definition.Namespace = TextSymbolHashed
		},
		"layout-relative": func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].Definition.Relative++ },
		"not-static":      func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].Static = false },
		"wrong-ABI":       func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].ABI = 0 },
		"wrong-name":      func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].Name = "same-code-foreign" },
		"unknown-flags":   func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].Flags |= 32 },
		"DUPok":           func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].Flags |= 2 },
		"mutable":         func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].Flags = 16 },
		"negative-size":   func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].DeclaredSize = -1 },
		"wrong-size":      func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].DeclaredSize = 9 },
		"short-size":      func(o *SDKASMDataObservation) { o.Sources[0].ExpandedLayouts[0].DeclaredSize = 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			observation := readonlyLiteralClone(t, readonlyLiteralModel())
			mutate(observation)
			if _, err := ReadonlyLiteralDataInitializers(observation); !errors.Is(err, ErrContext) {
				t.Fatal("unbound or foreign DATA became an initializer", err)
			}
		})
	}
}

func TestReadonlyLiteralDataFragmentNegatives(t *testing.T) {
	for name, mutate := range map[string]func(*ASMDataFragment){
		"negative-offset":    func(f *ASMDataFragment) { f.Offset = -1 },
		"negative-width":     func(f *ASMDataFragment) { f.Width = -1 },
		"past-written-P":     func(f *ASMDataFragment) { f.Offset = 2 },
		"unsupported-width":  func(f *ASMDataFragment) { f.Width = 3 },
		"wrong-float-width":  func(f *ASMDataFragment) { f.Kind = ASMDataFloat },
		"bits-not-truncated": func(f *ASMDataFragment) { f.Bits = 511 },
		"different-bits":     func(f *ASMDataFragment) { f.Bits = 254 },
		"unknown-kind":       func(f *ASMDataFragment) { f.Kind = "bytes-from-hash" },
		"address":            func(f *ASMDataFragment) { f.Kind = ASMDataAddress; f.Address = &ASMDataAddressValue{Name: "foreign"} },
		"hidden-address":     func(f *ASMDataFragment) { f.Address = &ASMDataAddressValue{Name: "foreign"} },
		"hidden-string":      func(f *ASMDataFragment) { f.String = []byte("x") },
		"string-overflow":    func(f *ASMDataFragment) { f.Kind = ASMDataString; f.Bits = 0; f.String = []byte("xy") },
		"string-hidden-bits": func(f *ASMDataFragment) { f.Kind = ASMDataString; f.String = []byte{255} },
		"negative-ordinal":   func(f *ASMDataFragment) { f.Ordinal = -1 },
		"missing-line":       func(f *ASMDataFragment) { f.Line = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			observation := readonlyLiteralModel()
			mutate(&observation.Sources[0].ExpandedLayouts[0].Fragments[0])
			if _, err := ReadonlyLiteralDataInitializers(observation); !errors.Is(err, ErrContext) {
				t.Fatal("invalid literal fragment became initialized bytes", err)
			}
		})
	}
	for _, kind := range []string{"overlap", "reordered", "missing-fragment", "missing-hole"} {
		t.Run(kind, func(t *testing.T) {
			observation := readonlyLiteralModel()
			layout := &observation.Sources[0].ExpandedLayouts[0]
			switch kind {
			case "overlap", "reordered":
				second := layout.Fragments[0]
				if kind == "overlap" {
					second.Ordinal++
				} else {
					second.Offset++
				}
				layout.Fragments = append(layout.Fragments, second)
			case "missing-fragment":
				layout.Fragments = nil
			case "missing-hole":
				layout.Fragments[0].Offset = 0
			}
			if _, err := ReadonlyLiteralDataInitializers(observation); !errors.Is(err, ErrContext) {
				t.Fatal("incomplete sparse source became an initializer", err)
			}
		})
	}
}

func TestReadonlyLiteralDataAggregateZeroTailBudget(t *testing.T) {
	observation := readonlyLiteralModel()
	layout := &observation.Sources[0].ExpandedLayouts[0]
	layout.DeclaredSize = archiveLimit
	layout.Definition.Size = archiveLimit
	observation.Members[2].Definitions[0].Size = archiveLimit
	observation.Sources[0].Original.Definitions[0].Size = archiveLimit
	observation.Sources[0].Expanded.Definitions[0].Size = archiveLimit
	second := *layout
	second.Name, second.Ordinal = "second", 2
	second.Definition.Name, second.Definition.Relative, second.Definition.Index = "second", 1, 1
	second.DeclaredSize, second.Definition.Size = 1, 1
	second.Fragments, second.Definition.Data = nil, nil
	observation.Sources[0].ExpandedLayouts = append(observation.Sources[0].ExpandedLayouts, second)
	for _, member := range []*ASMDataMember{&observation.Members[2], &observation.Sources[0].Original, &observation.Sources[0].Expanded} {
		member.Definitions = append(member.Definitions, second.Definition)
	}
	if _, err := ReadonlyLiteralDataInitializers(observation); !errors.Is(err, ErrContext) {
		t.Fatal("per-global zero tails bypassed the aggregate initializer byte bound", err)
	}
}

func TestReadonlyLiteralDataDefinitionRoleNegatives(t *testing.T) {
	for name, mutate := range map[string]func(*ASMDataDefinition){
		"named-link-visible": func(d *ASMDataDefinition) { d.ABI = 0 },
		"hashed64":           func(d *ASMDataDefinition) { d.Namespace = TextSymbolHashed64 },
		"hashed":             func(d *ASMDataDefinition) { d.Namespace = TextSymbolHashed },
		"nonpkg-definition":  func(d *ASMDataDefinition) { d.Namespace = TextSymbolNonpkgDefinition },
		"nonpkg-reference":   func(d *ASMDataDefinition) { d.Namespace = TextSymbolNonpkgReference },
		// Kind 4 retains its positive whole-object case above. FIPS tagging
		// does not turn mutable NOPTR storage into a readonly initializer.
		"mutable-NOPTR-FIPS":      func(d *ASMDataDefinition) { d.Kind = 6 },
		"mutable-NOPTR":           func(d *ASMDataDefinition) { d.Kind = 5 },
		"mutable-DATA":            func(d *ASMDataDefinition) { d.Kind = 7 },
		"BSS":                     func(d *ASMDataDefinition) { d.Kind = 9 },
		"TLSBSS":                  func(d *ASMDataDefinition) { d.Kind = 11 },
		"DUPok":                   func(d *ASMDataDefinition) { d.Flags = 1 },
		"unknown-flags":           func(d *ASMDataDefinition) { d.Flags = 128 },
		"other-role-flags":        func(d *ASMDataDefinition) { d.Flags2 = 1 },
		"hash-cannot-select-body": func(d *ASMDataDefinition) { d.Hash = []byte("samehash") },
		"written-beyond-size":     func(d *ASMDataDefinition) { d.Size = 1 },
		"size-beyond-budget":      func(d *ASMDataDefinition) { d.Size = archiveLimit + 1 },
		"address-relocation":      func(d *ASMDataDefinition) { d.Relocations = []TextRelocation{{Offset: 0, Size: 1, Type: 1}} },
	} {
		t.Run(name, func(t *testing.T) {
			observation := readonlyLiteralClone(t, readonlyLiteralModel())
			for _, member := range []*ASMDataMember{&observation.Members[2], &observation.Sources[0].Original, &observation.Sources[0].Expanded} {
				mutate(&member.Definitions[0])
			}
			mutate(&observation.Sources[0].ExpandedLayouts[0].Definition)
			if _, err := ReadonlyLiteralDataInitializers(observation); !errors.Is(err, ErrContext) {
				t.Fatal("whole-object agreement borrowed a different DATA role", err)
			}
		})
	}
}
