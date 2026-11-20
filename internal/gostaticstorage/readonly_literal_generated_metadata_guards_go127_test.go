//go:build go1.27

package gostaticstorage

import (
	"errors"
	"testing"
)

func readonlyMixedMetadataMembers(observation *SDKASMDataObservation, change func(*ASMDataMember)) {
	for _, member := range []*ASMDataMember{&observation.Members[2], &observation.Sources[0].Original, &observation.Sources[0].Expanded} {
		change(member)
	}
}

func readonlyMixedMetadataPoolDefinition(observation *SDKASMDataObservation, change func(*ASMDataDefinition)) {
	readonlyMixedMetadataDefinition(observation, &observation.Sources[0].GeneratedFloatPools[0].Definition, change)
}

func readonlyMixedMetadataDefinition(observation *SDKASMDataObservation, definition *ASMDataDefinition, change func(*ASMDataDefinition)) {
	index := definition.Index
	readonlyMixedMetadataMembers(observation, func(member *ASMDataMember) {
		for ordinal := range member.Definitions {
			if member.Definitions[ordinal].Index == index {
				change(&member.Definitions[ordinal])
			}
		}
	})
	change(definition)
}

func readonlyMixedMetadataUnknown(observation *SDKASMDataObservation, name string, forged bool) {
	definition := observation.Sources[0].GeneratedFloatPools[0].Definition
	definition.Name = name
	definition.Index, definition.Relative = 100000, 100000
	readonlyMixedMetadataMembers(observation, func(member *ASMDataMember) {
		member.Definitions = append(member.Definitions, definition)
	})
	if forged {
		pool := observation.Sources[0].GeneratedFloatPools[0]
		pool.Definition = definition
		observation.Sources[0].GeneratedFloatPools = append(observation.Sources[0].GeneratedFloatPools, pool)
	}
}

func readonlyMixedMetadataGuards(t *testing.T, original *SDKASMDataObservation) {
	t.Helper()
	for name, change := range map[string]func(*SDKASMDataObservation){
		"missing-pool-metadata": func(o *SDKASMDataObservation) { o.Sources[0].GeneratedFloatPools = nil },
		"missing-FUNCDATA-metadata": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFuncdata = nil
		},
		"missing-all-metadata": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFloatPools, o.Sources[0].GeneratedFuncdata = nil, nil
		},
		"duplicate-pool": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFloatPools = append(o.Sources[0].GeneratedFloatPools, o.Sources[0].GeneratedFloatPools[0])
		},
		"duplicate-FUNCDATA": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFuncdata = append(o.Sources[0].GeneratedFuncdata, o.Sources[0].GeneratedFuncdata[0])
		},
		"missing-pool-owner": func(o *SDKASMDataObservation) { o.Sources[0].GeneratedFloatPools[0].Owners = nil },
		"missing-FUNCDATA-owner": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFuncdata[0].Owners = nil
		},
		"duplicate-pool-owner": func(o *SDKASMDataObservation) {
			pool := &o.Sources[0].GeneratedFloatPools[0]
			pool.Owners = append(pool.Owners, pool.Owners[0])
		},
		"duplicate-FUNCDATA-owner": func(o *SDKASMDataObservation) {
			metadata := &o.Sources[0].GeneratedFuncdata[0]
			metadata.Owners = append(metadata.Owners, metadata.Owners[0])
		},
		"pool-is-ordinary-layout": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFloatPools[0].Definition = o.Sources[0].ExpandedLayouts[0].Definition
		},
		"FUNCDATA-is-ordinary-layout": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFuncdata[0].Definition = o.Sources[0].ExpandedLayouts[0].Definition
		},
		"missing-source-TEXT": func(o *SDKASMDataObservation) { o.Sources[0].TextOrder = nil },
		"pool-definition-name": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFloatPools[0].Definition.Name += "forged"
		},
		"pool-definition-index": func(o *SDKASMDataObservation) { o.Sources[0].GeneratedFloatPools[0].Definition.Index++ },
		"pool-definition-namespace": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFloatPools[0].Definition.Namespace = TextSymbolSelf
		},
		"pool-IEEE": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataPoolDefinition(o, func(definition *ASMDataDefinition) { definition.Data[0] ^= 1 })
		},
		"pool-IEEE-and-matching-hash": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataPoolDefinition(o, func(definition *ASMDataDefinition) {
				definition.Data[0] ^= 1
				definition.Hash[0] ^= 1
			})
		},
		"pool-local-role": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataPoolDefinition(o, func(definition *ASMDataDefinition) { definition.Flags = 0 })
		},
		"pool-whole-hash": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataPoolDefinition(o, func(definition *ASMDataDefinition) { definition.Hash[0] ^= 1 })
		},
		"pool-whole-width": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataPoolDefinition(o, func(definition *ASMDataDefinition) { definition.Size = 8 })
		},
		"pool-whole-alignment": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataPoolDefinition(o, func(definition *ASMDataDefinition) { definition.Align = 8 })
		},
		"pool-whole-ABI": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataPoolDefinition(o, func(definition *ASMDataDefinition) { definition.ABI = 1 })
		},
		"pool-whole-kind": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataPoolDefinition(o, func(definition *ASMDataDefinition) { definition.Kind = 5 })
		},
		"pool-whole-flags2": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataPoolDefinition(o, func(definition *ASMDataDefinition) { definition.Flags2 = 1 })
		},
		"unknown-named-definition": func(o *SDKASMDataObservation) { readonlyMixedMetadataUnknown(o, "uncovered", false) },
		"unknown-float-prefix": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataUnknown(o, "$f32.00000001", false)
		},
		"unknown-FUNCDATA-prefix": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataUnknown(o, "gclocals·unproved", false)
		},
		"unknown-definition-with-forged-owner": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataUnknown(o, "$f32.80000000", true)
		},
		"extra-pool-TEXT-reference": func(o *SDKASMDataObservation) {
			relocation := o.Sources[0].GeneratedFloatPools[0].Owners[0].Relocation
			readonlyMixedMetadataMembers(o, func(member *ASMDataMember) {
				member.Texts[0].Relocations = append(member.Texts[0].Relocations, relocation)
			})
		},
		"extra-pool-auxiliary": func(o *SDKASMDataObservation) {
			ref := o.Sources[0].GeneratedFloatPools[0].Owners[0].Relocation.Target
			readonlyMixedMetadataMembers(o, func(member *ASMDataMember) {
				member.Texts[0].Auxiliary = append(member.Texts[0].Auxiliary, TextAuxiliary{Type: 2, Target: ref})
			})
		},
		"FUNCDATA-invalid-payload": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFuncdata[0].Definition.Data[0] ^= 1
		},
		"FUNCDATA-invalid-hash": func(o *SDKASMDataObservation) {
			o.Sources[0].GeneratedFuncdata[0].Definition.Hash[0] ^= 1
		},
		"FUNCDATA-whole-payload": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataDefinition(o, &o.Sources[0].GeneratedFuncdata[0].Definition,
				func(definition *ASMDataDefinition) { definition.Data[0] ^= 1 })
		},
		"FUNCDATA-whole-hash": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataDefinition(o, &o.Sources[0].GeneratedFuncdata[0].Definition,
				func(definition *ASMDataDefinition) { definition.Hash[0] ^= 1 })
		},
		"FUNCDATA-whole-role": func(o *SDKASMDataObservation) {
			readonlyMixedMetadataDefinition(o, &o.Sources[0].GeneratedFuncdata[0].Definition,
				func(definition *ASMDataDefinition) { definition.Flags = 0 })
		},
		"FUNCDATA-extra-TEXT-reference": func(o *SDKASMDataObservation) {
			definition := o.Sources[0].GeneratedFuncdata[0].Definition
			readonlyMixedMetadataMembers(o, func(member *ASMDataMember) {
				member.Texts[0].Relocations = append(member.Texts[0].Relocations, TextRelocation{Offset: 0, Size: 4, Type: 1,
					Target: TextReference{PackageIndex: 2147483645, SymbolIndex: definition.Relative, Name: definition.Name, ABIKnown: true}})
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			observation := readonlyLiteralClone(t, original)
			change(observation)
			if images, err := ReadonlyLiteralDataInitializers(observation); !errors.Is(err, ErrContext) || images != nil {
				t.Fatal("unproved or forged metadata hid an uncovered named DATA definition", images, err)
			}
		})
	}
	readonlyMixedMetadataOwnerGuards(t, original)
}

func readonlyMixedMetadataOwnerGuards(t *testing.T, original *SDKASMDataObservation) {
	t.Helper()
	for name, change := range map[string]func(*ASMGeneratedFloatPoolOwner){
		"statement":          func(owner *ASMGeneratedFloatPoolOwner) { owner.StatementOrdinal = -1 },
		"source-TEXT":        func(owner *ASMGeneratedFloatPoolOwner) { owner.TextSourceOrdinal++ },
		"object-TEXT":        func(owner *ASMGeneratedFloatPoolOwner) { owner.TextObjectOrdinal++ },
		"TEXT-namespace":     func(owner *ASMGeneratedFloatPoolOwner) { owner.TextNamespace = TextSymbolSelf },
		"TEXT-relative":      func(owner *ASMGeneratedFloatPoolOwner) { owner.TextRelative++ },
		"TEXT-index":         func(owner *ASMGeneratedFloatPoolOwner) { owner.TextIndex++ },
		"non-FCONST-opcode":  func(owner *ASMGeneratedFloatPoolOwner) { owner.Opcode = "MOVL" },
		"original-IEEE":      func(owner *ASMGeneratedFloatPoolOwner) { owner.SourceFloat64Bits = 0 },
		"relocation-ordinal": func(owner *ASMGeneratedFloatPoolOwner) { owner.RelocationOrdinal++ },
		"relocation-offset":  func(owner *ASMGeneratedFloatPoolOwner) { owner.Relocation.Offset++ },
		"relocation-width":   func(owner *ASMGeneratedFloatPoolOwner) { owner.Relocation.Size = 1 },
		"relocation-target":  func(owner *ASMGeneratedFloatPoolOwner) { owner.Relocation.Target.SymbolIndex++ },
	} {
		t.Run("pool-owner-"+name, func(t *testing.T) {
			observation := readonlyLiteralClone(t, original)
			change(&observation.Sources[0].GeneratedFloatPools[0].Owners[0])
			if images, err := ReadonlyLiteralDataInitializers(observation); !errors.Is(err, ErrContext) || images != nil {
				t.Fatal("forged pool source/TEXT/relocation owner bypassed complete inventory", images, err)
			}
		})
	}
	for name, change := range map[string]func(*ASMGeneratedFuncdataOwner){
		"statement":      func(owner *ASMGeneratedFuncdataOwner) { owner.StatementOrdinal = -1 },
		"source-TEXT":    func(owner *ASMGeneratedFuncdataOwner) { owner.TextSourceOrdinal++ },
		"object-TEXT":    func(owner *ASMGeneratedFuncdataOwner) { owner.TextObjectOrdinal++ },
		"TEXT-namespace": func(owner *ASMGeneratedFuncdataOwner) { owner.TextNamespace = TextSymbolSelf },
		"TEXT-relative":  func(owner *ASMGeneratedFuncdataOwner) { owner.TextRelative++ },
		"TEXT-index":     func(owner *ASMGeneratedFuncdataOwner) { owner.TextIndex++ },
		"auxiliary-slot": func(owner *ASMGeneratedFuncdataOwner) { owner.Slot = 0 },
	} {
		t.Run("FUNCDATA-owner-"+name, func(t *testing.T) {
			observation := readonlyLiteralClone(t, original)
			change(&observation.Sources[0].GeneratedFuncdata[0].Owners[0])
			if images, err := ReadonlyLiteralDataInitializers(observation); !errors.Is(err, ErrContext) || images != nil {
				t.Fatal("forged FUNCDATA source/TEXT/auxiliary owner bypassed complete inventory", images, err)
			}
		})
	}
}
