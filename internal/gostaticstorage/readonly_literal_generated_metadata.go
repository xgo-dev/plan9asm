package gostaticstorage

import (
	"fmt"
	"math"
	"reflect"
	"sort"
)

// Generated metadata explains whole-object inventory, not initialized storage.
// Validate mutable records again before the planner accounts for them. The live
// factory's independent source/tool association remains a separate authority.
func readonlyGeneratedMetadata(source ASMDataSourceObservation, target string) ([]ASMDataDefinition, error) {
	if len(source.GeneratedFloatPools) == 0 && len(source.GeneratedFuncdata) == 0 {
		return nil, nil
	}
	member := source.Expanded
	if len(source.TextOrder) != len(member.Texts) || len(source.TextOrder) == 0 || len(source.TextOrder) > symbolLimit ||
		len(source.GeneratedFuncdata) > 1 || len(source.GeneratedFloatPools)+len(source.GeneratedFuncdata) > len(member.Definitions) {
		return nil, contextError("readonly metadata lacks its complete source/TEXT inventory")
	}
	seenTexts := make(map[int]bool, len(source.TextOrder))
	for ordinal, owner := range source.TextOrder {
		if owner.SourceOrdinal != ordinal || owner.ObjectOrdinal < 0 || owner.ObjectOrdinal >= len(member.Texts) || seenTexts[owner.ObjectOrdinal] {
			return nil, contextError("readonly metadata source/TEXT order changed")
		}
		text := member.Texts[owner.ObjectOrdinal]
		if owner.Name != text.Name || owner.ABI != text.ABI || owner.Namespace != text.Namespace ||
			owner.Relative != text.Relative || owner.Index != text.Index {
			return nil, contextError("readonly metadata source/TEXT identity changed")
		}
		seenTexts[owner.ObjectOrdinal] = true
	}
	statements := make(map[int]bool)
	definitions, err := readonlyGeneratedFloatPools(source, target, statements)
	if err != nil {
		return nil, err
	}
	for _, metadata := range source.GeneratedFuncdata {
		if !validGeneratedLocalsDefinition(metadata.Definition) || len(metadata.Owners) == 0 || len(metadata.Owners) > len(member.Texts) {
			return nil, contextError("readonly FUNCDATA metadata definition/payload/hash/owners changed")
		}
		owners := make(map[int]bool, len(metadata.Owners))
		for _, owner := range metadata.Owners {
			if !readonlyMetadataStatement(statements, owner.StatementOrdinal, owner.TextSourceOrdinal) ||
				!readonlyMetadataTextOwner(source.TextOrder, owner.TextSourceOrdinal, owner.TextObjectOrdinal,
					owner.TextNamespace, owner.TextRelative, owner.TextIndex) || owner.Slot != 1 || owners[owner.TextObjectOrdinal] {
				return nil, contextError("readonly FUNCDATA metadata source/TEXT/slot owner changed")
			}
			ref, found := generatedFuncdataSlot(member.Texts[owner.TextObjectOrdinal], owner.Slot)
			if !found || !generatedFuncdataReference(metadata.Definition, ref) {
				return nil, contextError("readonly FUNCDATA metadata lost its actual auxiliary identity")
			}
			owners[owner.TextObjectOrdinal] = true
		}
		if err := validateGeneratedFuncdataReferences(member, metadata.Definition, owners); err != nil {
			return nil, err
		}
		definitions = append(definitions, metadata.Definition)
	}
	return definitions, nil
}

func readonlyMetadataTextOwner(order []ASMSourceText, source, object int, namespace TextSymbolNamespace, relative, index uint32) bool {
	if source < 0 || source >= len(order) {
		return false
	}
	text := order[source]
	return text.ObjectOrdinal == object && text.Namespace == namespace && text.Relative == relative && text.Index == index
}

func readonlyMetadataStatement(used map[int]bool, statement, textSource int) bool {
	if statement <= textSource || statement >= symbolLimit || used[statement] {
		return false
	}
	used[statement] = true
	return true
}

func readonlyGeneratedFloatPools(source ASMDataSourceObservation, target string, statements map[int]bool) ([]ASMDataDefinition, error) {
	if len(source.GeneratedFloatPools) == 0 {
		return nil, nil
	}
	member := source.Expanded
	// Reconstruct only the existing relocation-owner inventory. Neither an
	// assembler nor a new source parser is needed by this pure image planner.
	replay := make([]ASMGeneratedFloatPool, len(source.GeneratedFloatPools))
	uses := make([][]asmGeneratedFloatPoolUse, len(member.Texts))
	byName := make(map[string]int, len(replay))
	var definitions []ASMDataDefinition
	totalOwners := 0
	for ordinal, pool := range source.GeneratedFloatPools {
		if len(pool.Owners) == 0 || len(pool.Owners) > symbolLimit-totalOwners {
			return nil, contextError("readonly float-pool metadata has no bounded actual source owners")
		}
		totalOwners += len(pool.Owners)
		if _, duplicate := byName[pool.Definition.Name]; duplicate {
			return nil, contextError("readonly float-pool metadata repeats a definition")
		}
		byName[pool.Definition.Name] = ordinal
		replay[ordinal].Definition = pool.Definition
		for _, owner := range pool.Owners {
			form, known := asmGeneratedFloatPoolForms[owner.Opcode]
			if !known || !readonlyMetadataStatement(statements, owner.StatementOrdinal, owner.TextSourceOrdinal) ||
				!readonlyMetadataTextOwner(source.TextOrder, owner.TextSourceOrdinal, owner.TextObjectOrdinal,
					owner.TextNamespace, owner.TextRelative, owner.TextIndex) {
				return nil, contextError("readonly float-pool metadata source/TEXT/opcode owner changed")
			}
			value := math.Float64frombits(owner.SourceFloat64Bits)
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return nil, contextError("readonly float-pool original FCONST is not a finite float64 token")
			}
			bits := owner.SourceFloat64Bits
			if form.width == 4 {
				bits = uint64(math.Float32bits(float32(value)))
			}
			name := fmt.Sprintf("$f%d.%0*x", form.width*8, form.width*2, bits)
			if pool.Definition.Name != name || !validGeneratedFloatPoolDefinition(pool.Definition, form.width, bits, target) {
				return nil, contextError("readonly float-pool metadata IEEE/name/namespace/attributes/hash changed")
			}
			text := member.Texts[owner.TextObjectOrdinal]
			if owner.RelocationOrdinal < 0 || owner.RelocationOrdinal >= len(text.Relocations) ||
				!reflect.DeepEqual(owner.Relocation, text.Relocations[owner.RelocationOrdinal]) {
				return nil, contextError("readonly float-pool metadata lost its actual relocation identity")
			}
			uses[owner.TextObjectOrdinal] = append(uses[owner.TextObjectOrdinal], asmGeneratedFloatPoolUse{owner: owner, pool: ordinal})
		}
		definitions = append(definitions, pool.Definition)
	}
	for _, textUses := range uses {
		sort.Slice(textUses, func(i, j int) bool { return textUses[i].owner.StatementOrdinal < textUses[j].owner.StatementOrdinal })
	}
	if err := joinGeneratedFloatPoolOwners(member, replay, byName, uses, target); err != nil {
		return nil, err
	}
	if !sameGeneratedFloatPools(source.GeneratedFloatPools, replay) {
		return nil, contextError("readonly float-pool complete relocation owners differ")
	}
	return definitions, nil
}
