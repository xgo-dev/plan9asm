package gostaticstorage

import "strings"

func generatedFloatPoolReference(definition ASMDataDefinition, ref TextReference) bool {
	return ref.PackageIndex == 2147483646 && ref.SymbolIndex == definition.Relative &&
		ref.Name == definition.Name && ref.ABIKnown && ref.ABI == definition.ABI && (!ref.KindKnown || ref.Kind == definition.Kind)
}

// Source order selects actual pool relocations inside each independently
// associated TEXT. Do not infer a producer from a name or search another TEXT
// for convenient matching bytes. Every pool relocation must have one owner.
func joinGeneratedFloatPoolOwners(member ASMDataMember, pools []ASMGeneratedFloatPool, byName map[string]int, uses [][]asmGeneratedFloatPoolUse, target string) error {
	relocationType := uint16(14) // Actual x86-64 R_PCREL; 386 uses R_ADDR.
	if strings.HasSuffix(target, "/386") {
		relocationType = 1
	}
	byRelative := make(map[uint32]int, len(pools))
	for ordinal, pool := range pools {
		byRelative[pool.Definition.Relative] = ordinal
	}
	associated := func(ref TextReference) bool {
		_, named := byName[ref.Name]
		_, indexed := byRelative[ref.SymbolIndex]
		return named || ref.PackageIndex == 2147483646 && indexed
	}
	for ordinal, text := range member.Texts {
		use, position := 0, 0
		lastEnd := int64(0)
		for relocationOrdinal, relocation := range text.Relocations {
			if !associated(relocation.Target) {
				continue
			}
			if use >= len(uses[ordinal]) {
				return contextError("generated float pool has an extra ordinary TEXT reference without a source FCONST")
			}
			expected := uses[ordinal][use]
			definition := pools[expected.pool].Definition
			if !generatedFloatPoolReference(definition, relocation.Target) || relocation.Type != relocationType ||
				relocation.Size != 4 || relocation.Add != 0 || relocation.Offset < lastEnd ||
				relocation.Offset > text.Size-relocation.Size {
				return contextError("generated float pool source and actual object-local relocation differ")
			}
			end := relocation.Offset + relocation.Size
			for position < len(text.Positions) && text.Positions[position].End <= relocation.Offset {
				position++
			}
			if position == len(text.Positions) || text.Positions[position].Start > relocation.Offset ||
				text.Positions[position].End < end || text.Positions[position].File == "" || text.Positions[position].Line <= 0 {
				return contextError("generated float pool relocation crosses its actual source-PC interval")
			}
			expected.owner.RelocationOrdinal, expected.owner.Relocation = relocationOrdinal, relocation
			pools[expected.pool].Owners = append(pools[expected.pool].Owners, expected.owner)
			use++
			lastEnd = end
		}
		if use != len(uses[ordinal]) {
			return contextError("generated float pool source has no corresponding actual TEXT relocation")
		}
		for _, auxiliary := range text.Auxiliary {
			if associated(auxiliary.Target) {
				return contextError("generated float pool is an unassociated TEXT auxiliary target")
			}
		}
	}
	for _, definition := range member.Definitions {
		for _, relocation := range definition.Relocations {
			if associated(relocation.Target) {
				return contextError("generated float pool is an ordinary DATA relocation target")
			}
		}
	}
	return nil
}
