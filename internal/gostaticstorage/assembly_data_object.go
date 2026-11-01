package gostaticstorage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
)

func observeASMDataObject(data, builtin []byte, target string, flags uint32, referenced sdkReferencedSymbols) (ASMDataMember, error) {
	var member ASMDataMember
	builtins, err := textBuiltins(builtin)
	if err != nil {
		return member, err
	}
	reader := objectBody
	if flags&16 != 0 && flags&4 == 0 {
		reader = sdkObjectBody
	}
	body, err := reader(data, target)
	if err != nil {
		return member, err
	}
	member.ObjectOffset = int64(len(data) - len(body))
	object, err := checkedSDKObject(body, flags, flags&4 != 0)
	if err != nil {
		return member, err
	}
	// TEXT validates every reference, relocation and auxiliary record, including
	// unused ones. It retains all original bodies rather than choosing by name.
	member.Texts, err = readCheckedTextObjectKinds(object, target, builtins, referenced, true)
	if err != nil {
		return member, err
	}
	symbols, err := object.indexedSymbols()
	if err != nil {
		return member, err
	}
	resolve, _, err := objectReferenceResolver(object, builtins, referenced)
	if err != nil {
		return member, err
	}
	member.Flags = flags
	for _, symbol := range symbols {
		if symbol.Namespace == TextSymbolNonpkgReference || currentSDKObjectIsText(symbol.Kind) {
			continue
		}
		index := int(symbol.Index)
		start, end := object.indices[2][index], object.indices[2][index+1]
		dataBytes := append([]byte(nil), object.block(16)[start:end]...)
		value := ASMDataDefinition{Namespace: symbol.Namespace, Relative: symbol.Relative, Index: symbol.Index,
			Name: symbol.Name, ABI: symbol.ABI, Kind: symbol.Kind, Flags: symbol.Flags, Flags2: symbol.Flags2,
			Size: symbol.Size, Align: symbol.Align, Hash: append([]byte(nil), symbol.Hash...),
			DataOffset: binary.LittleEndian.Uint32(body[20+16*4:]) + start, Data: dataBytes}
		for ordinal := object.indices[0][index]; ordinal < object.indices[0][index+1]; ordinal++ {
			raw := object.block(14)[int(ordinal)*23 : (int(ordinal)+1)*23]
			target, err := resolve(raw[15:])
			if err != nil {
				return member, err
			}
			relocation := TextRelocation{Offset: int64(int32(binary.LittleEndian.Uint32(raw))), Size: int64(raw[4]),
				Type: binary.LittleEndian.Uint16(raw[5:]), Add: int64(binary.LittleEndian.Uint64(raw[7:])), Target: target}
			if relocation.Offset < 0 || relocation.Size > int64(len(value.Data)) || relocation.Offset > int64(len(value.Data))-relocation.Size {
				return member, contextError("DATA physical relocation exceeds its actual written data")
			}
			value.Relocations = append(value.Relocations, relocation)
		}
		member.Definitions = append(member.Definitions, value)
	}
	return member, nil
}

func asmDataBaseKind(kind uint8) uint8 {
	switch kind {
	case 4: // SRODATAFIPS.
		return 3
	case 6: // SNOPTRDATAFIPS.
		return 5
	case 8: // SDATAFIPS.
		return 7
	}
	return kind
}

func validateASMDataArchiveNames(members []ASMDataMember) error {
	declarationPairs := asmDataCompilerDeclarationPairs(members)
	type abiGroup struct {
		// The value records whether this member's definitions use the
		// linker-visible nonpackage namespace, rather than package-local Self.
		members      map[int]bool
		nonDuplicate bool
	}
	type definitionIndex struct {
		group    *abiGroup
		member   int
		index    uint32
		relative bool
	}
	type namedGroup struct {
		kind       uint8
		storageABI uint16
		abis       map[uint16]*abiGroup
	}
	seen := make(map[string]*namedGroup)
	var nonpackageIndices map[definitionIndex]bool
	observe := func(name string, abi uint16, namespace TextSymbolNamespace, kind, flags uint8, member int, index, relative uint32) error {
		if name == "" || abi == 65535 || namespace == TextSymbolHashed64 || namespace == TextSymbolHashed {
			return nil
		}
		kind = asmDataBaseKind(kind)
		group := seen[name]
		if group == nil {
			group = &namedGroup{kind: kind, storageABI: abi, abis: make(map[uint16]*abiGroup)}
			seen[name] = group
		}
		if group.kind != kind {
			return contextError(fmt.Sprintf("SDK ASM DATA named definition collides with a different TEXT/storage kind: name=%q previous-kind=%d kind=%d ABI=%d namespace=%d member=%d index=%d",
				name, group.kind, kind, abi, namespace, member, index))
		}
		if !currentSDKObjectIsText(kind) && group.storageABI != abi {
			return contextError("SDK ASM DATA named storage has multiple ABI identities")
		}
		identities := group.abis[abi]
		if identities == nil {
			identities = &abiGroup{members: make(map[int]bool)}
			group.abis[abi] = identities
		}
		duplicate := flags&1 != 0
		previousNonpackage, sameMember := identities.members[member]
		nonpackage := namespace == TextSymbolNonpkgDefinition
		if sameMember && !(previousNonpackage && nonpackage) || !duplicate && identities.nonDuplicate {
			return contextError(fmt.Sprintf("SDK ASM DATA named definition has an ambiguous non-DUPok body: name=%q ABI=%d namespace=%d member=%d same-member=%t previous-non-DUPok=%t flags=%#x",
				name, abi, namespace, member, sameMember, identities.nonDuplicate, flags))
		}
		if nonpackage {
			// Keep every object-local identity. DUPok permits several original
			// definitions; it never permits replaying the same index twice or
			// selecting one body by its name or equal data bytes.
			if nonpackageIndices == nil {
				nonpackageIndices = make(map[definitionIndex]bool)
			}
			combined := definitionIndex{group: identities, member: member, index: index}
			local := definitionIndex{group: identities, member: member, index: relative, relative: true}
			if nonpackageIndices[combined] || nonpackageIndices[local] {
				return contextError("SDK ASM DATA named definition repeats an original nonpackage index: " + name)
			}
			nonpackageIndices[combined], nonpackageIndices[local] = true, true
		}
		identities.members[member] = nonpackage
		identities.nonDuplicate = identities.nonDuplicate || !duplicate
		// Only aggregate collision facts, never a winning body. All original
		// member/namespace/index identities remain in the returned observation.
		return nil
	}
	for ordinal, member := range members {
		for _, definition := range member.Definitions {
			if asmDataCompilerBSSDeclaration(member, definition) &&
				declarationPairs[asmDataStorageExtent{asmDataStorageIdentity{definition.Name, definition.ABI}, definition.Size}] {
				continue // Preserve the original record; it is not a second initialized body.
			}
			if err := observe(definition.Name, definition.ABI, definition.Namespace, definition.Kind, definition.Flags, ordinal, definition.Index, definition.Relative); err != nil {
				return err
			}
		}
		for _, text := range member.Texts {
			if err := observe(text.Name, text.ABI, text.Namespace, text.Kind, text.Flags, ordinal, text.Index, text.Relative); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinASMDataLayouts(states []asmDataLayoutState, member ASMDataMember) ([]ASMGlobalLayout, error) {
	type candidateKey struct {
		name string
		abi  uint16
	}
	candidates := make(map[candidateKey][]int, len(member.Definitions))
	for index, definition := range member.Definitions {
		key := candidateKey{definition.Name, definition.ABI}
		candidates[key] = append(candidates[key], index)
	}
	used := make(map[uint32]bool)
	lastRelative := make(map[TextSymbolNamespace]uint32)
	layouts := make([]ASMGlobalLayout, 0, len(states))
	for _, state := range states {
		indices := candidates[candidateKey{state.layout.Name, state.layout.ABI}]
		// The name/ABI identifies candidate membership only. An ambiguous object
		// never selects a body by hash, bytes or a convenient storage namespace.
		if len(indices) != 1 || used[member.Definitions[indices[0]].Index] {
			return nil, contextError("source GLOBL lacks one unique object-local DATA definition")
		}
		definition := member.Definitions[indices[0]]
		if previous, present := lastRelative[definition.Namespace]; present && definition.Relative <= previous {
			return nil, contextError("source GLOBL order differs from its actual object-local namespace order")
		}
		lastRelative[definition.Namespace] = definition.Relative
		used[definition.Index] = true
		if asmDataBaseKind(definition.Kind) != state.kind || int64(definition.Size) != state.actualSize ||
			!bytes.Equal(definition.Data, state.data) || (definition.Flags&1 != 0) != (state.layout.Flags&2 != 0) ||
			len(definition.Relocations) != len(state.addresses) {
			return nil, contextError("source DATA/GLOBL bytes, size, flags or relocation inventory differs from the actual object")
		}
		for ordinal, fragment := range state.addresses {
			relocation := definition.Relocations[ordinal]
			address := fragment.Address
			if relocation.Offset != fragment.Offset || relocation.Size != fragment.Width || relocation.Type != 1 ||
				relocation.Add != address.Addend || relocation.Target.Name != address.Name || !relocation.Target.ABIKnown || relocation.Target.ABI != address.ABI {
				return nil, contextError("source address fragment differs from its exact ordered actual R_ADDR")
			}
		}
		layout := state.layout
		layout.Definition = definition
		layouts = append(layouts, layout)
	}
	for _, definition := range member.Definitions {
		if definition.Name != "" && asmDataBaseKind(definition.Kind) >= 3 && asmDataBaseKind(definition.Kind) <= 11 && !used[definition.Index] {
			return nil, contextError("actual assembly DATA definition is missing from the whole source inventory")
		}
	}
	return layouts, nil
}

// Whole anonymous definitions are compared too: they cannot hide unconsumed
// DATA bytes or relocations. Physical source-file positions are retained in
// both observations; line-preserving inputs must otherwise agree exactly.
func sameASMDataObjects(first, second ASMDataMember) bool {
	filter := func(member ASMDataMember) ASMDataMember {
		member.Name, member.NameBytes, member.Ordinal, member.Offset, member.Size, member.ObjectOffset = "", nil, 0, 0, 0, 0
		definitions := make([]ASMDataDefinition, 0, len(member.Definitions))
		for _, definition := range member.Definitions {
			definition.DataOffset = 0
			definitions = append(definitions, definition)
		}
		member.Definitions = definitions
		member.Texts = append([]TextRecord(nil), member.Texts...)
		for index := range member.Texts {
			member.Texts[index].Positions, member.Texts[index].PCFile, member.Texts[index].PCLine = nil, nil, nil
		}
		return member
	}
	return reflect.DeepEqual(filter(first), filter(second))
}
