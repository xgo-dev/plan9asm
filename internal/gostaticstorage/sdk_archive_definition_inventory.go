package gostaticstorage

import (
	"encoding/binary"
	"sort"
)

// SDKArchiveDefinitionIdentity is an offline object-local record. In particular,
// equal names, bytes or hashes do not select a linked winner or mint a role.
type SDKArchiveDefinitionIdentity struct {
	PackagePath, MemberName string
	MemberOrdinal           int
	Namespace               TextSymbolNamespace
	Index                   uint32
	Name                    string
	ABI                     uint16
	Kind, Flags, Flags2     uint8
	Size, Align             uint32
}

// SDKArchiveDefinitionInventory retains every named definition in every actual
// selected archive member. A live linker producer separately authenticates the
// complete source graph, archives, tool route, command profile and linked image.
func SDKArchiveDefinitionInventory(archives map[string]SDKReferencedArchive, target string) ([]SDKArchiveDefinitionIdentity, error) {
	if !X86SDKTarget(target) {
		return nil, contextError("definition inventory has an unobserved SDK target")
	}
	// Reuse the complete exact header/member/index grammar and shared aggregate
	// archive bounds, rather than interpreting another permissive object format.
	if _, err := sdkReferencedArchiveSymbols(archives, target); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(archives))
	for path := range archives {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var result []SDKArchiveDefinitionIdentity
	for _, path := range paths {
		members, err := archiveMembers(archives[path].Archive)
		if err != nil {
			return nil, err
		}
		for ordinal, member := range members[1:] {
			flags, reader := sdkCompilerObjectFlags(target), sdkObjectBody
			if ordinal != 0 {
				flags, reader = flags|4, objectBody
			}
			body, err := reader(member.data, target)
			if err != nil {
				return nil, err
			}
			object, err := checkedSDKIndexedMetadata(body, flags, ordinal != 0)
			if err != nil {
				return nil, err
			}
			symbols, err := sdkMetadataDefinitionInventory(object)
			if err != nil {
				return nil, err
			}
			for _, symbol := range symbols {
				if symbol.Name == "" || symbol.Namespace == TextSymbolNonpkgReference {
					continue
				}
				result = append(result, SDKArchiveDefinitionIdentity{PackagePath: path,
					MemberName: member.name, MemberOrdinal: ordinal + 1,
					Namespace: symbol.Namespace, Index: symbol.Index, Name: symbol.Name,
					ABI: symbol.ABI, Kind: symbol.Kind, Flags: symbol.Flags, Flags2: symbol.Flags2,
					Size: symbol.Size, Align: symbol.Align})
			}
		}
	}
	return result, nil
}

// This is an ambiguity inventory, not storageSymbols(cpu): observing that a
// namespace exists does not give its objects the pinned CPU/global role.
func sdkMetadataDefinitionInventory(object *sdkIndexedMetadataObject) ([]indexedObjectSymbol, error) {
	var result []indexedObjectSymbol
	base := uint32(0)
	for group, namespace := range []TextSymbolNamespace{TextSymbolSelf, TextSymbolHashed64, TextSymbolHashed, TextSymbolNonpkgDefinition} {
		block := object.block(group + 3)
		for offset := 0; offset < len(block); offset += 21 {
			raw := block[offset : offset+21]
			name, err := object.stringAt(raw)
			if err != nil {
				return nil, err
			}
			relative := uint32(offset / 21)
			result = append(result, indexedObjectSymbol{Namespace: namespace, Relative: relative, Index: base + relative, Name: name,
				ABI: binary.LittleEndian.Uint16(raw[8:]), Kind: raw[10], Flags: raw[11], Flags2: raw[12],
				Size: binary.LittleEndian.Uint32(raw[13:]), Align: binary.LittleEndian.Uint32(raw[17:])})
		}
		base += uint32(len(block) / 21)
	}
	return result, nil
}
