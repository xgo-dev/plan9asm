package gostaticstorage

type asmDataStorageIdentity struct {
	name string
	abi  uint16
}

type asmDataStorageExtent struct {
	asmDataStorageIdentity
	size uint32
}

func asmDataCompilerBSSDeclaration(member ASMDataMember, definition ASMDataDefinition) bool {
	return member.Name == "_go_.o" && definition.Namespace == TextSymbolSelf &&
		definition.ABI != 65535 && (definition.Kind == 9 || definition.Kind == 10) &&
		definition.Flags&1 == 0 && definition.Size > 0 &&
		len(definition.Data) == 0 && len(definition.Relocations) == 0
}

func asmDataAssemblyInitializer(member ASMDataMember, definition ASMDataDefinition) bool {
	kind := asmDataBaseKind(definition.Kind)
	// The enclosing SDK archive reader authenticates the exact selected member
	// names, including their byte truncation. A suffix is not an origin proof.
	return member.Name != "" && member.Name != "_go_.o" && member.Name != "__.PKGDEF" &&
		definition.Namespace == TextSymbolNonpkgDefinition && definition.ABI != 65535 &&
		definition.Flags&1 == 0 && (kind == 3 || kind == 5 || kind == 7) &&
		definition.Size > 0 && len(definition.Data) > 0 && uint64(len(definition.Data)) <= uint64(definition.Size)
}

// Go can declare storage without an initializer and define it in ASM. The
// linker admits this empty-BSS/content pair before diagnosing duplicate bodies.
// Classify only the exact observed pair; neither record is rewritten/removed,
// and no winning body, numerical bytes or storage permission is returned.
func asmDataCompilerDeclarationPairs(members []ASMDataMember) map[asmDataStorageExtent]bool {
	initializers := make(map[asmDataStorageExtent]bool)
	declarations := make(map[asmDataStorageIdentity]int)
	var candidates []asmDataStorageExtent
	for _, member := range members {
		for _, definition := range member.Definitions {
			identity := asmDataStorageIdentity{definition.Name, definition.ABI}
			extent := asmDataStorageExtent{identity, definition.Size}
			if asmDataAssemblyInitializer(member, definition) {
				initializers[extent] = true
			}
			if asmDataCompilerBSSDeclaration(member, definition) {
				declarations[identity]++
				candidates = append(candidates, extent)
			}
		}
	}
	result := make(map[asmDataStorageExtent]bool)
	for _, candidate := range candidates {
		if declarations[candidate.asmDataStorageIdentity] == 1 && initializers[candidate] {
			result[candidate] = true
		}
	}
	return result
}
