package gostaticstorage

// ASMSourceText associates one source TEXT ordinal with its unchanged physical
// goobj record. It is diagnostic metadata, never native entry/call/result or
// storage authority. ObjectOrdinal indexes Member.Texts, not source order.
type ASMSourceText struct {
	SourceOrdinal, ObjectOrdinal int
	Name                         string
	ABI                          uint16
	Namespace                    TextSymbolNamespace
	Relative, Index              uint32
}

// ASMSourceTextOrder retains the actual assembler's namespace/index ordering
// while checking a complete one-to-one source association. Go NumberSyms puts
// static ASM definitions in Self and all nonstatic ASM definitions in Nonpkg;
// it preserves declaration order inside each bank, not across the banks.
// Linkshared/content-addressable TEXT needs a separate observed source role.
func ASMSourceTextOrder(source []byte, packagePath string, member ASMDataMember) ([]ASMSourceText, error) {
	statements, err := asmDataStatements(source)
	if err != nil {
		return nil, err
	}
	type key struct {
		name string
		abi  uint16
		ns   TextSymbolNamespace
	}
	var names []key
	for _, statement := range statements {
		if statement[0].text != "TEXT" {
			continue
		}
		operands := asmDataOperands(statement[1:])
		if len(operands) != 2 && len(operands) != 3 {
			return nil, contextError("source TEXT declaration has an invalid operand inventory")
		}
		symbol, err := asmDataSymbol(operands[0], packagePath)
		if err != nil || symbol.Addend != 0 {
			return nil, contextError("source TEXT declaration lacks its exact symbol/ABI")
		}
		namespace := TextSymbolNonpkgDefinition
		if symbol.Static {
			namespace = TextSymbolSelf
		}
		names = append(names, key{symbol.Name, symbol.ABI, namespace})
	}
	if len(names) != len(member.Texts) {
		return nil, contextError("source TEXT declaration inventory differs from the complete actual object")
	}
	if len(names) == 0 {
		return nil, nil
	}
	if member.Flags&4 == 0 {
		return nil, contextError("source TEXT association requires an actual assembler object role")
	}
	physical := make(map[key]int, len(names))
	indices := make(map[uint32]bool, len(names))
	var previous TextRecord
	for ordinal, record := range member.Texts {
		if record.Name == "" || !currentSDKObjectIsText(record.Kind) ||
			record.Namespace != TextSymbolSelf && record.Namespace != TextSymbolNonpkgDefinition ||
			record.Namespace == TextSymbolSelf && (record.ABI != 65535 || record.Index != record.Relative) ||
			record.Namespace == TextSymbolNonpkgDefinition && record.ABI != 0 && record.ABI != 1 ||
			record.Index < record.Relative || indices[record.Index] {
			return nil, contextError("source TEXT has an unknown/duplicate physical symbol role")
		}
		if ordinal != 0 && (record.Index <= previous.Index || record.Namespace < previous.Namespace ||
			record.Namespace == previous.Namespace && (record.Relative <= previous.Relative ||
				record.Index-record.Relative != previous.Index-previous.Relative)) {
			return nil, contextError("source TEXT physical namespace/index order differs")
		}
		identity := key{record.Name, record.ABI, record.Namespace}
		if _, duplicate := physical[identity]; duplicate {
			return nil, contextError("source TEXT has duplicate symbol/ABI/namespace identities")
		}
		physical[identity], indices[record.Index], previous = ordinal, true, record
	}
	result := make([]ASMSourceText, len(names))
	used := make(map[int]bool, len(names))
	last := make(map[TextSymbolNamespace]int)
	for ordinal, identity := range names {
		objectOrdinal, found := physical[identity]
		prior, hasPrior := last[identity.ns]
		if !found || used[objectOrdinal] || hasPrior && objectOrdinal <= prior {
			return nil, contextError("source TEXT symbol/ABI/namespace/ordinal differs from the exact original body")
		}
		record := member.Texts[objectOrdinal]
		result[ordinal] = ASMSourceText{SourceOrdinal: ordinal, ObjectOrdinal: objectOrdinal,
			Name: record.Name, ABI: record.ABI, Namespace: record.Namespace, Relative: record.Relative, Index: record.Index}
		used[objectOrdinal], last[identity.ns] = true, objectOrdinal
	}
	return result, nil
}
