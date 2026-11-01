package gostaticstorage

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"reflect"
	"strconv"
	"strings"
)

// ASMGeneratedFuncdata is an actual assembler-created metadata association.
// It is never an ASMGlobalLayout, literal, readable storage, GC-correctness,
// native-entry or numerical permission.
type ASMGeneratedFuncdata struct {
	Definition ASMDataDefinition
	Owners     []ASMGeneratedFuncdataOwner
}

type ASMGeneratedFuncdataOwner struct {
	StatementOrdinal, TextSourceOrdinal, TextObjectOrdinal int
	Slot                                                   int
	TextNamespace                                          TextSymbolNamespace
	TextRelative, TextIndex                                uint32
}

func generatedASMFuncdata(source []byte, packagePath string, member ASMDataMember) ([]ASMGeneratedFuncdata, error) {
	if !bytes.Contains(source, []byte("no_pointers_stackmap")) {
		return nil, nil
	}
	texts, err := ASMSourceTextOrder(source, packagePath, member)
	if err != nil {
		return nil, err
	}
	return generatedASMFuncdataWithTextOrder(source, packagePath, member, texts)
}

func generatedASMFuncdataWithTextOrder(source []byte, packagePath string, member ASMDataMember, texts []ASMSourceText) ([]ASMGeneratedFuncdata, error) {
	if !bytes.Contains(source, []byte("no_pointers_stackmap")) {
		return nil, nil // No additional parser/query cost for unrelated sources.
	}
	statements, err := asmDataStatements(source)
	if err != nil {
		return nil, err
	}
	if len(texts) != len(member.Texts) || member.Flags&4 == 0 {
		return nil, contextError("generated FUNCDATA lacks the complete actual source/TEXT order")
	}
	definitionsByRelative := make(map[uint32][]ASMDataDefinition)
	for _, definition := range member.Definitions {
		if definition.Namespace == TextSymbolHashed {
			definitionsByRelative[definition.Relative] = append(definitionsByRelative[definition.Relative], definition)
		}
	}
	var metadata *ASMGeneratedFuncdata
	owners := make(map[int]bool)
	seenTexts := make(map[int]bool, len(texts))
	textOrdinal := -1
	for ordinal, statement := range statements {
		if statement[0].text == "TEXT" {
			textOrdinal++
			if textOrdinal >= len(texts) {
				return nil, contextError("generated FUNCDATA source has an unassociated TEXT")
			}
			owner := texts[textOrdinal]
			if owner.SourceOrdinal != textOrdinal || owner.ObjectOrdinal < 0 || owner.ObjectOrdinal >= len(member.Texts) || seenTexts[owner.ObjectOrdinal] {
				return nil, contextError("generated FUNCDATA source/TEXT ordinal changed")
			}
			text := member.Texts[owner.ObjectOrdinal]
			operands := asmDataOperands(statement[1:])
			if len(operands) != 2 && len(operands) != 3 {
				return nil, contextError("generated FUNCDATA source TEXT declaration changed")
			}
			symbol, err := asmDataSymbol(operands[0], packagePath)
			namespace := TextSymbolNonpkgDefinition
			if symbol.Static {
				namespace = TextSymbolSelf
			}
			if err != nil || symbol.Addend != 0 || owner.Name != symbol.Name || owner.ABI != symbol.ABI || owner.Namespace != namespace ||
				owner.Name != text.Name || owner.ABI != text.ABI || owner.Namespace != text.Namespace || owner.Relative != text.Relative || owner.Index != text.Index {
				return nil, contextError("generated FUNCDATA source/TEXT identity changed")
			}
			seenTexts[owner.ObjectOrdinal] = true
		}
		reserved := false
		for _, token := range statement {
			reserved = reserved || token.text == "no_pointers_stackmap"
		}
		if !reserved {
			continue
		}
		operands := asmDataOperands(statement[1:])
		if statement[0].text != "FUNCDATA" || len(operands) != 2 || len(operands[0]) < 2 || operands[0][0].kind != '$' || textOrdinal < 0 {
			return nil, contextError("reserved generated FUNCDATA has a storage/address or unbound source use")
		}
		slot, err := asmDataInteger(operands[0][1:])
		symbol, symbolErr := asmDataSymbol(operands[1], packagePath)
		if err != nil || symbolErr != nil || slot != 1 || symbol.Name != "no_pointers_stackmap" || symbol.ABI != 0 || symbol.Static || symbol.Addend != 0 {
			return nil, contextError("reserved generated FUNCDATA lost its complete locals-map source role")
		}
		owner := texts[textOrdinal]
		if owners[owner.ObjectOrdinal] {
			return nil, contextError("generated FUNCDATA has a duplicate source owner/slot")
		}
		ref, found := generatedFuncdataSlot(member.Texts[owner.ObjectOrdinal], int(slot))
		if !found || ref.PackageIndex != 2147483645 || !ref.ABIKnown || ref.ABI != 0 {
			return nil, contextError("generated FUNCDATA lacks its exact hashed object-local auxiliary slot")
		}
		var definitions []ASMDataDefinition
		for _, definition := range definitionsByRelative[ref.SymbolIndex] {
			if generatedFuncdataReference(definition, ref) {
				definitions = append(definitions, definition)
			}
		}
		if len(definitions) != 1 || !validGeneratedLocalsDefinition(definitions[0]) {
			return nil, contextError("generated FUNCDATA has an unknown payload/hash/namespace/definition")
		}
		if metadata == nil {
			metadata = &ASMGeneratedFuncdata{Definition: definitions[0]}
		} else if !reflect.DeepEqual(metadata.Definition, definitions[0]) {
			return nil, contextError("one reserved locals-map rewrite produced different definitions")
		}
		owners[owner.ObjectOrdinal] = true
		metadata.Owners = append(metadata.Owners, ASMGeneratedFuncdataOwner{StatementOrdinal: ordinal, TextSourceOrdinal: textOrdinal,
			TextObjectOrdinal: owner.ObjectOrdinal, Slot: 1, TextNamespace: owner.Namespace, TextRelative: owner.Relative, TextIndex: owner.Index})
	}
	if textOrdinal+1 != len(texts) {
		return nil, contextError("generated FUNCDATA source omitted part of its complete TEXT order")
	}
	if metadata == nil {
		return nil, nil // No generated definition is inferred from a name or payload.
	}
	definition := metadata.Definition
	normalized := strings.ReplaceAll(definition.Name, "·", ".")
	for _, statement := range statements {
		var prefix strings.Builder
		for index, token := range statement {
			text := token.text
			if unquoted, err := strconv.Unquote(text); err == nil {
				text = unquoted
			}
			prefix.WriteString(text)
			if token.kind == '(' && index+2 < len(statement) && statement[index+1].text == "SB" && statement[index+2].kind == ')' && strings.Contains(prefix.String(), normalized) {
				return nil, contextError("generated metadata has an explicit source storage/address alias")
			}
		}
	}
	if err := validateGeneratedFuncdataReferences(member, definition, owners); err != nil {
		return nil, err
	}
	return []ASMGeneratedFuncdata{*metadata}, nil
}

// Recheck every use, not only the auxiliary entry selected by one owner. The
// source observer and pure readonly planner share this closed metadata role.
func validateGeneratedFuncdataReferences(member ASMDataMember, definition ASMDataDefinition, owners map[int]bool) error {
	uses := 0
	for ordinal, text := range member.Texts {
		for _, relocation := range text.Relocations {
			if generatedFuncdataReference(definition, relocation.Target) || relocation.Target.Name == definition.Name {
				return contextError("generated metadata is an ordinary TEXT relocation target")
			}
		}
		slot := -1
		for _, auxiliary := range text.Auxiliary {
			if auxiliary.Type == 2 {
				slot++ // Nil entries occupy real FUNCDATA slots too.
			}
			if generatedFuncdataReference(definition, auxiliary.Target) || auxiliary.Target.Name == definition.Name {
				if auxiliary.Type != 2 || slot != 1 || !owners[ordinal] || !generatedFuncdataReference(definition, auxiliary.Target) {
					return contextError("generated metadata has an unassociated auxiliary owner or slot")
				}
				uses++
			}
		}
	}
	for _, data := range member.Definitions {
		for _, relocation := range data.Relocations {
			if generatedFuncdataReference(definition, relocation.Target) || relocation.Target.Name == definition.Name {
				return contextError("generated metadata is an ordinary DATA relocation target")
			}
		}
	}
	if uses != len(owners) {
		return contextError("generated metadata auxiliary inventory differs from its complete source owners")
	}
	return nil
}

func generatedFuncdataSlot(text TextRecord, wanted int) (TextReference, bool) {
	slot := 0
	for _, auxiliary := range text.Auxiliary {
		if auxiliary.Type == 2 {
			if slot == wanted {
				return auxiliary.Target, true
			}
			slot++
		}
	}
	return TextReference{}, false
}

func generatedFuncdataReference(definition ASMDataDefinition, ref TextReference) bool {
	return definition.Namespace == TextSymbolHashed && ref.PackageIndex == 2147483645 && ref.SymbolIndex == definition.Relative &&
		ref.Name == definition.Name && ref.ABIKnown && ref.ABI == definition.ABI && (!ref.KindKnown || ref.Kind == definition.Kind)
}

func validGeneratedLocalsDefinition(definition ASMDataDefinition) bool {
	if definition.Namespace != TextSymbolHashed || definition.ABI != 0 || definition.Kind != 3 || definition.Flags != 1 || definition.Flags2 != 0 ||
		definition.Size != 8 || definition.Align != 4 || len(definition.Relocations) != 0 || !bytes.Equal(definition.Data, []byte{2, 0, 0, 0, 0, 0, 0, 0}) {
		return false
	}
	// Selected Go GCLocalsSym and writer.contentHash are independent hashes.
	// Validate the full generated identity, never merely a gclocals name prefix.
	nameHash := sha256.Sum256(definition.Data)
	nameHash[0] ^= 0xff
	if definition.Name != "gclocals·"+base64.StdEncoding.EncodeToString(nameHash[:16]) {
		return false
	}
	hash := sha256.New()
	hash.Write([]byte{1})
	var shape [9]byte
	binary.LittleEndian.PutUint64(shape[:8], uint64(definition.Size))
	shape[8] = 'F'
	hash.Write(shape[:])
	hash.Write(bytes.TrimRight(definition.Data, "\x00"))
	return bytes.Equal(definition.Hash, hash.Sum(nil)[:16])
}

func sameGeneratedFuncdata(first, second []ASMGeneratedFuncdata) bool {
	normalize := func(values []ASMGeneratedFuncdata) []ASMGeneratedFuncdata {
		result := append([]ASMGeneratedFuncdata(nil), values...)
		for index := range result {
			result[index].Definition.DataOffset = 0 // Physical offsets stay in both complete members.
		}
		return result
	}
	return reflect.DeepEqual(normalize(first), normalize(second))
}

// Only independently source/auxiliary-closed generated metadata is partitioned.
// The original DATA join remains unchanged and strict for every other byte.
// Full definitions are retained in both complete object observations above.
func asmDataWithoutGeneratedFuncdata(member ASMDataMember, metadata []ASMGeneratedFuncdata) ASMDataMember {
	if len(metadata) == 0 {
		return member
	}
	definitions := make([]ASMDataDefinition, 0, len(member.Definitions))
	for _, definition := range member.Definitions {
		generated := false
		for _, record := range metadata {
			generated = generated || reflect.DeepEqual(record.Definition, definition)
		}
		if !generated {
			definitions = append(definitions, definition)
		}
	}
	member.Definitions = definitions
	return member
}
