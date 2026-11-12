package gostaticstorage

import (
	"bytes"
	"reflect"
)

// ReadonlyLiteralDataImage is a pure initializer plan, never a live owner,
// pointer, numerical-read or native-body capability. Its object-local identity
// is retained instead of choosing a global by name or hash.
type ReadonlyLiteralDataImage struct {
	SourceOrdinal, MemberOrdinal int
	SourceName, MemberName       string
	DeclaredSize                 int64
	Definition                   ASMDataDefinition
	Fragments                    []ASMDataFragment
	Initial                      []byte
}

// ReadonlyLiteralDataInitializers examines already observed complete DATA
// records. Only the separate live SDK factory can create an initializer owner.
func ReadonlyLiteralDataInitializers(observation *SDKASMDataObservation) ([]ReadonlyLiteralDataImage, error) {
	if observation == nil || observation.Protocol != ASMDataProtocol && observation.Protocol != ASMDataCPPProtocol ||
		!X86SDKTarget(observation.Target) || observation.PackagePath == "" ||
		len(observation.Sources) == 0 || len(observation.Sources) > 62 || len(observation.Members) != len(observation.Sources)+2 {
		return nil, contextError("readonly literal DATA lacks its complete observation role")
	}
	names := make([]string, len(observation.Sources))
	for index, source := range observation.Sources {
		names[index] = source.Name
	}
	members, err := sdkAssemblyMemberNames(names)
	if err != nil {
		return nil, err
	}
	var total int64
	// Preflight the whole allocation, including unwritten zero tails, before
	// creating any image. Sparse P bytes alone are not the initialized extent.
	for _, source := range observation.Sources {
		for _, layout := range source.ExpandedLayouts {
			total += int64(layout.Definition.Size)
			if layout.Definition.Size > archiveLimit || total > archiveLimit {
				return nil, contextError("readonly literal DATA complete initializer bytes exceed the existing object bound")
			}
		}
	}
	var images []ReadonlyLiteralDataImage
	for ordinal, source := range observation.Sources {
		member := observation.Members[ordinal+2]
		if member.Ordinal != ordinal+2 || member.Name != members[ordinal] || !bytes.Equal(member.NameBytes, []byte(member.Name)) ||
			member.Flags != sdkAssemblyObjectFlags(observation.Target) ||
			source.Original.Flags != sdkAssemblyObjectFlags(observation.Target) ||
			source.Expanded.Flags != sdkAssemblyObjectFlags(observation.Target) ||
			!sameASMDataObjects(source.Original, member) || !sameASMDataObjects(source.Original, source.Expanded) {
			return nil, contextError("readonly literal DATA whole source/object/archive identity differs")
		}
		if observation.Protocol == ASMDataCPPProtocol && (!reflect.DeepEqual(source.Original.Texts, member.Texts) ||
			!reflect.DeepEqual(source.Original.Texts, source.Expanded.Texts) || source.Layouts != nil || source.OriginalProgramSHA256 != "") {
			return nil, contextError("readonly literal DATA borrowed a raw program or changed complete CPP positions")
		}
		type identity struct {
			namespace TextSymbolNamespace
			index     uint32
		}
		definitions := make(map[identity]ASMDataDefinition, len(member.Definitions))
		for _, definition := range member.Definitions {
			key := identity{definition.Namespace, definition.Index}
			if _, exists := definitions[key]; exists {
				return nil, contextError("readonly literal DATA repeats an object-local definition")
			}
			definitions[key] = definition
		}
		used := make(map[identity]bool)
		lastGlobal := -1
		for _, layout := range source.ExpandedLayouts {
			key := identity{layout.Definition.Namespace, layout.Definition.Index}
			definition, present := definitions[key]
			first, second := definition, layout.Definition
			first.DataOffset, second.DataOffset = 0, 0
			if !present || used[key] || !reflect.DeepEqual(first, second) || layout.Ordinal <= lastGlobal || layout.Line < 1 {
				return nil, contextError("readonly literal DATA layout lost its unique source/namespace/index join")
			}
			lastGlobal, used[key] = layout.Ordinal, true
			if !layout.Static || layout.ABI != 65535 || layout.Name == "" || definition.Name != layout.Name || definition.ABI != layout.ABI ||
				layout.Flags != 8 && layout.Flags != 24 || definition.Namespace != TextSymbolSelf || asmDataBaseKind(definition.Kind) != 3 ||
				definition.Flags != 0 || definition.Flags2 != 0 || len(definition.Hash) != 0 || len(definition.Relocations) != 0 {
				return nil, contextError("DATA is not one private relocation-free readonly literal definition")
			}
			if layout.DeclaredSize < 0 || layout.DeclaredSize > archiveLimit || definition.Size > archiveLimit || len(definition.Data) > int(definition.Size) {
				return nil, contextError("readonly literal DATA written bytes exceed its actual object extent")
			}
			initial := make([]byte, definition.Size)
			end, previous, expectedSize := int64(0), -1, layout.DeclaredSize
			for _, fragment := range layout.Fragments {
				if fragment.Offset < end || fragment.Width < 0 || fragment.Offset > int64(len(definition.Data))-fragment.Width ||
					fragment.Ordinal <= previous || fragment.Line < 1 || fragment.Address != nil {
					return nil, contextError("readonly literal DATA fragments overlap or lose their source extent/order")
				}
				end, previous = fragment.Offset+fragment.Width, fragment.Ordinal
				// GloblPos sets Size to the declared value. Only DATA after
				// that declaration can grow it; prior P bytes do not enlarge
				// a subsequently shortened GLOBL or make it linkable.
				if fragment.Ordinal > layout.Ordinal && end > expectedSize {
					expectedSize = end
				}
				switch fragment.Kind {
				case ASMDataInteger, ASMDataFloat:
					if len(fragment.String) != 0 || fragment.Width != 1 && fragment.Width != 2 && fragment.Width != 4 && fragment.Width != 8 ||
						fragment.Kind == ASMDataFloat && fragment.Width != 4 && fragment.Width != 8 ||
						fragment.Width < 8 && fragment.Bits>>(8*uint(fragment.Width)) != 0 {
						return nil, contextError("readonly literal DATA bit pattern differs from its exact scalar width")
					}
					for index := int64(0); index < fragment.Width; index++ {
						initial[fragment.Offset+index] = byte(fragment.Bits >> (8 * uint(index)))
					}
				case ASMDataString:
					if fragment.Bits != 0 || int64(len(fragment.String)) > fragment.Width {
						return nil, contextError("readonly literal DATA string exceeds its exact padded byte extent")
					}
					copy(initial[fragment.Offset:end], fragment.String)
				default:
					return nil, contextError("readonly literal DATA contains an address or unknown initializer role")
				}
			}
			if expectedSize != int64(definition.Size) || end != int64(len(definition.Data)) || !bytes.Equal(initial[:end], definition.Data) {
				return nil, contextError("readonly literal DATA reconstructed sparse bytes differ from the original object")
			}
			image := ReadonlyLiteralDataImage{SourceOrdinal: ordinal, MemberOrdinal: member.Ordinal,
				SourceName: source.Name, MemberName: member.Name, DeclaredSize: layout.DeclaredSize,
				Definition: definition, Fragments: layout.Fragments, Initial: initial}
			// The plan owns its arrays; caller mutation cannot change the observed
			// object or another plan. This remains a pure value, not an owner token.
			image.Definition.Data = append([]byte(nil), definition.Data...)
			image.Fragments = append([]ASMDataFragment(nil), layout.Fragments...)
			for index := range image.Fragments {
				image.Fragments[index].String = append([]byte(nil), layout.Fragments[index].String...)
			}
			images = append(images, image)
		}
		metadata, err := readonlyGeneratedMetadata(source, observation.Target)
		if err != nil {
			return nil, err
		}
		for _, definition := range metadata {
			key := identity{definition.Namespace, definition.Index}
			actual, present := definitions[key]
			first, second := actual, definition
			first.DataOffset, second.DataOffset = 0, 0
			if !present || used[key] || !reflect.DeepEqual(first, second) {
				return nil, contextError("readonly metadata lost its exact definition or overlaps an ordinary DATA layout")
			}
			used[key] = true // Inventory only: metadata never produces an image.
		}
		for _, definition := range member.Definitions {
			if definition.Name != "" && !used[identity{definition.Namespace, definition.Index}] {
				return nil, contextError("readonly literal DATA omits a named definition from the complete source")
			}
		}
	}
	if len(images) == 0 {
		return nil, contextError("complete source has no private readonly literal DATA initializers")
	}
	return images, nil
}
