package gostaticstorage

import "encoding/binary"

// TextSymbolNamespace is an observed goobj block, not a native entry, storage
// identity or permission. Namespace-relative indices belong to one exact
// original object; they are never archive-global name lookup keys.
type TextSymbolNamespace uint8

const (
	TextSymbolSelf TextSymbolNamespace = iota
	TextSymbolHashed64
	TextSymbolHashed
	TextSymbolNonpkgDefinition
	TextSymbolNonpkgReference
)

type indexedObjectSymbol struct {
	Namespace           TextSymbolNamespace
	Relative, Index     uint32
	Name                string
	ABI                 uint16
	Kind, Flags, Flags2 uint8
	Size, Align         uint32
	Hash                []byte
}

// indexedSymbols preserves all four definition blocks and NonPkgRefs. DATA's
// separate named-global reader does not use this observation to admit hashes.
func (object *checkedGoObject) indexedSymbols() ([]indexedObjectSymbol, error) {
	var symbols []indexedObjectSymbol
	for namespace := TextSymbolSelf; namespace <= TextSymbolNonpkgReference; namespace++ {
		block := object.block(3 + int(namespace))
		for offset := 0; offset < len(block); offset += 21 {
			symbol := block[offset : offset+21]
			name, err := object.stringAt(symbol[:8])
			if err != nil {
				return nil, err
			}
			value := indexedObjectSymbol{
				Namespace: namespace, Relative: uint32(offset / 21), Index: uint32(len(symbols)),
				Name: name, ABI: binary.LittleEndian.Uint16(symbol[8:]), Kind: symbol[10],
				Flags: symbol[11], Flags2: symbol[12],
				Size: binary.LittleEndian.Uint32(symbol[13:]), Align: binary.LittleEndian.Uint32(symbol[17:]),
			}
			switch namespace {
			case TextSymbolHashed64:
				start := offset / 21 * 8
				value.Hash = append([]byte(nil), object.block(9)[start:start+8]...)
			case TextSymbolHashed:
				start := offset / 21 * 16
				value.Hash = append([]byte(nil), object.block(10)[start:start+16]...)
			}
			symbols = append(symbols, value)
		}
	}
	return symbols, nil
}

// Only named link-visible definitions enter this collision check. Hashed and
// static definitions retain their independent object-local indices. DUPok
// groups are observed in full, never reduced to a chosen linker/body winner.
type sdkAssemblyNamedDefinitions map[string][]indexedObjectSymbol

// This is the IsText role of the independently pinned current SDK schema,
// not a producer, namespace, ABI or storage permission. Historical readers
// keep their own enum: Kind 2 was SRODATA in older Go versions.
func currentSDKObjectIsText(kind uint8) bool {
	return kind == 1 || kind == 2 // STEXT, STEXTFIPS.
}

func (definitions sdkAssemblyNamedDefinitions) observe(symbol indexedObjectSymbol, assembly bool) error {
	if symbol.Namespace == TextSymbolNonpkgReference || symbol.Name == "" {
		return nil
	}
	if assembly && !currentSDKObjectIsText(symbol.Kind) {
		return contextError("assembly DATA definition needs an independent role: " + symbol.Name)
	}
	if symbol.Namespace == TextSymbolHashed64 || symbol.Namespace == TextSymbolHashed || symbol.ABI == 65535 {
		return nil
	}
	for _, previous := range definitions[symbol.Name] {
		if !currentSDKObjectIsText(symbol.Kind) || symbol.Kind != previous.Kind {
			return contextError("SDK name collides with a different TEXT/storage kind: " + symbol.Name)
		}
		if symbol.ABI != previous.ABI {
			continue
		}
		namedNonpackage := symbol.Namespace == TextSymbolNonpkgDefinition || previous.Namespace == TextSymbolNonpkgDefinition
		if !namedNonpackage || symbol.Flags&1 == 0 && previous.Flags&1 == 0 {
			return contextError("duplicate SDK same-ABI named definition: " + symbol.Name)
		}
	}
	definitions[symbol.Name] = append(definitions[symbol.Name], symbol)
	return nil
}
