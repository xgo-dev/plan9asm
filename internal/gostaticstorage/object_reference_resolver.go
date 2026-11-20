package gostaticstorage

import "encoding/binary"

// This shared resolver preserves the existing TEXT reference rules. Calling
// it creates no DATA or native permission; each consumer validates its exact
// record inventory and byte extent independently.
func objectReferenceResolver(object *checkedGoObject, builtins []TextReference, referenced sdkReferencedSymbols) (func([]byte) (TextReference, error), [5]int, error) {
	block := object.block
	counts := [5]int{}
	var symbols []byte
	for index := range counts {
		counts[index] = len(block(index+3)) / 21
		symbols = append(symbols, block(index+3)...)
	}
	symbol := func(index uint32) ([]byte, error) {
		if uint64(index) >= uint64(len(symbols)/21) {
			return nil, contextError("TEXT reference symbol index out of bounds")
		}
		return symbols[int(index)*21 : (int(index)+1)*21], nil
	}
	refNames := make(map[[2]uint32]string)
	for pos := 0; pos < len(block(17)); pos += 16 {
		record := block(17)[pos : pos+16]
		key := [2]uint32{binary.LittleEndian.Uint32(record), binary.LittleEndian.Uint32(record[4:])}
		name, err := object.stringAt(record[8:])
		if _, duplicate := refNames[key]; err != nil || duplicate {
			return nil, counts, contextError("invalid or duplicate TEXT reference name")
		}
		refNames[key] = name
	}
	resolve := func(raw []byte) (TextReference, error) {
		var err error
		ref := TextReference{PackageIndex: binary.LittleEndian.Uint32(raw), SymbolIndex: binary.LittleEndian.Uint32(raw[4:])}
		index, bound := ref.SymbolIndex, 0
		switch ref.PackageIndex {
		case 0:
			if index != 0 {
				return ref, contextError("nonzero invalid TEXT symbol reference")
			}
			return ref, nil
		case 2147483643: // PkgIdxSelf, pinned goobj format.
			bound = counts[0]
		case 2147483646: // PkgIdxHashed64.
			bound = counts[1]
			index += uint32(counts[0])
		case 2147483645: // PkgIdxHashed.
			bound = counts[2]
			index += uint32(counts[0] + counts[1])
		case 2147483647: // PkgIdxNone, including nonpackage references.
			bound = counts[3] + counts[4]
			index += uint32(counts[0] + counts[1] + counts[2])
		case 2147483644: // PkgIdxBuiltin.
			if uint64(index) >= uint64(len(builtins)) {
				return ref, contextError("TEXT builtin index out of bounds")
			}
			ref.Name, ref.ABI, ref.ABIKnown = builtins[index].Name, builtins[index].ABI, true
			return ref, nil
		default:
			if ref.PackageIndex >= 2147483643 || uint64(ref.PackageIndex) >= uint64(len(block(1))/8) || index >= symbolLimit {
				return ref, contextError("TEXT package/index reference out of bounds")
			}
			ref.Package, err = object.stringAt(block(1)[int(ref.PackageIndex)*8 : (int(ref.PackageIndex)+1)*8])
			if err != nil || ref.Package == "" {
				return ref, contextError("TEXT foreign reference lacks actual package record")
			}
			diagnostic, present := refNames[[2]uint32{ref.PackageIndex, ref.SymbolIndex}]
			if referenced != nil {
				return resolveSDKIndexedReference(ref, diagnostic, present, referenced)
			}
			ref.Name = diagnostic
			if !present || ref.Name == "" {
				return ref, contextError("TEXT foreign reference lacks actual package/name record")
			}
			return ref, nil
		}
		if uint64(ref.SymbolIndex) >= uint64(bound) {
			return ref, contextError("TEXT local symbol reference out of bounds")
		}
		s, err := symbol(index)
		if err != nil {
			return ref, err
		}
		ref.Name, err = object.stringAt(s[:8])
		ref.ABI = binary.LittleEndian.Uint16(s[8:])
		ref.ABIKnown = true
		return ref, err
	}
	return resolve, counts, nil
}
