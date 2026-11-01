package gostaticstorage

import (
	"bytes"
	"encoding/binary"
)

// This type intentionally cannot be used by the TEXT/DATA readers. It validates
// complete bounded object structure but only exposes compiler SymbolDefs
// metadata. Hashed bodies, Aux, initializers and native code grant no role.
type sdkIndexedMetadataObject struct {
	block    func(int) []byte
	stringAt func([]byte) (string, error)
}

func checkedSDKIndexedMetadata(data []byte, flags uint32, emptyAssembly bool) (*sdkIndexedMetadataObject, error) {
	const headerSize = 8 + 8 + 4 + 19*4
	if len(data) < headerSize || len(data) > archiveLimit || string(data[:8]) != "\x00go120ld" ||
		binary.LittleEndian.Uint32(data[16:20]) != flags {
		return nil, contextError("invalid SDK indexed-metadata object header/flags/bound")
	}
	var offsets [19]int
	previous := headerSize
	for index := range offsets {
		value := uint64(binary.LittleEndian.Uint32(data[20+4*index:]))
		if value < uint64(previous) || value > uint64(len(data)) {
			return nil, contextError("invalid SDK indexed-metadata block interval")
		}
		offsets[index], previous = int(value), int(value)
	}
	if offsets[18] != len(data) {
		return nil, contextError("SDK indexed-metadata blocks do not cover exact EOF")
	}
	block := func(index int) []byte { return data[offsets[index]:offsets[index+1]] }
	for _, specification := range []struct{ index, width int }{
		{0, 16}, {1, 8}, {2, 8}, {3, 21}, {4, 21}, {5, 21}, {6, 21}, {7, 21},
		{8, 10}, {9, 8}, {10, 16}, {11, 4}, {12, 4}, {13, 4}, {14, 23}, {15, 9}, {17, 16},
	} {
		if len(block(specification.index))%specification.width != 0 {
			return nil, contextError("unaligned SDK indexed-metadata record block")
		}
	}
	if len(block(3))/21 > symbolLimit {
		return nil, contextError("SDK indexed-metadata SymbolDefs exceed target metadata bound")
	}
	definitions := 0
	for index := 3; index <= 6; index++ {
		definitions += len(block(index)) / 21
	}
	if definitions == 0 && !emptyAssembly ||
		len(block(9))/8 != len(block(4))/21 || len(block(10))/16 != len(block(5))/21 {
		return nil, contextError("SDK indexed-metadata definition/hash counts differ")
	}
	// Validate all three index inventories without allocating N+1 entries.
	// The original whole archive bounds every loop and referenced byte interval.
	for _, specification := range []struct{ index, records, width int }{{11, 14, 23}, {12, 15, 9}, {13, 16, 1}} {
		indices := block(specification.index)
		bound := uint32(len(block(specification.records)) / specification.width)
		if len(indices) != 4*(definitions+1) {
			return nil, contextError("SDK indexed-metadata lacks complete symbol index inventory")
		}
		var prior uint32
		for offset := 0; offset < len(indices); offset += 4 {
			value := binary.LittleEndian.Uint32(indices[offset:])
			if offset == 0 && value != 0 || value < prior || value > bound {
				return nil, contextError("SDK indexed-metadata symbol index is unordered/out of bounds")
			}
			prior = value
		}
		if prior != bound {
			return nil, contextError("SDK indexed-metadata has unconsumed symbol index tail")
		}
	}
	stringBytes := func(reference []byte) ([]byte, error) {
		length := uint64(binary.LittleEndian.Uint32(reference))
		offset := uint64(binary.LittleEndian.Uint32(reference[4:]))
		if length > 4096 || offset < headerSize || offset > uint64(offsets[0]) || length > uint64(offsets[0])-offset {
			return nil, contextError("SDK indexed-metadata string exceeds original string block")
		}
		value := data[int(offset):int(offset+length)]
		if bytes.IndexAny(value, "\x00\r\n") >= 0 {
			return nil, contextError("invalid SDK indexed-metadata string")
		}
		return value, nil
	}
	for _, specification := range []struct{ index, width, start int }{
		{0, 16, 0}, {1, 8, 0}, {2, 8, 0}, {3, 21, 0}, {4, 21, 0}, {5, 21, 0},
		{6, 21, 0}, {7, 21, 0}, {17, 16, 8},
	} {
		for offset := 0; offset < len(block(specification.index)); offset += specification.width {
			if _, err := stringBytes(block(specification.index)[offset+specification.start:]); err != nil {
				return nil, err
			}
		}
	}
	for index := 3; index <= 7; index++ {
		for offset := 0; offset < len(block(index)); offset += 21 {
			kind := block(index)[offset+10]
			if kind > 25 || index != 7 && kind == 0 {
				return nil, contextError("unknown/undefined SDK indexed-metadata symbol kind")
			}
		}
	}
	stringAt := func(reference []byte) (string, error) {
		value, err := stringBytes(reference)
		return string(value), err
	}
	return &sdkIndexedMetadataObject{block: block, stringAt: stringAt}, nil
}

func (object *sdkIndexedMetadataObject) selfSymbols() ([]indexedObjectSymbol, error) {
	block := object.block(3)
	result := make([]indexedObjectSymbol, 0, len(block)/21)
	for offset := 0; offset < len(block); offset += 21 {
		symbol := block[offset : offset+21]
		name, err := object.stringAt(symbol)
		if err != nil {
			return nil, err
		}
		index := uint32(offset / 21)
		result = append(result, indexedObjectSymbol{Namespace: TextSymbolSelf, Relative: index, Index: index,
			Name: name, ABI: binary.LittleEndian.Uint16(symbol[8:]), Kind: symbol[10], Flags: symbol[11], Flags2: symbol[12],
			Size: binary.LittleEndian.Uint32(symbol[13:]), Align: binary.LittleEndian.Uint32(symbol[17:])})
	}
	return result, nil
}

// The pinned CPU source's one-argument linkname variables live in NonpkgDefs.
// Only that independent CPU role may request this additional namespace; generic
// SDK globals and indexed foreign references retain SymbolDefs alone.
func (object *sdkIndexedMetadataObject) storageSymbols(cpu bool) ([]indexedObjectSymbol, error) {
	result, err := object.selfSymbols()
	if err != nil || !cpu {
		return result, err
	}
	base := uint32(0)
	for _, block := range []int{3, 4, 5} {
		base += uint32(len(object.block(block)) / 21)
	}
	block := object.block(6)
	for offset := 0; offset < len(block); offset += 21 {
		symbol := block[offset : offset+21]
		name, err := object.stringAt(symbol)
		if err != nil {
			return nil, err
		}
		relative := uint32(offset / 21)
		result = append(result, indexedObjectSymbol{Namespace: TextSymbolNonpkgDefinition,
			Relative: relative, Index: base + relative, Name: name,
			ABI: binary.LittleEndian.Uint16(symbol[8:]), Kind: symbol[10], Flags: symbol[11], Flags2: symbol[12],
			Size: binary.LittleEndian.Uint32(symbol[13:]), Align: binary.LittleEndian.Uint32(symbol[17:])})
	}
	return result, nil
}
