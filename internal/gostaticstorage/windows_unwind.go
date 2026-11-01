package gostaticstorage

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"reflect"
	"strings"
)

// WindowsAMD64UnwindRecord observes one complete original Go metadata record.
// It grants no source, frame, handler or native Windows unwind permission.
type WindowsAMD64UnwindRecord struct {
	Index                uint32
	Name                 string
	Data                 []byte
	PrologueEnd, PushEnd uint8
}

type WindowsAMD64AssemblyUnwind struct {
	Texts            []TextRecord
	Unwind           []WindowsAMD64UnwindRecord
	Version          string
	AuxType          uint8
	TextFlags2       uint8
	ListingAlignment bool
}

// ObserveWindowsAMD64AssemblyUnwind is a read-only, bounded object observation.
// A live source factory must independently bind original source, actual tools,
// the pinned producer/schema, full listing and physical prologue/source PCs.
func ObserveWindowsAMD64AssemblyUnwind(data, builtinSource []byte, privateLeaves ...[]TextRecord) (WindowsAMD64AssemblyUnwind, error) {
	var result WindowsAMD64AssemblyUnwind
	if len(privateLeaves) > 1 {
		return result, contextError("Windows metadata has multiple private source-role inventories")
	}
	if len(data) == 0 || len(data) > archiveLimit {
		return result, contextError("Windows assembly object exceeds its byte bound")
	}
	version, err := objectHeaderVersion(data, "windows/amd64")
	if err != nil {
		return result, err
	}
	schema, ok := windowsUnwindFormat(version)
	if !ok {
		return result, contextError("unregistered Windows unwind object producer")
	}
	builtins, err := textBuiltinsForDigest(builtinSource, schema.builtin)
	if err != nil {
		return result, err
	}
	end := bytes.Index(data, []byte("\n!\n"))
	if end < 0 || end > 4096 {
		return result, contextError("invalid Windows assembly object text header")
	}
	body := data[end+3:]
	object, err := checkedObject(body, 4, false)
	if err != nil {
		return result, err
	}
	// Record widths/indexing are identical, but old symbol/Aux enums are not.
	// Reject unknown historical values before invoking the shared byte reader.
	for _, index := range []int{3, 4, 5, 6, 7} {
		for pos := 0; pos < len(object.block(index)); pos += 21 {
			kind := object.block(index)[pos+10]
			if kind > schema.kind || schema.kind >= 24 && kind == 2 {
				return result, contextError("unknown or FIPS Windows assembly symbol kind")
			}
		}
	}
	for pos := 0; pos < len(object.block(15)); pos += 9 {
		if object.block(15)[pos] > schema.aux {
			return result, contextError("unknown Windows assembly auxiliary kind")
		}
	}
	for pos := 0; pos < len(object.block(14)); pos += 23 {
		kind := binary.LittleEndian.Uint16(object.block(14)[pos+5:])
		if !(kind >= 1 && kind <= schema.relocationMax || kind == 0x8001 || kind == 0x8005) {
			return result, contextError("unknown Windows assembly relocation kind")
		}
	}
	texts, err := readTextObjectKinds(body, "windows/amd64", 4, false, builtins, nil, false)
	if err != nil {
		return result, err
	}
	if len(texts) == 0 {
		return result, contextError("Windows metadata lacks its complete TEXT inventory")
	}
	var leaves map[uint32]TextRecord
	if len(privateLeaves) == 1 && len(privateLeaves[0]) != 0 {
		if len(privateLeaves[0]) > len(texts) {
			return result, contextError("Windows private source-role inventory exceeds its complete object")
		}
		leaves = make(map[uint32]TextRecord, len(privateLeaves[0]))
		for _, text := range privateLeaves[0] {
			_, duplicate := leaves[text.Index]
			if duplicate || text.Name == "" || text.Kind != 1 || text.Flags != 16 ||
				!(text.Namespace == TextSymbolSelf && text.ABI == 65535 ||
					text.Namespace == TextSymbolNonpkgDefinition && text.ABI == 0) {
				return result, contextError("Windows private source-role inventory has an invalid TEXT identity")
			}
			leaves[text.Index] = text
		}
	}
	block := object.block
	counts := [4]int{}
	var symbols []byte
	for index := range counts {
		counts[index] = len(block(index+3)) / 21
		symbols = append(symbols, block(index+3)...)
	}
	hashedStart, hashedEnd := counts[0]+counts[1], counts[0]+counts[1]+counts[2]
	byIndex := make(map[uint32]WindowsAMD64UnwindRecord)
	names := make(map[string]bool)
	for index := 0; index < object.count; index++ {
		symbol := symbols[index*21 : (index+1)*21]
		name, err := object.stringAt(symbol[:8])
		if err != nil || name != "" && names[name] {
			return result, contextError("duplicate or invalid Windows definition name")
		}
		if name != "" {
			names[name] = true
		}
		for n := object.indices[1][index]; n < object.indices[1][index+1]; n++ {
			if block(15)[int(n)*9] == schema.aux && symbol[10] != 1 {
				return result, contextError("Windows SEH auxiliary belongs to a non-TEXT definition")
			}
		}
		if symbol[10] != schema.kind {
			if strings.HasPrefix(name, "go:sehuw.") {
				return result, contextError("Windows unwind name lacks its actual metadata kind")
			}
			continue
		}
		start, end := object.indices[2][index], object.indices[2][index+1]
		if index < hashedStart || index >= hashedEnd || binary.LittleEndian.Uint16(symbol[8:]) != 0 ||
			symbol[11] != 3 || symbol[12] != schema.flag2 || binary.LittleEndian.Uint32(symbol[13:]) != 12 ||
			binary.LittleEndian.Uint32(symbol[17:]) != 4 || end-start != 12 {
			return result, contextError("Windows unwind symbol/block/extent role differs")
		}
		bytes := block(16)[start:end]
		if name != "go:sehuw.12."+base64.StdEncoding.EncodeToString(bytes) {
			return result, contextError("Windows unwind name does not bind its complete original bytes")
		}
		if bytes[0] != 1 {
			return result, contextError("Windows native exception-handler/version flags require a separate role")
		}
		if object.indices[0][index] != object.indices[0][index+1] ||
			object.indices[1][index] != object.indices[1][index+1] {
			return result, contextError("Windows unwind auxiliary/relocation requires a separate role")
		}
		if bytes[1] == 0 || bytes[2] != 2 || bytes[3] != 5 || bytes[4] != bytes[1] ||
			bytes[5] != 3 || bytes[6] == 0 || bytes[6] >= bytes[4] || bytes[7] != 0x50 ||
			binary.LittleEndian.Uint32(bytes[8:]) != 0 {
			return result, contextError("unknown Windows unwind header/node/offset/tail grammar")
		}
		value := WindowsAMD64UnwindRecord{uint32(index), name, append([]byte(nil), bytes...), bytes[1], bytes[6]}
		byIndex[value.Index] = value
		result.Unwind = append(result.Unwind, value)
	}
	used := make(map[uint32]bool)
	textNames := make(map[string]bool)
	for _, text := range texts {
		leaf, private := leaves[text.Index]
		if private && !reflect.DeepEqual(leaf, text) {
			return WindowsAMD64AssemblyUnwind{}, contextError("Windows private TEXT differs from its complete source/object association")
		}
		if text.Name == "" || textNames[text.Name] || text.Kind != 1 || !private && text.ABI != 0 ||
			text.Flags&^16 != 0 || text.Flags2 != schema.flag2 {
			return WindowsAMD64AssemblyUnwind{}, contextError("Windows closed-local metadata needs complete distinct ABI0 TEXTs")
		}
		textNames[text.Name] = true
		links := 0
		for _, aux := range text.Auxiliary {
			if aux.Type != schema.aux {
				continue
			}
			links++
			if aux.Target.PackageIndex != 2147483645 || !aux.Target.ABIKnown || aux.Target.ABI != 0 ||
				uint64(aux.Target.SymbolIndex) >= uint64(counts[2]) {
				return WindowsAMD64AssemblyUnwind{}, contextError("Windows TEXT SEH reference lacks its local hashed role")
			}
			index := aux.Target.SymbolIndex + uint32(hashedStart)
			unwind, exists := byIndex[index]
			if !exists || aux.Target.Name != unwind.Name || int(unwind.PrologueEnd) >= len(text.Code) {
				return WindowsAMD64AssemblyUnwind{}, contextError("Windows TEXT refers to missing/wrong/oversized unwind metadata")
			}
			used[index] = true
		}
		minimumLinks := 1
		if private {
			// The original-source join checks whether this leaf has an
			// automatic frame. Observe either valid object shape here; only
			// the independently bound zero-frame source can omit SEH.
			minimumLinks = 0
			delete(leaves, text.Index)
		}
		if links < minimumLinks || links > 1 {
			return WindowsAMD64AssemblyUnwind{}, contextError("Windows TEXT has missing or duplicate SEH auxiliary ownership")
		}
	}
	if len(leaves) != 0 {
		return WindowsAMD64AssemblyUnwind{}, contextError("Windows private source-role inventory has a foreign TEXT")
	}
	if len(used) != len(byIndex) {
		return WindowsAMD64AssemblyUnwind{}, contextError("Windows unwind inventory has an orphan definition")
	}
	result.Texts = texts
	result.Version, result.AuxType = version, schema.aux
	result.TextFlags2, result.ListingAlignment = schema.flag2, schema.listingAlignment
	return result, nil
}
