package gostaticstorage

import (
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"strconv"
	"strings"
)

const TextProtocol = "actual_go_text_records_observation_v2"
const builtinSourceRole = "src/cmd/internal/goobj/builtinlist.go"

// These are binary observations, not decoded instruction/read, TEXT entry,
// caller, pointer or result certificates. Wasm Size/Positions use Go virtual
// PCs; Code/Relocation offsets still address physical object bytes.
type TextReference struct {
	PackageIndex, SymbolIndex uint32
	Package, Name             string
	ABI                       uint16
	ABIKnown                  bool
	Kind                      uint8
	KindKnown                 bool
}

type TextRelocation struct {
	Offset, Size int64
	Type         uint16
	Add          int64
	Target       TextReference
}

type TextAuxiliary struct {
	Type   uint8
	Target TextReference
}

type TextPosition struct {
	Start, End int64
	File       string
	Line       int32
}

type TextRecord struct {
	Index          uint32
	Namespace      TextSymbolNamespace
	Relative       uint32
	Hash           []byte
	Name           string
	ABI            uint16
	Kind           uint8
	Flags, Flags2  uint8
	Size           int64
	Code           []byte
	Relocations    []TextRelocation
	Auxiliary      []TextAuxiliary
	PCFile, PCLine []byte
	Positions      []TextPosition
}

type TextMember struct {
	Name         string
	Offset, Size int64
	Flags        uint32
	Texts        []TextRecord
}

func textBuiltins(source []byte) ([]TextReference, error) {
	return textBuiltinsForDigest(source, formatSources[builtinSourceRole])
}

func textBuiltinsForDigest(source []byte, expected string) ([]TextReference, error) {
	if digest(source) != expected {
		return nil, contextError("TEXT builtin source differs from the selected SDK")
	}
	file, err := parser.ParseFile(token.NewFileSet(), builtinSourceRole, source, 0)
	if err != nil {
		return nil, contextError("invalid original builtin table")
	}
	var result []TextReference
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.VAR {
			continue
		}
		for _, specification := range group.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "builtins" || len(value.Values) != 1 {
				return nil, contextError("unknown builtin source declaration")
			}
			table, ok := value.Values[0].(*ast.CompositeLit)
			if !ok || len(table.Elts) == 0 || len(table.Elts) > symbolLimit {
				return nil, contextError("invalid bounded builtin inventory")
			}
			for _, element := range table.Elts {
				pair, ok := element.(*ast.CompositeLit)
				if !ok || len(pair.Elts) != 2 {
					return nil, contextError("unknown builtin pair")
				}
				name, nameOK := pair.Elts[0].(*ast.BasicLit)
				abi, abiOK := pair.Elts[1].(*ast.BasicLit)
				if !nameOK || !abiOK {
					return nil, contextError("nonliteral builtin identity")
				}
				text, textErr := strconv.Unquote(name.Value)
				number, abiErr := strconv.ParseUint(abi.Value, 10, 16)
				if textErr != nil || abiErr != nil || text == "" {
					return nil, contextError("invalid builtin name/ABI")
				}
				result = append(result, TextReference{Name: text, ABI: uint16(number), ABIKnown: true})
			}
		}
	}
	if len(result) == 0 {
		return nil, contextError("missing actual builtin inventory")
	}
	return result, nil
}

func textArchives(report Report, packages map[string]Package) (map[string][]TextMember, error) {
	if report.Protocol == SDKGlobalsProtocol {
		return sdkGlobalMembers(report, packages)
	}
	builtins, err := textBuiltins(report.TextBuiltinSource)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]TextMember, len(packages))
	for path, pkg := range packages {
		archive := report.Archives[path]
		// Reuse the existing source/member role admission unchanged. The
		// following parser supplies metadata, not another admission path.
		if report.Protocol == SDKCPUProtocol {
			_, err = readSDKCPUArchive(archive, report.Target, pkg.SFiles)
		} else {
			_, err = readArchive(archive, report.Target)
		}
		if err != nil {
			return nil, err
		}
		result[path], err = readTextArchive(archive, report.Target, report.Protocol == SDKCPUProtocol, builtins)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func readTextArchive(data []byte, target string, sdkCPU bool, builtins []TextReference) ([]TextMember, error) {
	members, err := archiveMembers(data)
	if err != nil {
		return nil, err
	}
	var result []TextMember
	for index, member := range members {
		value := TextMember{Name: member.name, Offset: member.offset, Size: int64(len(member.data))}
		if index != 0 {
			if sdkCPU {
				value.Flags = sdkCompilerObjectFlags(target)
				if index != 1 {
					value.Flags |= 4
				}
			}
			reader := objectBody
			if sdkCPU && index == 1 {
				reader = sdkObjectBody
			}
			body, err := reader(member.data, target)
			if err != nil {
				return nil, err
			}
			value.Texts, err = readTextObject(body, target, value.Flags, sdkCPU && index != 1, builtins)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, value)
	}
	return result, nil
}

func readTextObject(data []byte, target string, flags uint32, empty bool, builtins []TextReference) ([]TextRecord, error) {
	return readTextObjectReferences(data, target, flags, empty, builtins, nil)
}

func readTextObjectReferences(data []byte, target string, flags uint32, empty bool, builtins []TextReference, referenced sdkReferencedSymbols) ([]TextRecord, error) {
	return readTextObjectKinds(data, target, flags, empty, builtins, referenced, true)
}

func readTextObjectKinds(data []byte, target string, flags uint32, empty bool, builtins []TextReference, referenced sdkReferencedSymbols, fipsText bool) ([]TextRecord, error) {
	object, err := checkedObject(data, flags, empty)
	if err != nil {
		return nil, err
	}
	return readCheckedTextObjectKinds(object, target, builtins, referenced, fipsText)
}

func readCheckedTextObjectKinds(object *checkedGoObject, target string, builtins []TextReference, referenced sdkReferencedSymbols, fipsText bool) ([]TextRecord, error) {
	block := object.block
	definitions, err := object.indexedSymbols()
	if err != nil {
		return nil, err
	}
	resolve, counts, err := objectReferenceResolver(object, builtins, referenced)
	if err != nil {
		return nil, err
	}
	// Validate unused reference/auxiliary records too: an overflowing reference
	// cannot hide behind another requested TEXT or a DATA-only definition.
	for _, spec := range []struct{ block, width, start int }{{8, 10, 0}, {14, 23, 15}, {15, 9, 1}, {17, 16, 0}} {
		for pos := 0; pos < len(block(spec.block)); pos += spec.width {
			if _, err := resolve(block(spec.block)[pos+spec.start : pos+spec.start+8]); err != nil {
				return nil, err
			}
		}
	}
	// All values come from the hash-bound Go1.27.1 objabi/goobj sources.
	// Enumerating a relocation kind records its identity, not read/address
	// permission or a decoded addend. Validate unused records as well.
	for pos := 0; pos < len(block(14)); pos += 23 {
		kind := binary.LittleEndian.Uint16(block(14)[pos+5:])
		if !(kind >= 1 && kind <= 106 || kind == 0x8001 || kind == 0x8005) {
			return nil, contextError("unknown original Go relocation kind")
		}
	}
	for pos := 0; pos < len(block(15)); pos += 9 {
		if block(15)[pos] > 14 {
			return nil, contextError("unknown original Go auxiliary kind")
		}
	}
	_, arch, _ := strings.Cut(target, "/")
	minLC := int64(1)
	if arch == "arm" || arch == "arm64" {
		minLC = 4
	}
	if arch != "386" && arch != "amd64" && arch != "arm" && arch != "arm64" && arch != "wasm" {
		return nil, contextError("unknown TEXT PC target")
	}
	var result []TextRecord
	for index := 0; index < object.count; index++ {
		definition := definitions[index]
		if definition.Kind != 1 && !(fipsText && currentSDKObjectIsText(definition.Kind)) {
			continue
		}
		value := TextRecord{Index: uint32(index), Namespace: definition.Namespace, Relative: definition.Relative,
			Hash: append([]byte(nil), definition.Hash...), Name: definition.Name, ABI: definition.ABI,
			Kind: definition.Kind, Flags: definition.Flags, Flags2: definition.Flags2, Size: int64(definition.Size)}
		start, end := object.indices[2][index], object.indices[2][index+1]
		value.Code = append([]byte(nil), block(16)[start:end]...)
		if value.Size > archiveLimit || arch != "wasm" && value.Size != int64(len(value.Code)) {
			return nil, contextError("TEXT native/virtual code extent differs")
		}
		for j := object.indices[0][index]; j < object.indices[0][index+1]; j++ {
			q := block(14)[int(j)*23 : int(j+1)*23]
			ref, _ := resolve(q[15:])
			r := TextRelocation{Offset: int64(int32(binary.LittleEndian.Uint32(q))), Size: int64(q[4]), Type: binary.LittleEndian.Uint16(q[5:]), Add: int64(binary.LittleEndian.Uint64(q[7:])), Target: ref}
			if r.Offset < 0 || r.Size > int64(len(value.Code)) || r.Offset > int64(len(value.Code))-r.Size || r.Type == 0 {
				return nil, contextError("TEXT physical relocation exceeds its code")
			}
			value.Relocations = append(value.Relocations, r)
		}
		var pcfile, pcline []byte
		seen := make(map[uint8]bool)
		for j := object.indices[1][index]; j < object.indices[1][index+1]; j++ {
			q := block(15)[int(j)*9 : int(j+1)*9]
			ref, _ := resolve(q[1:])
			if q[0] > 14 || q[0] == 8 && seen[8] || q[0] == 9 && seen[9] {
				return nil, contextError("unknown or duplicate TEXT PC auxiliary record")
			}
			seen[q[0]] = true
			value.Auxiliary = append(value.Auxiliary, TextAuxiliary{q[0], ref})
			if q[0] != 8 && q[0] != 9 {
				continue
			}
			if ref.PackageIndex != 2147483645 {
				return nil, contextError("TEXT PC table lacks its actual hashed data role")
			}
			id := int(ref.SymbolIndex) + counts[0] + counts[1]
			from, to := object.indices[2][id], object.indices[2][id+1]
			if q[0] == 8 {
				pcfile = block(16)[from:to]
			} else {
				pcline = block(16)[from:to]
			}
		}
		positions, err := textPositions(pcfile, pcline, value.Size, minLC, object)
		if err != nil {
			return nil, err
		}
		value.Positions = positions
		value.PCFile, value.PCLine = append([]byte(nil), pcfile...), append([]byte(nil), pcline...)
		result = append(result, value)
	}
	return result, nil
}

type pcValueSpan struct{ start, end, value int64 }

func textPCTable(data []byte, extent, minLC int64) ([]pcValueSpan, error) {
	if extent < 0 || extent > archiveLimit || minLC != 1 && minLC != 4 {
		return nil, contextError("invalid bounded TEXT PC extent/quantum")
	}
	var result []pcValueSpan
	pc, value := int64(0), int64(-1)
	read := func() (uint32, error) {
		var number uint32
		for shift := uint(0); shift <= 28; shift += 7 {
			if len(data) == 0 || shift == 28 && data[0] > 15 {
				return 0, contextError("truncated or overflowing TEXT PC varint")
			}
			b := data[0]
			data = data[1:]
			number |= uint32(b&127) << shift
			if b&128 == 0 {
				if shift != 0 && b == 0 {
					return 0, contextError("noncanonical TEXT PC varint")
				}
				return number, nil
			}
		}
		return 0, contextError("oversized TEXT PC varint")
	}
	for len(result) < symbolLimit {
		delta, err := read()
		if err != nil {
			return nil, err
		}
		if delta == 0 && len(result) != 0 {
			if len(data) != 0 || pc != extent {
				return nil, contextError("TEXT PC table has a tail or incomplete extent")
			}
			return result, nil
		}
		change := int64(delta >> 1)
		if delta&1 != 0 {
			change = -change - 1
		}
		value += change
		distance, err := read()
		// The pinned funcpctab writer can emit one (value, zero-distance)
		// pair for a TEXT-only function. Its logical PC domain is empty;
		// physical wasm bytes are deliberately not constrained by this role.
		zeroPC := extent == 0 && len(result) == 0 && distance == 0
		if err != nil || distance == 0 && !zeroPC || value < math.MinInt32 || value > math.MaxInt32 {
			return nil, contextError("invalid TEXT PC/value delta")
		}
		end := pc + int64(distance)*minLC
		if end <= pc && !zeroPC || end > extent {
			return nil, contextError("overflowing or oversized TEXT PC interval")
		}
		result = append(result, pcValueSpan{pc, end, value})
		pc = end
	}
	return nil, contextError("TEXT PC interval inventory exceeds its bound")
}

func textPositions(files, lines []byte, extent, minLC int64, object *checkedGoObject) ([]TextPosition, error) {
	if len(files) == 0 && len(lines) == 0 {
		if extent == 0 {
			return nil, nil
		}
		return []TextPosition{{0, extent, "", 0}}, nil
	}
	fileSpans, err := textPCTable(files, extent, minLC)
	if err != nil {
		return nil, err
	}
	lineSpans, err := textPCTable(lines, extent, minLC)
	if err != nil {
		return nil, err
	}
	var result []TextPosition
	for f, l := 0, 0; f < len(fileSpans) && l < len(lineSpans); {
		file, line := fileSpans[f], lineSpans[l]
		if file.value < 0 || file.value >= int64(len(object.block(2))/8) {
			return nil, contextError("TEXT PC file index out of bounds")
		}
		name, err := object.stringAt(object.block(2)[file.value*8 : (file.value+1)*8])
		if err != nil {
			return nil, err
		}
		start, end := file.start, file.end
		if line.start > start {
			start = line.start
		}
		if line.end < end {
			end = line.end
		}
		if end > extent {
			end = extent
		}
		if start < end {
			value := TextPosition{start, end, name, int32(line.value)}
			last := len(result) - 1
			if last >= 0 && result[last].End == start && result[last].File == name && result[last].Line == value.Line {
				result[last].End = end
			} else {
				result = append(result, value)
			}
		}
		if file.end <= line.end {
			f++
		}
		if line.end <= file.end {
			l++
		}
	}
	return result, nil
}
