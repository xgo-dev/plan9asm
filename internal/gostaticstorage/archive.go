// Package gostaticstorage observes bounded actual Go static storage. An object
// record is not a pointer, caller, frame, initialized result or read permission.
package gostaticstorage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

var ErrContext = errors.New("static storage needs actual source context")

type relocation struct {
	Offset int64
	Size   int64
	Type   uint16
}

type dataRecord struct {
	Name          string
	Kind          uint8
	ABI           uint16
	Flags, Flags2 uint8
	Size, Align   int64
	Data          []byte
	Relocations   []relocation
	Member        string
	Index         uint32
}

const archiveLimit = 16 << 20

// ArchiveMemberInventoryLimit is the existing complete compiler archive bound.
// SDK ASM inventories reserve two members for __.PKGDEF and _go_.o.
// Reusing this bound supplies no source/object or instruction authority.
const ArchiveMemberInventoryLimit = 64

// ObjectSymbolInventoryLimit is the existing complete object-symbol bound.
// Frontend cost preflights may reuse it; it creates no observation or authority.
const ObjectSymbolInventoryLimit = 1 << 16
const symbolLimit = ObjectSymbolInventoryLimit

func contextError(message string) error { return fmt.Errorf("%w: %s", ErrContext, message) }

// readArchive consumes an ordinary compiler archive, not nm/listing text. The
// capture boundary separately binds the Go version and complete format sources.
// This prototype excludes native/assembly archive members rather than guessing
// a missing object's ownership. Every offset/count is checked before indexing.
func readArchive(data []byte, target string) (map[string]dataRecord, error) {
	members, err := archiveMembers(data)
	if err != nil {
		return nil, err
	}
	if len(members) != 2 || members[0].name != "__.PKGDEF" || members[1].name != "_go_.o" {
		return nil, contextError("missing or nonordinary compiler package/object members")
	}
	object, err := objectBody(members[1].data, target)
	if err != nil {
		return nil, err
	}
	return readObject(object)
}

type archiveMember struct {
	name   string
	data   []byte
	offset int64
}

func archiveMembers(data []byte) ([]archiveMember, error) {
	if len(data) < 8 || len(data) > archiveLimit || string(data[:8]) != "!<arch>\n" {
		return nil, contextError("invalid compiler archive header or byte bound")
	}
	seen := make(map[string]bool)
	var members []archiveMember
	for pos := 8; pos < len(data); {
		if len(seen) >= ArchiveMemberInventoryLimit || len(data)-pos < 60 {
			return nil, contextError("truncated or oversized archive member inventory")
		}
		header := data[pos : pos+60]
		name := strings.TrimSpace(string(header[:16]))
		if string(header[58:]) != "`\n" || seen[name] || name == "" || strings.ContainsAny(name, "/\\\x00\r\n") {
			return nil, contextError("duplicate, unknown or non-compiler archive member")
		}
		seen[name] = true
		size, err := strconv.ParseUint(strings.TrimSpace(string(header[48:58])), 10, 32)
		pos += 60
		if err != nil || size == 0 || size > uint64(len(data)-pos) {
			return nil, contextError("invalid archive member extent")
		}
		members = append(members, archiveMember{name, data[pos : pos+int(size)], int64(pos)})
		pos += int(size)
		if size&1 != 0 {
			if pos >= len(data) || data[pos] != '\n' && data[pos] != 0 {
				return nil, contextError("invalid archive alignment byte")
			}
			pos++
		}
	}
	return members, nil
}

func objectBody(object []byte, target string) ([]byte, error) {
	end := bytes.Index(object, []byte("\n!\n"))
	if end < 0 || end > 4096 {
		return nil, contextError("invalid compiler object text header")
	}
	if _, err := objectVersion(object, target); err != nil {
		return nil, err
	}
	return object[end+3:], nil
}

func objectVersion(object []byte, target string) (string, error) {
	version, err := objectHeaderVersion(object, target)
	if err != nil {
		return "", err
	}
	if !gotoolchain.AuditedGo127(version) {
		return "", contextError("object target/version differs from selected compiler")
	}
	return version, nil
}

// The caller must separately admit and bind the exact producer. Parsing this
// header alone does not register a compiler object format.
func objectHeaderVersion(object []byte, target string) (string, error) {
	end := bytes.IndexByte(object, '\n')
	if end < 0 || end > 4096 {
		return "", contextError("invalid compiler object version header")
	}
	goos, goarch, valid := strings.Cut(target, "/")
	words := strings.Fields(string(object[:end]))
	if !valid || len(words) < 5 || words[0] != "go" || words[1] != "object" ||
		words[2] != goos || words[3] != goarch {
		return "", contextError("object target/version differs from selected compiler")
	}
	return words[4], nil
}

// ValidateObjectVersion binds an object (or compiler export member) to its
// producer's exact patch release. Shared format support alone is not a match.
func ValidateObjectVersion(object []byte, target, version string) error {
	actual, err := objectVersion(object, target)
	if err != nil {
		return err
	}
	if actual != version {
		return contextError("object version differs from its actual producer")
	}
	return nil
}

// These byte roles are pinned to Go 1.27.1 cmd/internal/goobj/objfile.go, rather
// than inferred from symbol spellings or the data-only assembler listing.
func readObject(data []byte) (map[string]dataRecord, error) {
	return readObjectRole(data, 0, false)
}

// checkedObject is shared structural validation, not an archive/source role.
// DATA and TEXT readers still independently choose their allowed member roles.
type checkedGoObject struct {
	block    func(int) []byte
	stringAt func([]byte) (string, error)
	indices  [3][]uint32
	count    int
}

func checkedObject(data []byte, flags uint32, emptyAssembly bool) (*checkedGoObject, error) {
	return checkedObjectRecords(data, flags, emptyAssembly, false)
}

// SDK compiler bodies have four independently bounded definition namespaces.
// This offline decoding role supplies no SDK provenance or source authority.
// Ordinary bodies and individual assembly members retain their original bound.
func checkedSDKObject(data []byte, flags uint32, emptyAssembly bool) (*checkedGoObject, error) {
	return checkedObjectRecords(data, flags, emptyAssembly, flags&16 != 0 && flags&4 == 0)
}

func checkedObjectRecords(data []byte, flags uint32, emptyAssembly, sdkCompiler bool) (*checkedGoObject, error) {
	const headerSize = 8 + 8 + 4 + 19*4
	if len(data) < headerSize || len(data) > archiveLimit || string(data[:8]) != "\x00go120ld" {
		return nil, contextError("unknown or truncated binary goobj header")
	}
	// ObjFlagShared, FromAssembly and Unlinkable are outside this prototype.
	if binary.LittleEndian.Uint32(data[16:20]) != flags {
		return nil, contextError("nonordinary compiler object flags")
	}
	var offsets [19]int
	previous := headerSize
	for i := range offsets {
		value := uint64(binary.LittleEndian.Uint32(data[20+4*i:]))
		if value < uint64(previous) || value > uint64(len(data)) {
			return nil, contextError("overlapping, unordered or out-of-range object block")
		}
		offsets[i], previous = int(value), int(value)
	}
	if offsets[18] != len(data) {
		return nil, contextError("object blocks do not cover exact EOF")
	}
	block := func(index int) []byte { return data[offsets[index]:offsets[index+1]] }
	// Check every fixed-record block, including unused reference/aux records.
	widths := [...]int{16, 8, 8, 21, 21, 21, 21, 21, 10, 8, 16, 4, 4, 4, 23, 9, 0, 16}
	for index, width := range widths {
		if width == 0 {
			continue // Raw DATA bytes are bounded by the complete object interval.
		}
		// Index tables contain N+1 entries and are checked exactly below.
		// SDK relocation/Aux work is bounded by its own aligned byte block,
		// not the unrelated number of definitions in a single namespace.
		boundedByBytes := index >= 11 && index <= 13 || sdkCompiler && (index == 14 || index == 15)
		if len(block(index))%width != 0 || !boundedByBytes && len(block(index))/width > symbolLimit {
			return nil, contextError(fmt.Sprintf("invalid or excessive binary block record count: block=%d bytes=%d width=%d records=%d limit=%d",
				index, len(block(index)), width, len(block(index))/width, symbolLimit))
		}
	}
	definitionBlocks := [...]int{3, 4, 5, 6}
	count := 0
	for _, i := range definitionBlocks {
		count += len(block(i)) / 21
	}
	definitionLimit := symbolLimit
	if sdkCompiler {
		definitionLimit *= len(definitionBlocks)
	}
	if count == 0 && !emptyAssembly || count > definitionLimit || len(block(9))/8 != len(block(4))/21 || len(block(10))/16 != len(block(5))/21 {
		return nil, contextError("invalid symbol/hash inventory")
	}
	var indices [3][]uint32
	for slot, spec := range []struct{ index, records, width int }{{11, 14, 23}, {12, 15, 9}, {13, 16, 1}} {
		if len(block(spec.index)) != 4*(count+1) {
			return nil, contextError("missing complete symbol index inventory")
		}
		values := make([]uint32, count+1)
		for i := range values {
			values[i] = binary.LittleEndian.Uint32(block(spec.index)[4*i:])
			if i == 0 && values[i] != 0 || i > 0 && values[i] < values[i-1] || uint64(values[i]) > uint64(len(block(spec.records))/spec.width) {
				return nil, contextError("unordered or overflowing object index")
			}
		}
		if uint64(values[count]) != uint64(len(block(spec.records))/spec.width) {
			return nil, contextError("unconsumed object index tail")
		}
		indices[slot] = values
	}
	stringAt := func(ref []byte) (string, error) {
		length, off := uint64(binary.LittleEndian.Uint32(ref)), uint64(binary.LittleEndian.Uint32(ref[4:]))
		if length > 4096 || off < headerSize || off > uint64(offsets[0]) || length > uint64(offsets[0])-off {
			return "", contextError("object string outside complete string block")
		}
		name := string(data[int(off):int(off+length)])
		if strings.ContainsAny(name, "\x00\r\n") {
			return "", contextError("invalid binary symbol name")
		}
		return name, nil
	}
	// Validate all string-bearing fixed records, not just requested definitions.
	// Reference/auxiliary inventory cannot hide an overflowing string reference.
	for _, spec := range []struct{ index, width, start int }{{0, 16, 0}, {1, 8, 0}, {2, 8, 0}, {3, 21, 0}, {4, 21, 0}, {5, 21, 0}, {6, 21, 0}, {7, 21, 0}, {17, 16, 8}} {
		for pos := 0; pos < len(block(spec.index)); pos += spec.width {
			if _, err := stringAt(block(spec.index)[pos+spec.start : pos+spec.start+8]); err != nil {
				return nil, err
			}
		}
	}
	// The pinned objabi SymKind enum ends at SSEHUNWINDINFO (25).
	// Sxxx (0) is only meaningful for an undefined nonpackage reference.
	for index := 3; index <= 7; index++ {
		for pos := 0; pos < len(block(index)); pos += 21 {
			kind := block(index)[pos+10]
			if kind > 25 || index != 7 && kind == 0 {
				return nil, contextError("unknown or undefined Go symbol kind")
			}
		}
	}
	return &checkedGoObject{block, stringAt, indices, count}, nil
}

func readObjectRole(data []byte, flags uint32, emptyAssembly bool) (map[string]dataRecord, error) {
	object, err := checkedObject(data, flags, emptyAssembly)
	if err != nil {
		return nil, err
	}
	block, stringAt, indices, count := object.block, object.stringAt, object.indices, object.count
	result := make(map[string]dataRecord, count)
	symbols := data[binary.LittleEndian.Uint32(data[32:]):binary.LittleEndian.Uint32(data[48:])]
	for i := 0; i < count; i++ {
		// All five symbol blocks are adjacent, as checked above. Keep DATA's
		// legacy named-definition view separate from indexed TEXT metadata.
		sym := symbols[21*i : 21*(i+1)]
		name, err := stringAt(sym[:8])
		if err != nil {
			return nil, err
		}
		// Content-addressed symbols can share an empty name; they never become
		// requested typed globals. Named duplicate definitions fail closed.
		if name != "" {
			if _, duplicate := result[name]; duplicate {
				return nil, contextError("duplicate native symbol definition")
			}
		}
		r := dataRecord{Name: name, ABI: binary.LittleEndian.Uint16(sym[8:]), Kind: sym[10], Flags: sym[11], Flags2: sym[12],
			Size: int64(binary.LittleEndian.Uint32(sym[13:])), Align: int64(binary.LittleEndian.Uint32(sym[17:]))}
		start, end := int(indices[2][i]), int(indices[2][i+1])
		if end > start {
			r.Data = append([]byte(nil), block(16)[start:end]...)
		}
		for j := indices[0][i]; j < indices[0][i+1]; j++ {
			q := block(14)[int(j)*23 : int(j+1)*23]
			r.Relocations = append(r.Relocations, relocation{int64(int32(binary.LittleEndian.Uint32(q))), int64(q[4]), binary.LittleEndian.Uint16(q[5:])})
		}
		if name != "" {
			result[name] = r
		}
	}
	return result, nil
}
