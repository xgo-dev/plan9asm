package gotoolprofile

import "sync"

// Retain only immutable output from pure parsing of exact original bytes.
// Every caller still checks the complete SDK version, source digests, projected
// declaration count and AST registrations. Physical captures/rechecks still
// read all source files. This is neither a proof cache nor object evidence.
var instrumentationExportDeclarations = newInstrumentationExportDeclarationMemo(64, 8<<20)

type instrumentationExportDeclarationKey struct {
	name, target, sourceSHA string
}

type instrumentationExportDeclarationEntry struct {
	original string
	result   instrumentationExportDeclarationResult
	bytes    int
}

type instrumentationExportDeclarationMemo struct {
	mu                   sync.Mutex
	maxEntries, maxBytes int
	bytes                int
	entries              map[instrumentationExportDeclarationKey]instrumentationExportDeclarationEntry
	order                []instrumentationExportDeclarationKey
}

func newInstrumentationExportDeclarationMemo(maxEntries, maxBytes int) *instrumentationExportDeclarationMemo {
	return &instrumentationExportDeclarationMemo{
		maxEntries: maxEntries, maxBytes: maxBytes,
		entries: make(map[instrumentationExportDeclarationKey]instrumentationExportDeclarationEntry),
	}
}

func (memo *instrumentationExportDeclarationMemo) replay(name string, data []byte, target string) (instrumentationExportDeclarationResult, error) {
	key := instrumentationExportDeclarationKey{name, target, bytesSHA256(data)}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if entry, present := memo.entries[key]; present && entry.original == string(data) {
		return entry.result, nil
	}

	result, err := parseInstrumentationExportDeclaration(name, data, target)
	if err != nil {
		return result, err
	}
	registered, known := instrumentationExportEnvironmentRegistrations[name+"#"+target]
	byteCount := len(data) + len(name) + len(target) + len(key.sourceSHA) + len(result.text) + len(result.digest)
	// Unknown or changed successful parses preserve their original result but
	// cannot occupy retained entries. Derived strings are counted as well as
	// inputs; there are no retained mutable AST nodes or caller-owned slices.
	if !known || result.digest != registered || memo.maxEntries <= 0 || byteCount > memo.maxBytes {
		return result, nil
	}
	if entry, present := memo.entries[key]; present {
		memo.remove(key, entry)
	}
	for len(memo.entries) >= memo.maxEntries || memo.bytes+byteCount > memo.maxBytes {
		oldest := memo.order[0]
		memo.remove(oldest, memo.entries[oldest])
	}
	entry := instrumentationExportDeclarationEntry{string(data), result, byteCount}
	memo.entries[key] = entry
	memo.order = append(memo.order, key)
	memo.bytes += byteCount
	return result, nil
}

func (memo *instrumentationExportDeclarationMemo) remove(key instrumentationExportDeclarationKey, entry instrumentationExportDeclarationEntry) {
	delete(memo.entries, key)
	memo.bytes -= entry.bytes
	for i, existing := range memo.order {
		if existing == key {
			copy(memo.order[i:], memo.order[i+1:])
			memo.order[len(memo.order)-1] = instrumentationExportDeclarationKey{}
			memo.order = memo.order[:len(memo.order)-1]
			break
		}
	}
}
