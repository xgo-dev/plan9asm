package gotoolprofile

import (
	"reflect"
	"sync"
)

// This memo saves only pure parsing of audited registrations. Physical captures
// still read every file, and portable replay still checks every supplied byte,
// digest, version and AST registration. It retains neither source authority nor
// a compiler/object result. Entry and original-byte bounds limit process memory.
var instrumentationRulesMemo = newInstrumentationRuleMemo(16, 8<<20)

type instrumentationRuleMemoKey struct {
	version string
	hashes  [3]string
}

type instrumentationRuleMemoEntry struct {
	originals [3]string
	rules     *InstrumentationSourceRules
	bytes     int
}

type instrumentationRuleMemo struct {
	mu                   sync.Mutex
	maxEntries, maxBytes int
	bytes                int
	entries              map[instrumentationRuleMemoKey]instrumentationRuleMemoEntry
	order                []instrumentationRuleMemoKey
}

func newInstrumentationRuleMemo(maxEntries, maxBytes int) *instrumentationRuleMemo {
	return &instrumentationRuleMemo{
		maxEntries: maxEntries, maxBytes: maxBytes,
		entries: make(map[instrumentationRuleMemoKey]instrumentationRuleMemoEntry),
	}
}

func (memo *instrumentationRuleMemo) replay(root, version string, contents map[string][]byte) (*InstrumentationSourceRules, error) {
	key := instrumentationRuleMemoKey{version: version}
	byteCount := len(version)
	for i, name := range instrumentationRuleSources {
		key.hashes[i] = bytesSHA256(contents[name])
		byteCount += len(contents[name])
	}

	memo.mu.Lock()
	defer memo.mu.Unlock()
	if entry, present := memo.entries[key]; present {
		exact := true
		for i, name := range instrumentationRuleSources {
			if entry.originals[i] != string(contents[name]) {
				exact = false
				break
			}
		}
		if exact {
			return cloneInstrumentationRules(entry.rules, root), nil
		}
	}

	rules, err := parseInstrumentationRuleSources("", version, contents)
	if err != nil {
		return nil, err
	}
	minor, versionErr := goMinor(version)
	// Unknown successful grammar is returned unchanged, but never retained.
	// Only the fixed audited target tables can occupy memo entries; this also
	// bounds derived maps independently of arbitrarily large source grammars.
	if versionErr != nil || minor < 20 || minor > 27 ||
		!reflect.DeepEqual(rules.registration, instrumentationRuleRegistrations(minor)) ||
		memo.maxEntries <= 0 || byteCount > memo.maxBytes {
		rules.root = root
		return rules, nil
	}

	// A digest is only an index. A different exact-byte entry with that index
	// replaces it, rather than borrowing its parsed result or double-counting.
	if entry, present := memo.entries[key]; present {
		memo.remove(key, entry)
	}
	for len(memo.entries) >= memo.maxEntries || memo.bytes+byteCount > memo.maxBytes {
		oldest := memo.order[0]
		memo.remove(oldest, memo.entries[oldest])
	}
	entry := instrumentationRuleMemoEntry{rules: rules, bytes: byteCount}
	for i, name := range instrumentationRuleSources {
		entry.originals[i] = string(contents[name])
	}
	memo.entries[key] = entry
	memo.order = append(memo.order, key)
	memo.bytes += byteCount
	return cloneInstrumentationRules(rules, root), nil
}

func (memo *instrumentationRuleMemo) remove(key instrumentationRuleMemoKey, entry instrumentationRuleMemoEntry) {
	delete(memo.entries, key)
	memo.bytes -= entry.bytes
	for i, existing := range memo.order {
		if existing == key {
			copy(memo.order[i:], memo.order[i+1:])
			memo.order[len(memo.order)-1] = instrumentationRuleMemoKey{}
			memo.order = memo.order[:len(memo.order)-1]
			break
		}
	}
}

func cloneInstrumentationRules(original *InstrumentationSourceRules, root string) *InstrumentationSourceRules {
	result := &InstrumentationSourceRules{
		root: root, version: original.version,
		sources:      copyInstrumentationHashes(original.sources),
		registration: copyInstrumentationHashes(original.registration),
		targets:      make(map[InstrumentationMode]map[string]bool, len(original.targets)),
	}
	for mode, targets := range original.targets {
		copy := make(map[string]bool, len(targets))
		for target, supported := range targets {
			copy[target] = supported
		}
		result.targets[mode] = copy
	}
	return result
}
