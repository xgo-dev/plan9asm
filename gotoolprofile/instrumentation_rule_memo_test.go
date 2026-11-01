package gotoolprofile

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func instrumentationMemoContents(proof *InstrumentationSourceProof) map[string][]byte {
	contents := make(map[string][]byte, len(proof.SourceText))
	for name, text := range proof.SourceText {
		contents[name] = []byte(text)
	}
	return contents
}

func instrumentationMemoBytes(version string, contents map[string][]byte) int {
	count := len(version)
	for _, name := range instrumentationRuleSources {
		count += len(contents[name])
	}
	return count
}

func TestInstrumentationRuleMemoMatchesUncachedAndOwnsOriginalBytes(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	contents := instrumentationMemoContents(proof)
	want, err := parseInstrumentationRuleSources("", proof.GoVersion, contents)
	if err != nil {
		t.Fatal(err)
	}
	memo := newInstrumentationRuleMemo(2, 8<<20)
	for i := 0; i < 3; i++ {
		got, err := memo.replay("", proof.GoVersion, contents)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("memo differs from original parser: %v", err)
		}
		got.targets[InstrumentationRace]["unregistered/target"] = true
	}
	if len(memo.entries) != 1 || len(memo.order) != 1 || memo.bytes != instrumentationMemoBytes(proof.GoVersion, contents) {
		t.Fatal("repeated input occupied additional entries or changed byte accounting")
	}
	contents["VERSION"][0] = 'x'
	if _, err := memo.replay("", proof.GoVersion, contents); err == nil {
		t.Fatal("changed caller bytes reused earlier source validity")
	}
	got, err := memo.replay("", proof.GoVersion, instrumentationMemoContents(proof))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("caller bytes modified retained originals: %v", err)
	}
}

func TestInstrumentationRuleMemoIndexIsNotExactByteAuthority(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	contents := instrumentationMemoContents(proof)
	memo := newInstrumentationRuleMemo(2, 8<<20)
	want, err := memo.replay("", proof.GoVersion, contents)
	if err != nil {
		t.Fatal(err)
	}
	// Put different exact bytes under the same index to exercise the collision
	// branch without claiming a real SHA-256 collision. They must not be a hit.
	key := memo.order[0]
	entry := memo.entries[key]
	entry.originals[0] = "different bytes with the same test index"
	entry.rules = cloneInstrumentationRules(entry.rules, "")
	entry.rules.targets[InstrumentationRace]["unregistered/target"] = true
	memo.entries[key] = entry
	got, err := memo.replay("", proof.GoVersion, contents)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("digest-only lookup borrowed another original: %v", err)
	}
	if memo.entries[key].originals[0] != proof.SourceText["VERSION"] || len(memo.entries) != 1 ||
		len(memo.order) != 1 || memo.bytes != instrumentationMemoBytes(proof.GoVersion, contents) {
		t.Fatal("collision replacement changed bounds or retained mismatching bytes")
	}
}

func TestInstrumentationRuleMemoVersionAndAllSourcesSelectIndependentEntries(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	memo := newInstrumentationRuleMemo(8, 8<<20)
	contents := instrumentationMemoContents(proof)
	if _, err := memo.replay("", proof.GoVersion, contents); err != nil {
		t.Fatal(err)
	}
	for _, name := range instrumentationRuleSources {
		changed := instrumentationMemoContents(proof)
		changed[name] = append(changed[name], []byte("\n// independent original bytes\n")...)
		got, err := memo.replay("", proof.GoVersion, changed)
		want, parseErr := parseInstrumentationRuleSources("", proof.GoVersion, changed)
		if err != nil || parseErr != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("source %s did not select its exact parsed result: %v / %v", name, err, parseErr)
		}
	}
	// This is only parser-key coverage, not an observed SDK version claim.
	alternateVersion := proof.GoVersion[:strings.LastIndex(proof.GoVersion, ".")] + ".999"
	changed := instrumentationMemoContents(proof)
	changed["VERSION"] = []byte(strings.Replace(proof.SourceText["VERSION"], proof.GoVersion, alternateVersion, 1))
	got, err := memo.replay("", alternateVersion, changed)
	if err != nil || got.version != alternateVersion || len(memo.entries) != 5 {
		t.Fatalf("exact source/version keys were folded: %v", err)
	}
	if _, err := memo.replay("", proof.GoVersion, changed); err == nil {
		t.Fatal("warmed alternate version bypassed VERSION validation")
	}
}

func TestInstrumentationRuleMemoBoundsEvictAndOversizedInputsRemainUncached(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	base := instrumentationMemoContents(proof)
	baseBytes := instrumentationMemoBytes(proof.GoVersion, base)
	for name, memo := range map[string]*instrumentationRuleMemo{
		"entry bound": newInstrumentationRuleMemo(2, 8<<20),
		"byte bound":  newInstrumentationRuleMemo(8, 2*baseBytes+100),
	} {
		t.Run(name, func(t *testing.T) {
			var first instrumentationRuleMemoKey
			for i := 0; i < 3; i++ {
				contents := instrumentationMemoContents(proof)
				contents["src/internal/platform/supported.go"] = append(contents["src/internal/platform/supported.go"], []byte(fmt.Sprintf("\n// entry %d\n", i))...)
				if _, err := memo.replay("", proof.GoVersion, contents); err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					first = memo.order[0]
				}
			}
			if _, retained := memo.entries[first]; retained || len(memo.entries) != 2 || len(memo.order) != 2 || memo.bytes > memo.maxBytes {
				t.Fatal("memo did not evict oldest entries within both bounds")
			}
			count := 0
			for _, entry := range memo.entries {
				count += entry.bytes
			}
			if count != memo.bytes {
				t.Fatal("eviction byte accounting differs from retained originals")
			}
		})
	}
	for _, memo := range []*instrumentationRuleMemo{
		newInstrumentationRuleMemo(0, 8<<20),
		newInstrumentationRuleMemo(2, baseBytes-1),
	} {
		for i := 0; i < 2; i++ {
			if _, err := memo.replay("", proof.GoVersion, base); err != nil {
				t.Fatal(err)
			}
		}
		if len(memo.entries) != 0 || len(memo.order) != 0 || memo.bytes != 0 {
			t.Fatal("disabled or oversized input occupied the memo")
		}
	}
}

func TestInstrumentationRuleMemoDoesNotRetainErrorsOrUnregisteredTables(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	memo := newInstrumentationRuleMemo(2, 8<<20)
	for name, contents := range map[string]map[string][]byte{
		"wrong VERSION": instrumentationMemoContents(proof),
		"unknown table": instrumentationMemoContents(proof),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "wrong VERSION" {
				contents["VERSION"] = []byte("wrong\n")
			} else {
				file := "src/internal/platform/supported.go"
				contents[file] = []byte(strings.Replace(string(contents[file]), `case "linux":`, `case "plan9":`, 1))
			}
			for i := 0; i < 2; i++ {
				got, err := memo.replay("", proof.GoVersion, contents)
				want, parseErr := parseInstrumentationRuleSources("", proof.GoVersion, contents)
				if fmt.Sprint(err) != fmt.Sprint(parseErr) || !reflect.DeepEqual(got, want) {
					t.Fatalf("uncached failure/grammar behavior changed: %v / %v", err, parseErr)
				}
			}
			if len(memo.entries) != 0 || len(memo.order) != 0 || memo.bytes != 0 {
				t.Fatal("failed or unaudited registration occupied the memo")
			}
		})
	}
}

func TestInstrumentationRuleMemoConcurrentReplaysHaveIndependentMapsAndRoots(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	contents := instrumentationMemoContents(proof)
	want, err := parseInstrumentationRuleSources("", proof.GoVersion, contents)
	if err != nil {
		t.Fatal(err)
	}
	memo := newInstrumentationRuleMemo(2, 8<<20)
	errors := make(chan error, 16)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			root := fmt.Sprintf("private-root-%d", i)
			got, err := memo.replay(root, proof.GoVersion, contents)
			if err != nil {
				errors <- err
				return
			}
			if !reflect.DeepEqual(got, cloneInstrumentationRules(want, root)) {
				errors <- fmt.Errorf("worker %d received another replay's state", i)
			}
			got.sources["VERSION"] = "changed"
			got.registration["instrumentInit"] = "changed"
			got.targets[InstrumentationRace]["unregistered/target"] = true
		}(i)
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	got, err := memo.replay("", proof.GoVersion, contents)
	if err != nil || !reflect.DeepEqual(got, want) || len(memo.entries) != 1 {
		t.Fatalf("concurrent outputs modified retained state: %v", err)
	}
}
