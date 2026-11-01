package gotoolprofile

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func instrumentationDeclarationMemoOriginal(t *testing.T, target string) (string, []byte) {
	t.Helper()
	proof := instrumentationExportEnvironmentFixture(t)
	name := "src/cmd/go/internal/cfg/cfg.go"
	original, present := proof.SourceDeclarations[name+"#"+target]
	if !present {
		t.Fatalf("missing complete fixture declaration %s", target)
	}
	return name, []byte("package replay\n" + original + "\n")
}

func TestInstrumentationExportDeclarationMemoMatchesParserAndOwnsBytes(t *testing.T) {
	proof := instrumentationExportEnvironmentFixture(t)
	memo := newInstrumentationExportDeclarationMemo(64, 8<<20)
	for key, original := range proof.SourceDeclarations {
		name, target, _ := strings.Cut(key, "#")
		data := []byte("package replay\n" + original + "\n")
		want, err := parseInstrumentationExportDeclaration(name, data, target)
		if err != nil || want.declarations != 1 {
			t.Fatalf("original parser: %v", err)
		}
		for i := 0; i < 3; i++ {
			got, err := memo.replay(name, data, target)
			if err != nil || got != want {
				t.Fatalf("memo differs from original parser for %s: %v", key, err)
			}
		}
		data[0] = '!'
		if _, err := memo.replay(name, data, target); err == nil {
			t.Fatal("changed caller bytes borrowed a prior parse")
		}
		got, err := memo.replay(name, []byte("package replay\n"+original+"\n"), target)
		if err != nil || got != want {
			t.Fatalf("caller mutated the memo's original bytes: %v", err)
		}
	}
	if len(memo.entries) != len(proof.SourceDeclarations) || len(memo.order) != len(memo.entries) {
		t.Fatal("repeated or failed inputs occupied additional entries")
	}
}

func TestInstrumentationExportDeclarationMemoExactInputsAndDeclarationCount(t *testing.T) {
	name, data := instrumentationDeclarationMemoOriginal(t, "EnvOrAndChanged")
	memo := newInstrumentationExportDeclarationMemo(8, 8<<20)
	want, err := memo.replay(name, data, "EnvOrAndChanged")
	if err != nil {
		t.Fatal(err)
	}
	key := instrumentationExportDeclarationKey{name, "EnvOrAndChanged", bytesSHA256(data)}
	entry := memo.entries[key]
	// Simulate an equal index with different original bytes. The index cannot
	// replace the exact-byte comparison or supply the retained projection.
	entry.original = strings.Repeat("x", len(data))
	entry.result.text, entry.result.digest = "invented", "invented"
	memo.entries[key] = entry
	got, err := memo.replay(name, data, "EnvOrAndChanged")
	if err != nil || got != want || len(memo.entries) != 1 {
		t.Fatalf("index collision borrowed an unrelated result: %v", err)
	}
	commented := append(append([]byte(nil), data...), []byte("\n// a distinct exact original\n")...)
	got, err = memo.replay(name, commented, "EnvOrAndChanged")
	if err != nil || got != want || len(memo.entries) != 2 {
		t.Fatalf("different originals were conflated: %v", err)
	}
	extra := append(append([]byte(nil), data...), []byte("\nfunc additional() {}\n")...)
	got, err = memo.replay(name, extra, "EnvOrAndChanged")
	if err != nil || got.text != want.text || got.digest != want.digest || got.declarations != 2 {
		t.Fatalf("complete source declaration count was lost: %v", err)
	}
	proof := instrumentationExportEnvironmentFixture(t)
	proof.SourceDeclarations[name+"#EnvOrAndChanged"] += "\nfunc additional() {}\n"
	if err := validateInstrumentationExportEnvironment(proof); err == nil {
		t.Fatal("a warmed parse authorized an additional projected declaration")
	}
}

func TestInstrumentationExportDeclarationMemoBoundsAndNonAdmission(t *testing.T) {
	name, data := instrumentationDeclarationMemoOriginal(t, "EnvOrAndChanged")
	probe := newInstrumentationExportDeclarationMemo(4, 8<<20)
	if _, err := probe.replay(name, data, "EnvOrAndChanged"); err != nil {
		t.Fatal(err)
	}
	entryBytes := probe.bytes
	for _, input := range []struct {
		entries, bytes int
		wantEntries    int
	}{
		{1, entryBytes, 1}, {1, entryBytes - 1, 0},
		{0, entryBytes, 0}, {-1, entryBytes, 0}, {1, 0, 0},
	} {
		memo := newInstrumentationExportDeclarationMemo(input.entries, input.bytes)
		for i := 0; i < 2; i++ {
			if _, err := memo.replay(name, data, "EnvOrAndChanged"); err != nil {
				t.Fatal(err)
			}
		}
		if len(memo.entries) != input.wantEntries || memo.bytes > input.bytes {
			t.Fatalf("entry/original/derived-byte bound changed: %+v", input)
		}
	}
	memo := newInstrumentationExportDeclarationMemo(2, 8<<20)
	for _, target := range []string{"EnvOrAndChanged", "GOAMD64", "GOARM64"} {
		name, data := instrumentationDeclarationMemoOriginal(t, target)
		if _, err := memo.replay(name, data, target); err != nil {
			t.Fatal(err)
		}
	}
	if len(memo.entries) != 2 || len(memo.order) != 2 || memo.order[0].target != "GOAMD64" || memo.order[1].target != "GOARM64" {
		t.Fatal("entry eviction is not bounded FIFO")
	}
	count := memo.bytes
	for _, input := range []struct {
		name, target string
		data         []byte
		wantError    bool
	}{
		{"unknown.go", "EnvOrAndChanged", data, false},
		{name, "missing", data, true},
		{name, "EnvOrAndChanged", []byte("package replay\nfunc EnvOrAndChanged() {}\n"), false},
		{name, "EnvOrAndChanged", []byte("package replay\nfunc EnvOrAndChanged("), true},
		{name, "EnvOrAndChanged", append(append([]byte(nil), data...), data[len("package replay\n"):]...), true},
	} {
		_, err := memo.replay(input.name, input.data, input.target)
		if (err != nil) != input.wantError || len(memo.entries) != 2 || memo.bytes != count {
			t.Fatalf("failed or unregistered parse was retained: %+v, %v", input, err)
		}
	}
	bounded := newInstrumentationExportDeclarationMemo(8, entryBytes*2-1)
	if _, err := bounded.replay(name, data, "EnvOrAndChanged"); err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.replay(name, append(append([]byte(nil), data...), '\n'), "EnvOrAndChanged"); err != nil {
		t.Fatal(err)
	}
	if len(bounded.entries) != 1 || len(bounded.order) != 1 || bounded.bytes > bounded.maxBytes {
		t.Fatal("original plus derived bytes did not trigger eviction")
	}
}

func TestInstrumentationExportDeclarationMemoConcurrentImmutableResults(t *testing.T) {
	name, data := instrumentationDeclarationMemoOriginal(t, "EnvOrAndChanged")
	want, err := parseInstrumentationExportDeclaration(name, data, "EnvOrAndChanged")
	if err != nil {
		t.Fatal(err)
	}
	memo := newInstrumentationExportDeclarationMemo(8, 8<<20)
	errors := make(chan error, 16)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 16; j++ {
				got, err := memo.replay(name, data, "EnvOrAndChanged")
				if err != nil || got != want {
					errors <- fmt.Errorf("concurrent original replay changed: %v", err)
					return
				}
				got.text, got.digest, got.declarations = "changed", "changed", 99
			}
		}()
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if len(memo.entries) != 1 || len(memo.order) != 1 {
		t.Fatal("concurrent exact inputs acquired independent retained entries")
	}
}
