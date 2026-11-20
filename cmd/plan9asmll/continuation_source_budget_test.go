package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestContinuationReferenceInventoryBounds(t *testing.T) {
	t.Run("reference-files", func(t *testing.T) {
		directory := t.TempDir()
		for index := 0; index < continuationReferenceFiles; index++ {
			if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("reference_%04d.h", index)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if names, err := continuationReferenceNames(directory); err != nil || len(names) != continuationReferenceFiles {
			t.Fatalf("exact file boundary: %d %v", len(names), err)
		}
		if err := os.WriteFile(filepath.Join(directory, "extra.h"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := continuationReferenceNames(directory); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatalf("unbounded reference representation: %v", err)
		}
	})
	t.Run("ignored-directory-entries", func(t *testing.T) {
		directory := t.TempDir()
		for index := 0; index < continuationDirectoryEntries; index++ {
			if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("ignored_%04d.note", index)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if names, err := continuationReferenceNames(directory); err != nil || len(names) != 0 {
			t.Fatalf("exact enumeration boundary: %d %v", len(names), err)
		}
		if err := os.WriteFile(filepath.Join(directory, "extra.note"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := continuationReferenceNames(directory); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatalf("unbounded directory enumeration: %v", err)
		}
	})
}

func TestContinuationReferenceReadChargesBeforeRetention(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "reference.h")
	if err := os.WriteFile(filename, []byte("ab"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, initial := range []int64{-1, continuationReferenceBytes - 1, continuationReferenceBytes + 1} {
		total := initial
		record, err := readContinuationReference(filename, &total)
		if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || record.data != nil || total != initial {
			t.Fatalf("invalid/oversized representation was retained: initial=%d total=%d error=%v", initial, total, err)
		}
	}
	total := int64(continuationReferenceBytes - 2)
	if record, err := readContinuationReference(filename, &total); err != nil || total != continuationReferenceBytes || string(record.data) != "ab" {
		t.Fatalf("exact aggregate boundary: total=%d error=%v", total, err)
	}
	if err := os.Truncate(filename, continuationReferenceBytes+1); err != nil {
		t.Fatal(err)
	}
	total = 0
	if record, err := readContinuationReference(filename, &total); !errors.Is(err, plan9asm.ErrProbeNeedsContext) || record.data != nil || total != 0 {
		t.Fatalf("oversized actual file allocated a source tape: %v", err)
	}
}
