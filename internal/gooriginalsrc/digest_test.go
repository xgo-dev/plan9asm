package gooriginalsrc

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestHashRegularFileExactBytesAndBounds(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, "input")
	for _, size := range []int{0, 1, 65535, 65536, 65537, 1 << 20} {
		data := bytes.Repeat([]byte{0xa5}, size)
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
		digest, err := HashRegularFile(name, int64(size))
		if err != nil || digest != sha256.Sum256(data) {
			t.Fatal("complete bounded bytes changed", size, err)
		}
		if size > 0 {
			if _, err := HashRegularFile(name, int64(size-1)); err == nil {
				t.Fatal("file exceeded the caller's exact byte bound", size)
			}
		}
	}
	for _, limit := range []int64{-1, toolByteLimit + 1} {
		if _, err := HashRegularFile(name, limit); err == nil {
			t.Fatal("invalid bound acquired a physical file observation", limit)
		}
	}
	if _, err := HashRegularFile(directory, toolByteLimit); err == nil {
		t.Fatal("directory became a regular-file digest")
	}
}

func TestHashRegularFileConcurrentPoolIsolation(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for index := 0; index < 8; index++ {
		name := filepath.Join(directory, string(rune('a'+index)))
		data := bytes.Repeat([]byte{byte(index)}, 65537+index)
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
		want := sha256.Sum256(data)
		workers.Add(1)
		go func(name string, want [32]byte) {
			defer workers.Done()
			for round := 0; round < 8; round++ {
				actual, err := HashRegularFile(name, toolByteLimit)
				if err != nil || actual != want {
					t.Error("pooled buffer mixed independent physical files", err)
					return
				}
			}
		}(name, want)
	}
	workers.Wait()
}
