package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Private verifier unit only. This does not construct a public source/frame
// observation, actual compiler selection or an ASM permission.
func frameInputDigestFixture(t *testing.T, size int) (*GoAMD64FrameSource, string, byte) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, "input")
	data := bytes.Repeat([]byte{0x5a}, size)
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	source := &GoAMD64FrameSource{request: GoAMD64FrameCaptureRequest{Directory: directory},
		owned: directory, ownedInfo: info, directoryInfo: info,
		entries: []string{"input"}, inputs: map[string][32]byte{name: sha256.Sum256(data)}}
	if err := source.verifyInputs(); err != nil {
		t.Fatal("unchanged complete verifier control failed", err)
	}
	return source, name, 0x5a
}

func TestGoAMD64FrameInputVerificationHasBoundedAllocations(t *testing.T) {
	source, _, _ := frameInputDigestFixture(t, 8<<20)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for round := 0; round < 3; round++ {
		if err := source.verifyInputs(); err != nil {
			t.Fatal(err)
		}
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("three complete 8-MiB file verifications allocated %d bytes", allocated)
	if allocated > 4<<20 {
		t.Fatal("digest-only verification allocated whole-file buffers", allocated)
	}
}

func TestGoAMD64FrameInputVerificationReadsTailDespiteSameMetadata(t *testing.T) {
	source, name, original := frameInputDigestFixture(t, 1<<20)
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteAt([]byte{original ^ 1}, info.Size()-1)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(name, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := source.verifyInputs(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("same-size same-time tail mutation escaped complete content verification", err)
	}
}

func TestGoAMD64FrameInputVerificationRetainsInputRole(t *testing.T) {
	for _, mutation := range []string{"missing", "directory", "growth", "truncation"} {
		t.Run(mutation, func(t *testing.T) {
			source, name, _ := frameInputDigestFixture(t, 128)
			switch mutation {
			case "missing":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
			case "growth":
				if err := os.Truncate(name, 129); err != nil {
					t.Fatal(err)
				}
			case "truncation":
				if err := os.Truncate(name, 127); err != nil {
					t.Fatal(err)
				}
			}
			if err := source.verifyInputs(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed physical input retained its verifier role", err)
			}
		})
	}
}
