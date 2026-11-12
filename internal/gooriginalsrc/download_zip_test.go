package gooriginalsrc

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"
)

// This is only an exact-origin consistency fixture. The test binary is not a
// Go driver, and a DownloadReceipt here cannot mint a package/frame capability.
func originalZIPConsistencyFixture(t *testing.T) (*OriginSet, DownloadReceipt, map[string][]byte) {
	t.Helper()
	cache, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := "example.invalid/zip-guard@v1.0.0"
	root := filepath.Join(cache, key)
	prefix := filepath.Join(cache, "cache", "download", "example.invalid", "zip-guard", "@v", "v1.0.0")
	for _, directory := range []string{root, filepath.Dir(prefix)} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{
		"go.mod":  []byte("module example.invalid/zip-guard\ngo 1.20\n"),
		"value.s": []byte("TEXT ·Value(SB),4,$0-0\n\tRET\n"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(prefix+".mod", files["go.mod"], 0600); err != nil {
		t.Fatal(err)
	}
	writeOriginalZIPFixture(t, prefix+".zip", key, files, "unchanged")
	zipSum, err := dirhash.HashZip(prefix+".zip", dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	modSum, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(files["go.mod"])), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	tool, err := filepath.EvalSymlinks(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewOriginSet(cache, tool)
	if err != nil {
		t.Fatal(err)
	}
	return set, DownloadReceipt{Path: "example.invalid/zip-guard", Version: "v1.0.0", Dir: root,
		Zip: prefix + ".zip", GoMod: prefix + ".mod", Sum: zipSum, GoModSum: modSum}, files
}

func writeOriginalZIPFixture(t *testing.T, name, key string, files map[string][]byte, role string) {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, member := range []string{"go.mod", "value.s"} {
		if _, present := files[member]; !present {
			continue
		}
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: key + "/" + member, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		data := files[member]
		if role == "oversized member" && member == "value.s" {
			if _, err := io.CopyN(entry, zeroOriginalZIPReader{}, fileByteLimit+1); err != nil {
				t.Fatal(err)
			}
		} else if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if role == "duplicate" {
		entry, err := writer.Create(key + "/value.s")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(files["value.s"]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := output.Bytes()
	if role == "dishonest header" || role == "CRC" {
		// Locate the actual central record by its complete original member name.
		member := []byte(key + "/value.s")
		position := bytes.LastIndex(data, member)
		if position < 46 || binary.LittleEndian.Uint32(data[position-46:]) != 0x02014b50 {
			t.Fatal("first-party ZIP did not contain its actual central member record")
		}
		header := data[position-46:]
		if role == "dishonest header" {
			binary.LittleEndian.PutUint32(header[24:], fileByteLimit+1)
		} else {
			header[16] ^= 1
		}
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}

type zeroOriginalZIPReader struct{}

func (zeroOriginalZIPReader) Read(data []byte) (int, error) {
	for i := range data {
		data[i] = 0
	}
	return len(data), nil
}

func TestOriginSetZIPCompleteBoundedMembers(t *testing.T) {
	for _, role := range []string{"unchanged", "oversized member", "dishonest header", "CRC", "duplicate"} {
		t.Run(role, func(t *testing.T) {
			set, receipt, files := originalZIPConsistencyFixture(t)
			writeOriginalZIPFixture(t, receipt.Zip, receipt.Path+"@"+receipt.Version, files, role)
			observed, err := set.Observe(context.Background(), receipt.Path, receipt.Version, receipt)
			if role == "unchanged" {
				if err != nil || observed.Root != receipt.Dir {
					t.Fatal("complete original ZIP/tree positive failed", err)
				}
				if err := set.Verify(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid complete ZIP yielded an exact origin observation")
			}
			if (role == "oversized member" || role == "dishonest header") && !strings.Contains(err.Error(), "ZIP member extent") {
				t.Fatalf("ZIP content was consumed before its retained extent guard: %v", err)
			}
			if err := set.Verify(); err == nil {
				t.Fatal(fmt.Sprintf("failed %s ZIP observation did not permanently revoke", role))
			}
		})
	}
}

type originalCloseFailureFixture struct {
	*bytes.Reader
	failure error
}

func (reader originalCloseFailureFixture) Close() error { return reader.failure }

func TestOriginalMemberHashRequiresClose(t *testing.T) {
	failure := errors.New("first-party member close failure")
	_, err := hashOriginalMembers([]string{"module@v1.0.0/member"}, func(string) (io.ReadCloser, error) {
		return originalCloseFailureFixture{Reader: bytes.NewReader([]byte("complete original bytes")), failure: failure}, nil
	})
	if !errors.Is(err, failure) {
		t.Fatal("Go Hash1 discarded a member close failure", err)
	}
}
