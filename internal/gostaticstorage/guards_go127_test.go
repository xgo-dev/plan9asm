//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func objectBytes(t *testing.T, archive []byte) []byte {
	t.Helper()
	for pos := 8; pos+60 <= len(archive); {
		header := archive[pos : pos+60]
		size, err := strconv.Atoi(strings.TrimSpace(string(header[48:58])))
		if err != nil || size <= 0 || size > len(archive)-pos-60 {
			t.Fatal("test input lacks actual archive member")
		}
		pos += 60
		if strings.TrimSpace(string(header[:16])) == "_go_.o" {
			object := archive[pos : pos+size]
			end := bytes.Index(object, []byte("\n!\n"))
			if end < 0 {
				t.Fatal("test input lacks actual object text header")
			}
			return object[end+3:]
		}
		pos += size + size%2
	}
	t.Fatal("test input lacks actual compiler object")
	return nil
}

func blockOffset(object []byte, block int) int {
	return int(binary.LittleEndian.Uint32(object[20+4*block:]))
}

func symbolIndex(t *testing.T, object []byte, name string) int {
	t.Helper()
	first, end := blockOffset(object, 3), blockOffset(object, 7)
	for pos := first; pos < end; pos += 21 {
		length := int(binary.LittleEndian.Uint32(object[pos:]))
		off := int(binary.LittleEndian.Uint32(object[pos+4:]))
		if string(object[off:off+length]) == name {
			return (pos - first) / 21
		}
	}
	t.Fatal("actual native symbol missing", name)
	return 0
}

func TestGoStaticStorageBinaryBoundaryGuards(t *testing.T) {
	dir, binaryPath, _ := fixture(t)
	selected := run(t, binaryPath, dir, fixtureEnv(t, "linux/amd64"), selectionArguments()...)
	var root Package
	decoder := json.NewDecoder(bytes.NewReader(selected))
	for root.ImportPath != fixtureModule {
		if err := decoder.Decode(&root); err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.ReadFile(root.Export)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readArchive(original, "linux/amd64"); err != nil {
		t.Fatal("actual positive control", err)
	}
	for name, mutate := range map[string]func([]byte){
		"archive magic":   func(a []byte) { a[0] ^= 1 },
		"member overflow": func(a []byte) { copy(a[8+48:8+58], "9999999999") },
		"unknown member":  func(a []byte) { copy(a[8:8+16], "unknown_member  ") },
		"goobj magic":     func(a []byte) { objectBytes(t, a)[0] ^= 1 },
		"object flags":    func(a []byte) { binary.LittleEndian.PutUint32(objectBytes(t, a)[16:], 1) },
		"backwards block": func(a []byte) {
			o := objectBytes(t, a)
			binary.LittleEndian.PutUint32(o[20+4*4:], uint32(blockOffset(o, 3)-1))
		},
		"overflow block": func(a []byte) { binary.LittleEndian.PutUint32(objectBytes(t, a)[20+4*14:], ^uint32(0)) },
		"unconsumed EOF": func(a []byte) {
			o := objectBytes(t, a)
			binary.LittleEndian.PutUint32(o[20+4*18:], uint32(len(o)-1))
		},
		"partial fixed record": func(a []byte) {
			o := objectBytes(t, a)
			binary.LittleEndian.PutUint32(o[20+4*4:], uint32(blockOffset(o, 4)+1))
		},
		"nonzero index start": func(a []byte) {
			o := objectBytes(t, a)
			binary.LittleEndian.PutUint32(o[blockOffset(o, 13):], 1)
		},
		"overflow index": func(a []byte) {
			o := objectBytes(t, a)
			binary.LittleEndian.PutUint32(o[blockOffset(o, 13)+4:], ^uint32(0))
		},
		"string outside block": func(a []byte) {
			o := objectBytes(t, a)
			binary.LittleEndian.PutUint32(o[blockOffset(o, 3)+4:], uint32(len(o)))
		},
		"overflow string length": func(a []byte) {
			o := objectBytes(t, a)
			binary.LittleEndian.PutUint32(o[blockOffset(o, 3):], ^uint32(0))
		},
		"duplicate definition": func(a []byte) {
			o := objectBytes(t, a)
			keys := blockOffset(o, 3) + 21*symbolIndex(t, o, fixtureModule+".Keys")
			data := blockOffset(o, 3) + 21*symbolIndex(t, o, fixtureModule+".Data")
			copy(o[data:data+8], o[keys:keys+8])
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]byte(nil), original...)
			mutate(changed)
			if _, err := readArchive(changed, "linux/amd64"); !errors.Is(err, ErrContext) {
				t.Fatalf("malformed binary accepted: %v", err)
			}
		})
	}
	for _, target := range []string{"linux/386", "linux/arm64", "unknown/amd64"} {
		t.Run("wrong-target-"+target, func(t *testing.T) {
			if _, err := readArchive(original, target); !errors.Is(err, ErrContext) {
				t.Fatal("object target changed but accepted")
			}
		})
	}
}

func TestGoStaticStorageRetainedRelocationAndLayoutGuards(t *testing.T) {
	dir, binaryPath, _ := fixture(t)
	req := request(t, dir, binaryPath, "linux/amd64")
	req.Variables = append(req.Variables, Reference{fixtureModule, "TwiceRelocated"})
	o, report := captured(t, req)
	for name, mutate := range map[string]func([]byte, int){
		"unsupported relocation":   func(object []byte, pos int) { binary.LittleEndian.PutUint16(object[pos+5:], 0xffff) },
		"invalid relocation width": func(object []byte, pos int) { object[pos+4] = 3 },
		"negative relocation":      func(object []byte, pos int) { binary.LittleEndian.PutUint32(object[pos:], ^uint32(0)) },
		"outside relocation":       func(object []byte, pos int) { binary.LittleEndian.PutUint32(object[pos:], 1<<20) },
		"overlap relocation":       func(object []byte, pos int) { copy(object[pos+23:pos+27], object[pos:pos+4]) },
		"extent mismatch": func(object []byte, _ int) {
			pos := blockOffset(object, 3) + 21*symbolIndex(t, object, fixtureModule+".Keys")
			binary.LittleEndian.PutUint32(object[pos+13:], 47)
		},
		"BSS changed into empty DATA": func(object []byte, _ int) {
			pos := blockOffset(object, 3) + 21*symbolIndex(t, object, fixtureModule+".Keys")
			object[pos+10] = 5
		},
		"nonordinary native flags": func(object []byte, _ int) {
			pos := blockOffset(object, 3) + 21*symbolIndex(t, object, fixtureModule+".Keys")
			object[pos+11] = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneReport(t, report)
			object := objectBytes(t, changed.Archives[fixtureModule])
			idx := symbolIndex(t, object, fixtureModule+".TwiceRelocated")
			rel := binary.LittleEndian.Uint32(object[blockOffset(object, 11)+idx*4:])
			pos := blockOffset(object, 14) + int(rel)*23
			mutate(object, pos)
			// Recompute the outer hash so reconstruction, not a stale digest,
			// rejects invalid compiler records. The sealed producer also rejects.
			changed.ArchiveSHA256[fixtureModule] = digest(changed.Archives[fixtureModule])
			if !errors.Is(ValidateReport(changed), ErrContext) || !errors.Is(o.CheckReport(context.Background(), changed), ErrContext) {
				t.Fatal("invalid data/layout record acquired numerical storage")
			}
		})
	}
}

func TestGoStaticStorageNumericalDoesNotGrantPointerStorage(t *testing.T) {
	dir, binaryPath, _ := fixture(t)
	for _, name := range []string{"PointerOnly", "StringOnly", "SliceOnly", "MapOnly", "ComplexOnly", "BlankOnly", "ZeroSize"} {
		t.Run(name, func(t *testing.T) {
			req := request(t, dir, binaryPath, "linux/amd64")
			req.Variables = []Reference{{fixtureModule, name}}
			o, err := Capture(context.Background(), req)
			if !errors.Is(err, ErrContext) {
				if o != nil {
					o.Close()
				}
				t.Fatalf("non-numerical/header/blank/empty storage granted: %v", err)
			}
		})
	}
	// uintptr is initialized numeric bits only; there is deliberately no API
	// in this package that grants an address/pointer or translation permission.
	req := request(t, dir, binaryPath, "linux/amd64")
	req.Variables = []Reference{{fixtureModule, "Address"}}
	_, report := captured(t, req)
	if len(report.Variables) != 1 || len(report.Variables[0].Numerical) != 1 || report.Variables[0].Numerical[0] != (Span{0, 8}) {
		t.Fatal("uintptr lost numerical byte definition")
	}
}

func TestGoStaticStorageSelectionDisplayBoundary(t *testing.T) {
	original := []byte(`{"ImportPath":"owner","Stale":true,"StaleReason":"build ID mismatch","Future":{"A":1}}`)
	stable := []byte(`{"ImportPath":"owner","Future":{"A":1}}`)
	if !sameSelection(original, stable) {
		t.Fatal("typed cache display is not source/import/export identity")
	}
	for _, bad := range []string{
		`{"ImportPath":"other","Future":{"A":1}}`,
		`{"ImportPath":"owner","Future":{"A":2}}`,
		`{"ImportPath":"owner","Stale":null,"Future":{"A":1}}`,
		`{"ImportPath":"owner","Stale":"true","Future":{"A":1}}`,
		`{"ImportPath":"owner","StaleReason":false,"Future":{"A":1}}`,
		string(stable) + "garbage",
		string(stable) + string(stable),
	} {
		if sameSelection(original, []byte(bad)) {
			t.Fatal("unknown field/input/trailing record was washed away", bad)
		}
	}
}
