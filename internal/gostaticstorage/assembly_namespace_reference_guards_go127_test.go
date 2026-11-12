//go:build go1.27

package gostaticstorage

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func copySDKReferencedArchives(original map[string]SDKReferencedArchive) map[string]SDKReferencedArchive {
	result := make(map[string]SDKReferencedArchive, len(original))
	for path, archive := range original {
		archive.Sources = append([]string(nil), archive.Sources...)
		archive.Archive = append([]byte(nil), archive.Archive...)
		result[path] = archive
	}
	return result
}

func sdkReferencedCompiler(t *testing.T, archive []byte, target string) ([]byte, *checkedGoObject) {
	t.Helper()
	members, err := archiveMembers(archive)
	if err != nil {
		t.Fatal(err)
	}
	body, err := objectBody(members[1].data, target)
	if err != nil {
		t.Fatal(err)
	}
	object, err := checkedObject(body, 16, false)
	if err != nil {
		t.Fatal(err)
	}
	return body, object
}

func TestGoSDKAssemblyReferencedArchiveBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			target := "linux/" + arch
			archive, builtin, dependencies := indexedForeignArchiveFixture(t, arch)
			if _, err := ObserveX86SDKAssemblyArchiveReferences(archive, builtin, target, []string{"entry.s"}, dependencies); err != nil {
				t.Fatal("complete actual indexed-reference precondition", err)
			}
			_, atomic := sdkReferencedCompiler(t, dependencies["sync/atomic"].Archive, target)
			selfCount := uint32(len(atomic.block(3)) / 21)
			originalBody, original := sdkReferencedCompiler(t, archive, target)
			var auxiliaryOffset int
			for position := 0; position < len(original.block(15)); position += 9 {
				auxiliary := original.block(15)[position : position+9]
				pkg := binary.LittleEndian.Uint32(auxiliary[1:])
				if pkg == 0 || pkg >= uint32(len(original.block(1))/8) {
					continue
				}
				path, err := original.stringAt(original.block(1)[int(pkg)*8 : int(pkg+1)*8])
				if err != nil {
					t.Fatal(err)
				}
				if path == "sync/atomic" && auxiliary[0] == 0 {
					auxiliaryOffset = int(binary.LittleEndian.Uint32(originalBody[20+4*15:])) + position
					break
				}
			}
			if auxiliaryOffset == 0 {
				t.Fatal("actual Aux-only foreign boundary is absent")
			}

			for _, test := range []struct {
				name   string
				mutate func(map[string]SDKReferencedArchive)
			}{
				{"missing target", func(values map[string]SDKReferencedArchive) { delete(values, "sync/atomic") }},
				{"missing archive", func(values map[string]SDKReferencedArchive) {
					value := values["sync/atomic"]
					value.Archive = nil
					values["sync/atomic"] = value
				}},
				{"wrong package", func(values map[string]SDKReferencedArchive) {
					value := values["sync/atomic"]
					value.PackagePath = "internal/cpu"
					values["sync/atomic"] = value
				}},
				{"wrong key", func(values map[string]SDKReferencedArchive) {
					values["../sync/atomic"] = values["sync/atomic"]
				}},
				{"missing assembly member", func(values map[string]SDKReferencedArchive) {
					value := values["sync/atomic"]
					value.Sources = nil
					values["sync/atomic"] = value
				}},
				{"foreign assembly member", func(values map[string]SDKReferencedArchive) {
					value := values["sync/atomic"]
					value.Sources[0] = "foreign.s"
					values["sync/atomic"] = value
				}},
				{"foreign compiler member", func(values map[string]SDKReferencedArchive) {
					value := values["sync/atomic"]
					members, err := archiveMembers(value.Archive)
					if err != nil {
						t.Fatal(err)
					}
					value.Archive[int(members[1].offset)-60] = 'x'
					values["sync/atomic"] = value
				}},
				{"truncated archive", func(values map[string]SDKReferencedArchive) {
					value := values["sync/atomic"]
					value.Archive = value.Archive[:len(value.Archive)-1]
					values["sync/atomic"] = value
				}},
			} {
				t.Run(test.name, func(t *testing.T) {
					changed := copySDKReferencedArchives(dependencies)
					test.mutate(changed)
					if _, err := ObserveX86SDKAssemblyArchiveReferences(archive, builtin, target, []string{"entry.s"}, changed); !errors.Is(err, ErrContext) {
						t.Fatal("invalid referenced archive acquired metadata", err)
					}
				})
			}
			for _, bound := range []uint32{selfCount, selfCount + 1, selfCount + uint32(len(atomic.block(4))/21), math.MaxUint32} {
				t.Run("NSym boundary", func(t *testing.T) {
					changed := append([]byte(nil), archive...)
					body, _ := sdkReferencedCompiler(t, changed, target)
					binary.LittleEndian.PutUint32(body[auxiliaryOffset+5:], bound)
					if _, err := ObserveX86SDKAssemblyArchiveReferences(changed, builtin, target, []string{"entry.s"}, dependencies); !errors.Is(err, ErrContext) {
						t.Fatal("foreign SymIdx crossed into a hashed/nonpackage namespace", bound, err)
					}
				})
			}
			for _, flags := range []uint32{0, 4, 17, 24} {
				t.Run("compiler flags", func(t *testing.T) {
					changed := copySDKReferencedArchives(dependencies)
					body, _ := sdkReferencedCompiler(t, changed["sync/atomic"].Archive, target)
					binary.LittleEndian.PutUint32(body[16:], flags)
					if _, err := ObserveX86SDKAssemblyArchiveReferences(archive, builtin, target, []string{"entry.s"}, changed); !errors.Is(err, ErrContext) {
						t.Fatal("foreign flags acquired SDK indexed metadata", flags, err)
					}
				})
			}
			other := "linux/amd64"
			if arch == "amd64" {
				other = "linux/386"
			}
			if _, err := ObserveX86SDKAssemblyArchiveReferences(archive, builtin, other, []string{"entry.s"}, dependencies); !errors.Is(err, ErrContext) {
				t.Fatal("referenced archive changed target identity", err)
			}
			for _, abi := range []uint16{2, 65535} {
				t.Run("unknown or object-local ABI", func(t *testing.T) {
					changed := copySDKReferencedArchives(dependencies)
					body, _ := sdkReferencedCompiler(t, changed["sync/atomic"].Archive, target)
					index := binary.LittleEndian.Uint32(originalBody[auxiliaryOffset+5:])
					start := int(binary.LittleEndian.Uint32(body[20+4*3:])) + int(index)*21
					binary.LittleEndian.PutUint16(body[start+8:], abi)
					if _, err := ObserveX86SDKAssemblyArchiveReferences(archive, builtin, target, []string{"entry.s"}, changed); !errors.Is(err, ErrContext) {
						t.Fatal("foreign target guessed an unknown/object-local ABI", abi, err)
					}
				})
			}
			if len(original.block(17)) == 0 {
				t.Fatal("actual source object lacks diagnostic-name negative control")
			}
			changed := append([]byte(nil), archive...)
			body, _ := sdkReferencedCompiler(t, changed, target)
			start := int(binary.LittleEndian.Uint32(body[20+4*17:]))
			copy(body[start:start+8], originalBody[auxiliaryOffset+1:auxiliaryOffset+9])
			if _, err := ObserveX86SDKAssemblyArchiveReferences(changed, builtin, target, []string{"entry.s"}, dependencies); !errors.Is(err, ErrContext) {
				t.Fatal("diagnostic RefName overrode actual compiler index identity", err)
			}
		})
	}
}
