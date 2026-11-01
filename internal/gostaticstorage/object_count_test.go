package gostaticstorage

import (
	"encoding/binary"
	"errors"
	"testing"
)

// Every definition owns three N+1 index entries, including a mandatory final
// sentinel. The ordinary definition limit stays strict. This structural test
// also runs with the minimum compiler, independently of SDK capture support.
func TestGoObjectDefinitionLimitIncludesIndexSentinel(t *testing.T) {
	for _, count := range []int{symbolLimit - 1, symbolLimit, symbolLimit + 1} {
		data := goObjectDefinitionCountsFixture([4]int{count}, 0)
		_, err := checkedObject(data, 0, false)
		if count <= symbolLimit && err != nil {
			t.Error("complete legal ordinary N+1 index inventory rejected", count, err)
		} else if count > symbolLimit && !errors.Is(err, ErrContext) {
			t.Error("ordinary definition bound widened", count, err)
		}
	}
}

// This builds only the structural definition/index inventories. It is not a
// source observation or a complete executable TEXT/body fixture.
func goObjectDefinitionCountsFixture(definitions [4]int, flags uint32) []byte {
	const headerSize = 8 + 8 + 4 + 19*4
	var blocks [18][]byte
	total := 0
	for namespace, count := range definitions {
		total += count
		block := make([]byte, 21*count)
		for offset := 0; offset < len(block); offset += 21 {
			binary.LittleEndian.PutUint32(block[offset+4:], headerSize)
			block[offset+10] = 3
		}
		blocks[3+namespace] = block
	}
	blocks[9] = make([]byte, 8*definitions[1])
	blocks[10] = make([]byte, 16*definitions[2])
	for _, block := range []int{11, 12, 13} {
		blocks[block] = make([]byte, 4*(total+1))
	}
	data := make([]byte, headerSize)
	copy(data, "\x00go120ld")
	binary.LittleEndian.PutUint32(data[16:], flags)
	for index, block := range blocks {
		binary.LittleEndian.PutUint32(data[20+4*index:], uint32(len(data)))
		data = append(data, block...)
	}
	binary.LittleEndian.PutUint32(data[20+4*18:], uint32(len(data)))
	return data
}

func TestGoSDKCompilerDefinitionNamespaceBounds(t *testing.T) {
	for _, row := range []struct {
		name        string
		definitions [4]int
		flags       uint32
		ordinary    bool
		accept      bool
	}{
		{"separate-namespaces", [4]int{22152, 515, 45159, 6976}, 16, false, true},
		{"four-namespace-bound", [4]int{symbolLimit, symbolLimit, symbolLimit, symbolLimit}, 16, false, true},
		{"ordinary-total-stays-bounded", [4]int{symbolLimit, 1}, 16, true, false},
		{"nonstandard-has-no-SDK-role", [4]int{symbolLimit, 1}, 0, false, false},
		{"assembly-has-no-compiler-role", [4]int{symbolLimit, 1}, 20, false, false},
		{"self-overflow", [4]int{symbolLimit + 1}, 16, false, false},
		{"hashed64-overflow", [4]int{1, symbolLimit + 1}, 16, false, false},
		{"hashed-overflow", [4]int{1, 0, symbolLimit + 1}, 16, false, false},
		{"nonpackage-overflow", [4]int{1, 0, 0, symbolLimit + 1}, 16, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			data := goObjectDefinitionCountsFixture(row.definitions, row.flags)
			var err error
			if row.ordinary {
				_, err = checkedObject(data, row.flags, false)
			} else {
				_, err = checkedSDKObject(data, row.flags, false)
			}
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrContext) {
				t.Fatal("definition namespace role or resource bound differs", err)
			}
		})
	}
}

func TestGoSDKCompilerBodyRejectsMalformedIntervalsAndIndices(t *testing.T) {
	for _, mutation := range []string{"flags", "header-offset", "truncated", "missing-sentinel",
		"nonzero-first", "overflowing-tail", "relocation-width", "auxiliary-width", "object-bytes"} {
		t.Run(mutation, func(t *testing.T) {
			data := goObjectDefinitionCountsFixture([4]int{1}, 16)
			offset := func(index int) int {
				return int(binary.LittleEndian.Uint32(data[20+4*index:]))
			}
			switch mutation {
			case "flags":
				binary.LittleEndian.PutUint32(data[16:], 0)
			case "header-offset":
				binary.LittleEndian.PutUint32(data[20:], ^uint32(0))
			case "truncated":
				data = data[:len(data)-1]
			case "missing-sentinel":
				at := offset(12) - 4
				data = append(data[:at:at], data[at+4:]...)
				for index := 12; index <= 18; index++ {
					binary.LittleEndian.PutUint32(data[20+4*index:], uint32(offset(index)-4))
				}
			case "nonzero-first":
				binary.LittleEndian.PutUint32(data[offset(11):], 1)
			case "overflowing-tail":
				binary.LittleEndian.PutUint32(data[offset(11)+4:], ^uint32(0))
			case "relocation-width", "auxiliary-width":
				first := 15
				if mutation == "auxiliary-width" {
					first = 16
				}
				data = append(data, 0)
				for index := first; index <= 18; index++ {
					binary.LittleEndian.PutUint32(data[20+4*index:], uint32(offset(index)+1))
				}
			case "object-bytes":
				// Make a structurally bounded raw-DATA interval whose complete
				// object exceeds the existing byte budget by exactly one byte.
				indexTail := offset(13) + 4
				padding := archiveLimit + 1 - len(data)
				data = append(data, make([]byte, padding)...)
				binary.LittleEndian.PutUint32(data[indexTail:], uint32(padding))
				for index := 17; index <= 18; index++ {
					binary.LittleEndian.PutUint32(data[20+4*index:], uint32(len(data)))
				}
			}
			if _, err := checkedSDKObject(data, 16, false); !errors.Is(err, ErrContext) {
				t.Fatal("SDK role accepted malformed or oversized object", err)
			}
		})
	}
}
