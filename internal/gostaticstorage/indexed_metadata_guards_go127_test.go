//go:build go1.27

package gostaticstorage

import (
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestGoSDKIndexedMetadataCompleteStructuralGuards(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			original, _ := indexedNamespaceObjectFixture(t, arch)
			complete, err := checkedObject(original, 16, false)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := checkedSDKIndexedMetadata(original, 16, false)
			if err != nil {
				t.Fatal("actual complete metadata precondition", err)
			}
			symbols, err := metadata.selfSymbols()
			if err != nil {
				t.Fatal(err)
			}
			all, err := complete.indexedSymbols()
			if err != nil || !reflect.DeepEqual(symbols, all[:len(complete.block(3))/21]) {
				t.Fatal("metadata-only reader exposed a different or non-SymbolDefs target", err)
			}
			for _, symbol := range symbols {
				if symbol.Namespace != TextSymbolSelf || len(symbol.Hash) != 0 {
					t.Fatal("referenced-only metadata granted a hashed/native body identity", symbol)
				}
			}
			blockOffset := func(block int) int { return int(binary.LittleEndian.Uint32(original[20+4*block:])) }
			check := func(t *testing.T, mutate func([]byte)) {
				t.Helper()
				changed := append([]byte(nil), original...)
				mutate(changed)
				if _, err := checkedSDKIndexedMetadata(changed, 16, false); !errors.Is(err, ErrContext) {
					t.Fatal("invalid original metadata structure acquired a target table", err)
				}
			}
			for _, block := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17} {
				t.Run("record alignment "+strconv.Itoa(block), func(t *testing.T) {
					check(t, func(data []byte) {
						binary.LittleEndian.PutUint32(data[20+4*(block+1):], uint32(blockOffset(block+1)-1))
					})
				})
			}
			for _, block := range []int{9, 10} {
				t.Run("hash count "+strconv.Itoa(block), func(t *testing.T) {
					check(t, func(data []byte) {
						width := 8
						if block == 10 {
							width = 16
						}
						binary.LittleEndian.PutUint32(data[20+4*(block+1):], uint32(blockOffset(block+1)-width))
					})
				})
			}
			for _, block := range []int{11, 12, 13} {
				for _, kind := range []string{"first", "last", "overflow", "count", "decreasing"} {
					t.Run("index "+strconv.Itoa(block)+" "+kind, func(t *testing.T) {
						check(t, func(data []byte) {
							start, end := blockOffset(block), blockOffset(block+1)
							switch kind {
							case "first":
								binary.LittleEndian.PutUint32(data[start:], 1)
							case "last":
								last := binary.LittleEndian.Uint32(data[end-4:])
								if last == 0 {
									t.Fatal("actual index lacks a complete terminal witness")
								}
								binary.LittleEndian.PutUint32(data[end-4:], last-1)
							case "overflow":
								binary.LittleEndian.PutUint32(data[end-4:], math.MaxUint32)
							case "count":
								binary.LittleEndian.PutUint32(data[20+4*(block+1):], uint32(end-4))
							case "decreasing":
								binary.LittleEndian.PutUint32(data[start+4:], 1)
								binary.LittleEndian.PutUint32(data[start+8:], 0)
							}
						})
					})
				}
			}
			for _, block := range []int{3, 4, 5, 6, 7, 17} {
				t.Run("unused string "+strconv.Itoa(block), func(t *testing.T) {
					if len(complete.block(block)) == 0 {
						t.Fatal("actual first-party namespace/string witness is absent", block)
					}
					check(t, func(data []byte) {
						start := blockOffset(block)
						if block == 17 {
							start += 8
						}
						binary.LittleEndian.PutUint32(data[start+4:], uint32(len(data)+1))
					})
				})
			}
			for block := 3; block <= 7; block++ {
				t.Run("unknown kind "+strconv.Itoa(block), func(t *testing.T) {
					check(t, func(data []byte) { data[blockOffset(block)+10] = 26 })
				})
			}
			for block := 3; block <= 6; block++ {
				t.Run("undefined definition "+strconv.Itoa(block), func(t *testing.T) {
					check(t, func(data []byte) { data[blockOffset(block)+10] = 0 })
				})
			}
			t.Run("exact EOF", func(t *testing.T) {
				check(t, func(data []byte) { binary.LittleEndian.PutUint32(data[20+4*18:], uint32(len(data)-1)) })
			})
			t.Run("flags", func(t *testing.T) {
				check(t, func(data []byte) { binary.LittleEndian.PutUint32(data[16:], 20) })
			})
		})
	}
}

func TestGoSDKIndexedMetadataSymbolDefsBoundRemainsStrict(t *testing.T) {
	const headerSize = 8 + 8 + 4 + 19*4
	count := symbolLimit + 1
	var blocks [18][]byte
	blocks[3] = make([]byte, 21*count)
	for offset := 0; offset < len(blocks[3]); offset += 21 {
		binary.LittleEndian.PutUint32(blocks[3][offset+4:], headerSize)
		blocks[3][offset+10] = 3
	}
	for _, block := range []int{11, 12, 13} {
		blocks[block] = make([]byte, 4*(count+1))
	}
	data := make([]byte, headerSize)
	copy(data, "\x00go120ld")
	binary.LittleEndian.PutUint32(data[16:], 16)
	for index, block := range blocks {
		binary.LittleEndian.PutUint32(data[20+4*index:], uint32(len(data)))
		data = append(data, block...)
	}
	binary.LittleEndian.PutUint32(data[20+4*18:], uint32(len(data)))
	if _, err := checkedSDKIndexedMetadata(data, 16, false); !errors.Is(err, ErrContext) ||
		!strings.Contains(err.Error(), "SymbolDefs exceed target metadata bound") {
		t.Fatal("referenced-only streaming widened the actual target metadata bound", err)
	}
}
