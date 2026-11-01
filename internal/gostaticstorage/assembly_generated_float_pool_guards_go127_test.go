//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// Alter all three actual objects together. Otherwise their ordinary inequality
// could hide a missing generated-source, payload, hash or relocation check.
func asmGeneratedFloatPoolMutateAll(t *testing.T, request *SDKASMDataObservationRequest, mutation string) {
	t.Helper()
	members, err := archiveMembers(request.Archive)
	if err != nil || len(members) != 3 || len(request.Sources) != 1 {
		t.Fatal("incomplete actual synchronized mutation fixture", err)
	}
	for _, object := range [][]byte{members[2].data, request.Sources[0].OriginalObject, request.Sources[0].ExpandedObject} {
		body, err := objectBody(object, request.Target)
		if err != nil {
			t.Fatal(err)
		}
		view, err := checkedObject(body, sdkAssemblyObjectFlags(request.Target), true)
		if err != nil {
			t.Fatal("original synchronized object precondition", err)
		}
		symbols, err := view.indexedSymbols()
		if err != nil {
			t.Fatal(err)
		}
		var pool uint32
		var relative uint32
		found := false
		for _, symbol := range symbols {
			if symbol.Name == "$f32.80000000" {
				pool, relative, found = symbol.Index, symbol.Relative, true
			}
		}
		if !found {
			t.Fatal("actual negative-zero pool witness is absent")
		}
		block := func(index int) int { return int(binary.LittleEndian.Uint32(body[20+index*4:])) }
		symbol := block(3) + int(pool)*21
		data := block(16) + int(view.indices[2][pool])
		hash := block(9) + int(relative)*8
		relocation := -1
		for _, candidate := range symbols {
			if candidate.Kind != 1 {
				continue
			}
			for index := view.indices[0][candidate.Index]; index < view.indices[0][candidate.Index+1]; index++ {
				offset := block(14) + int(index)*23
				if binary.LittleEndian.Uint32(body[offset+15:]) == 2147483646 &&
					binary.LittleEndian.Uint32(body[offset+19:]) == relative {
					relocation = offset
					break
				}
			}
			if relocation >= 0 {
				break
			}
		}
		if relocation < 0 {
			t.Fatal("actual source owner relocation is absent")
		}
		switch mutation {
		case "pool-name":
			name := int(binary.LittleEndian.Uint32(body[symbol+4:]))
			body[name+len("$f32.80000000")-1] = '1'
		case "pool-ABI":
			body[symbol+8] = 1
		case "pool-kind":
			body[symbol+10] = 5
		case "pool-local-flag":
			body[symbol+11] &^= 2
		case "pool-duplicate-flag":
			body[symbol+11] |= 1
		case "pool-flags2":
			body[symbol+12] = 1
		case "pool-size":
			binary.LittleEndian.PutUint32(body[symbol+13:], 8)
		case "pool-alignment":
			binary.LittleEndian.PutUint32(body[symbol+17:], 8)
		case "pool-bytes":
			body[data] ^= 1
		case "pool-hash":
			body[hash] ^= 1
		case "pool-bytes-and-matching-hash":
			body[data] ^= 1
			body[hash] ^= 1
		case "pool-namespace":
			binary.LittleEndian.PutUint32(body[20+5*4:], uint32(block(5)-21))
		case "owner-offset":
			body[relocation]++
		case "owner-width":
			body[relocation+4] = 1
		case "owner-addend":
			body[relocation+7] = 1
		case "owner-type":
			kind := uint16(1)
			if strings.HasSuffix(request.Target, "/386") {
				kind = 14
			}
			binary.LittleEndian.PutUint16(body[relocation+5:], kind)
		case "owner-namespace":
			binary.LittleEndian.PutUint32(body[relocation+15:], 2147483645)
		case "owner-index":
			binary.LittleEndian.PutUint32(body[relocation+19:], relative+1)
		default:
			t.Fatal("unknown synchronized object negative", mutation)
		}
	}
}

func asmGeneratedFloatPoolGuards(t *testing.T, original SDKASMDataObservationRequest) {
	t.Helper()
	for _, mutation := range []string{
		"pool-name", "pool-ABI", "pool-kind", "pool-local-flag", "pool-duplicate-flag", "pool-flags2",
		"pool-size", "pool-alignment", "pool-bytes", "pool-hash", "pool-bytes-and-matching-hash", "pool-namespace",
		"owner-offset", "owner-width", "owner-addend", "owner-type", "owner-namespace", "owner-index",
	} {
		t.Run(mutation, func(t *testing.T) {
			changed := cloneASMDataRequest(t, original)
			asmGeneratedFloatPoolMutateAll(t, &changed, mutation)
			if bytes.Equal(changed.Archive, original.Archive) {
				t.Fatal("negative failed to change the actual complete archive")
			}
			if observation, err := ObserveX86SDKASMData(changed); !errors.Is(err, ErrContext) || observation != nil {
				t.Fatal("forged generated identity/payload/relocation acquired a source/object observation", err)
			}
		})
	}
	for name, replacement := range map[string]string{
		"source-literal":        "MOVSS $-1.0",
		"source-width":          "MOVSD $-0.0",
		"source-without-FCONST": "XORPS X0",
		"prefix-without-FCONST": "MOVSS \"$f32.80000000\"(SB)",
		"integer-only":          "MOVSS $0",
		"parenthesized-integer": "MOVSS $(0)",
		"binary-floating":       "MOVSS $(1.0*0.0)",
		"mixed-floating":        "MOVSS $(1+0.0)",
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneASMDataRequest(t, original)
			source := bytes.Replace(changed.Sources[0].Original, []byte("MOVSS $-0.0"), []byte(replacement), 1)
			if bytes.Equal(source, changed.Sources[0].Original) {
				t.Fatal("actual source mutation witness is absent")
			}
			changed.Sources[0].Original = source
			changed.Sources[0].Expanded = bytes.ReplaceAll(source, []byte(","), []byte(", "))
			if observation, err := ObserveX86SDKASMData(changed); !errors.Is(err, ErrContext) || observation != nil {
				t.Fatal("an unmatched FCONST source acquired a generated-pool owner", err)
			}
		})
	}
	for _, statement := range []string{"GLOBL ordinary<>(SB),8,$8", "TEXT ·Case1(SB),4,$0-0"} {
		t.Run("missing-"+strings.Fields(statement)[0], func(t *testing.T) {
			changed := cloneASMDataRequest(t, original)
			source := bytes.Replace(changed.Sources[0].Original, []byte(statement), []byte("NOP"), 1)
			if bytes.Equal(source, changed.Sources[0].Original) {
				t.Fatal("actual whole source inventory witness is absent")
			}
			changed.Sources[0].Original = source
			changed.Sources[0].Expanded = bytes.ReplaceAll(source, []byte(","), []byte(", "))
			if observation, err := ObserveX86SDKASMData(changed); !errors.Is(err, ErrContext) || observation != nil {
				t.Fatal("an unknown DATA definition or missing source TEXT borrowed the pool partition", err)
			}
		})
	}
}
