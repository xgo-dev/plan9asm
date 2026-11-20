//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func cloneASMDataRequest(t *testing.T, request SDKASMDataObservationRequest) SDKASMDataObservationRequest {
	t.Helper()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var result SDKASMDataObservationRequest
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// These controls consume the exact objects made by the positive fixture, not
// synthetic object JSON. The returned observations have no live owner to copy,
// close or revoke; neither mutations nor a pass can create such authority.
func checkASMDataInputGuards(t *testing.T, original SDKASMDataObservationRequest) {
	t.Helper()
	for name, mutate := range map[string]func(*SDKASMDataObservationRequest){
		"non-DUPok-named-storage": func(r *SDKASMDataObservationRequest) {
			clearFlag := func(data []byte) {
				body, err := objectBody(data, r.Target)
				if err != nil {
					t.Fatal(err)
				}
				view, err := checkedObject(body, 20, true)
				if err != nil {
					t.Fatal(err)
				}
				symbols, err := view.indexedSymbols()
				if err != nil {
					t.Fatal(err)
				}
				for _, symbol := range symbols {
					if symbol.Name == "shared" {
						offset := int(binary.LittleEndian.Uint32(body[20+4*3:])) + int(symbol.Index)*21 + 11
						body[offset] &^= 1
					}
				}
			}
			members, err := archiveMembers(r.Archive)
			if err != nil {
				t.Fatal(err)
			}
			for _, member := range members[2:] {
				clearFlag(member.data)
			}
			for index := range r.Sources {
				clearFlag(r.Sources[index].OriginalObject)
				clearFlag(r.Sources[index].ExpandedObject)
				for _, slot := range []*[]byte{&r.Sources[index].Original, &r.Sources[index].Expanded} {
					*slot = bytes.ReplaceAll(*slot, []byte("2|8"), []byte("8"))
				}
			}
		},
		"missing-source":          func(r *SDKASMDataObservationRequest) { r.Sources = r.Sources[:1] },
		"empty-sources":           func(r *SDKASMDataObservationRequest) { r.Sources = nil },
		"extra-source":            func(r *SDKASMDataObservationRequest) { r.Sources = append(r.Sources, r.Sources[0]) },
		"reordered-sources":       func(r *SDKASMDataObservationRequest) { r.Sources[0], r.Sources[1] = r.Sources[1], r.Sources[0] },
		"source-name":             func(r *SDKASMDataObservationRequest) { r.Sources[0].Name = "foreign.s" },
		"source-directory":        func(r *SDKASMDataObservationRequest) { r.Sources[0].Name = "nested/data.s" },
		"source-extension":        func(r *SDKASMDataObservationRequest) { r.Sources[0].Name = "data.asm" },
		"missing-original":        func(r *SDKASMDataObservationRequest) { r.Sources[0].Original = nil },
		"missing-expanded":        func(r *SDKASMDataObservationRequest) { r.Sources[0].Expanded = nil },
		"missing-original-object": func(r *SDKASMDataObservationRequest) { r.Sources[0].OriginalObject = nil },
		"missing-expanded-object": func(r *SDKASMDataObservationRequest) { r.Sources[0].ExpandedObject = nil },
		"foreign-original-object": func(r *SDKASMDataObservationRequest) { r.Sources[0].OriginalObject = r.Sources[1].OriginalObject },
		"foreign-expanded-object": func(r *SDKASMDataObservationRequest) { r.Sources[0].ExpandedObject = r.Sources[1].ExpandedObject },
		"original-program": func(r *SDKASMDataObservationRequest) {
			r.Sources[0].Original = bytes.Replace(r.Sources[0].Original, []byte("RET"), []byte("NOP"), 1)
		},
		"expanded-program": func(r *SDKASMDataObservationRequest) {
			r.Sources[0].Expanded = bytes.Replace(r.Sources[0].Expanded, []byte("RET"), []byte("NOP"), 1)
		},
		"wrong-package":      func(r *SDKASMDataObservationRequest) { r.PackagePath += "/foreign" },
		"empty-package":      func(r *SDKASMDataObservationRequest) { r.PackagePath = "" },
		"wrong-target":       func(r *SDKASMDataObservationRequest) { r.Target = "linux/arm64" },
		"missing-builtin":    func(r *SDKASMDataObservationRequest) { r.BuiltinSource = nil },
		"edited-builtin":     func(r *SDKASMDataObservationRequest) { r.BuiltinSource[0] ^= 1 },
		"archive-tail":       func(r *SDKASMDataObservationRequest) { r.Archive = append(r.Archive, 0) },
		"archive-truncation": func(r *SDKASMDataObservationRequest) { r.Archive = r.Archive[:len(r.Archive)-1] },
		"source-NUL":         func(r *SDKASMDataObservationRequest) { r.Sources[0].Original = append(r.Sources[0].Original, 0) },
		"unknown-header-role": func(r *SDKASMDataObservationRequest) {
			r.Sources[0].Original = append([]byte("#include \"go_asm.h\"\n"), r.Sources[0].Original...)
		},
		"raw-data-value": func(r *SDKASMDataObservationRequest) {
			for _, slot := range []*[]byte{&r.Sources[0].Original, &r.Sources[0].Expanded} {
				*slot = bytes.Replace(*slot, []byte("0x12345"), []byte("0x12346"), 1)
			}
		},
		"raw-global-size": func(r *SDKASMDataObservationRequest) {
			for _, slot := range []*[]byte{&r.Sources[0].Original, &r.Sources[0].Expanded} {
				*slot = bytes.Replace(*slot, []byte("$24"), []byte("$25"), 1)
			}
		},
		"raw-missing-layout": func(r *SDKASMDataObservationRequest) {
			for _, slot := range []*[]byte{&r.Sources[0].Original, &r.Sources[0].Expanded} {
				lines := strings.Split(string(*slot), "\n")
				var kept []string
				for _, line := range lines {
					if !strings.Contains(line, "mutable<>") {
						kept = append(kept, line)
					}
				}
				*slot = []byte(strings.Join(kept, "\n"))
			}
		},
		"raw-extra-layout": func(r *SDKASMDataObservationRequest) {
			for _, slot := range []*[]byte{&r.Sources[0].Original, &r.Sources[0].Expanded} {
				*slot = append(*slot, []byte("GLOBL foreign<>(SB),8,$1\n")...)
			}
		},
		"raw-reordered-globals": func(r *SDKASMDataObservationRequest) {
			for _, slot := range []*[]byte{&r.Sources[0].Original, &r.Sources[0].Expanded} {
				lines := strings.Split(string(*slot), "\n")
				first, second := -1, -1
				for index, line := range lines {
					if strings.HasPrefix(line, "GLOBL integers<>") {
						first = index
					} else if strings.HasPrefix(line, "GLOBL floats<>") {
						second = index
					}
				}
				if first < 0 || second < 0 {
					t.Fatal("actual GLOBL order witness is missing")
				}
				lines[first], lines[second] = lines[second], lines[first]
				*slot = []byte(strings.Join(lines, "\n"))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneASMDataRequest(t, original)
			mutate(&changed)
			if observation, err := ObserveX86SDKASMData(changed); !errors.Is(err, ErrContext) || observation != nil {
				t.Fatal("changed complete source/object input acquired an observation", err)
			}
		})
	}
}

func checkASMDataBinaryGuards(t *testing.T, original SDKASMDataObservationRequest) {
	t.Helper()
	body, err := objectBody(original.Sources[0].OriginalObject, original.Target)
	if err != nil {
		t.Fatal(err)
	}
	view, err := checkedObject(body, 20, true)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := view.indexedSymbols()
	if err != nil {
		t.Fatal(err)
	}
	var integers, pointers, anonymous, text uint32
	found := make(map[string]bool)
	for _, symbol := range symbols {
		switch {
		case symbol.Name == "integers":
			integers, found["integer"] = symbol.Index, true
		case symbol.Name == "pointers":
			pointers, found["pointer"] = symbol.Index, true
		case symbol.Name == "" && symbol.Kind == 7 && !found["anonymous"]:
			anonymous, found["anonymous"] = symbol.Index, true
		case symbol.Kind == 1:
			text, found["text"] = symbol.Index, true
		}
	}
	if len(found) != 4 || len(view.block(10)) == 0 {
		t.Fatal("actual DATA binary guard witnesses are incomplete", found)
	}
	blockOffset := func(block int) int { return int(binary.LittleEndian.Uint32(body[20+block*4:])) }
	symbolOffset := func(index uint32) int { return blockOffset(3) + int(index)*21 }
	dataOffset := func(index uint32) int { return blockOffset(16) + int(view.indices[2][index]) }
	relocation := blockOffset(14) + int(view.indices[0][pointers])*23
	for name, mutate := range map[string]func([]byte){
		"owned-flags":          func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 4) },
		"compiler-flags":       func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 16) },
		"unknown-flags":        func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 20|2) },
		"unknown-kind":         func(b []byte) { b[symbolOffset(integers)+10] = 255 },
		"DATA-size":            func(b []byte) { b[symbolOffset(integers)+13]++ },
		"DATA-alignment":       func(b []byte) { b[symbolOffset(integers)+17]++ },
		"DATA-ABI":             func(b []byte) { b[symbolOffset(integers)+8]++ },
		"DATA-flags":           func(b []byte) { b[symbolOffset(integers)+11] ^= 1 },
		"DATA-byte":            func(b []byte) { b[dataOffset(integers)] ^= 1 },
		"anonymous-DATA-byte":  func(b []byte) { b[dataOffset(anonymous)] ^= 1 },
		"whole-TEXT-byte":      func(b []byte) { b[dataOffset(text)] ^= 1 },
		"content-hash":         func(b []byte) { b[blockOffset(10)] ^= 1 },
		"DATA-string-overflow": func(b []byte) { binary.LittleEndian.PutUint32(b[symbolOffset(integers)+4:], math.MaxUint32) },
		"DATA-index-overflow":  func(b []byte) { binary.LittleEndian.PutUint32(b[blockOffset(13)+int(integers)*4:], math.MaxUint32) },
		"DATA-index-tail": func(b []byte) {
			binary.LittleEndian.PutUint32(b[blockOffset(13)+view.count*4:], uint32(len(view.block(16))-1))
		},
		"relocation-offset":     func(b []byte) { b[relocation]++ },
		"relocation-negative":   func(b []byte) { binary.LittleEndian.PutUint32(b[relocation:], math.MaxUint32) },
		"relocation-width":      func(b []byte) { b[relocation+4]++ },
		"relocation-type":       func(b []byte) { binary.LittleEndian.PutUint16(b[relocation+5:], 2) },
		"relocation-addend":     func(b []byte) { b[relocation+7]++ },
		"relocation-target":     func(b []byte) { b[relocation+19]++ },
		"relocation-overflow":   func(b []byte) { binary.LittleEndian.PutUint32(b[relocation+19:], math.MaxUint32) },
		"relocation-namespace":  func(b []byte) { binary.LittleEndian.PutUint32(b[relocation+15:], 2147483645) },
		"relocation-invalidnil": func(b []byte) { binary.LittleEndian.PutUint32(b[relocation+15:], 0) },
		"hash-count":            func(b []byte) { binary.LittleEndian.PutUint32(b[20+11*4:], uint32(blockOffset(11)-16)) },
		"namespace-crossover":   func(b []byte) { binary.LittleEndian.PutUint32(b[20+4*4:], uint32(blockOffset(4)-21)) },
		"object-EOF":            func(b []byte) { binary.LittleEndian.PutUint32(b[20+18*4:], uint32(len(b)-1)) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneASMDataRequest(t, original)
			changedBody, err := objectBody(changed.Sources[0].OriginalObject, changed.Target)
			if err != nil {
				t.Fatal(err)
			}
			mutate(changedBody)
			if observation, err := ObserveX86SDKASMData(changed); !errors.Is(err, ErrContext) || observation != nil {
				t.Fatal("changed actual object acquired DATA identity/whole-body agreement", err)
			}
		})
	}
}
