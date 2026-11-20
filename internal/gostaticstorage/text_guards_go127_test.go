//go:build go1.27

package gostaticstorage

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
)

func textFixtureRecord(t *testing.T) (*Observation, Report, []byte, *checkedGoObject, TextRecord) {
	t.Helper()
	dir, driver, _ := fixture(t)
	observation, report := captured(t, request(t, dir, driver, "linux/amd64"))
	members, err := archiveMembers(report.Archives[fixtureModule])
	if err != nil {
		t.Fatal(err)
	}
	body, err := objectBody(members[1].data, report.Target)
	if err != nil {
		t.Fatal(err)
	}
	object, err := checkedObject(body, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range report.TextArchives[fixtureModule][1].Texts {
		if value.Name == fixtureModule+".Read" {
			return observation, report, body, object, value
		}
	}
	t.Fatal("actual first-party Go TEXT is missing")
	return nil, Report{}, nil, nil, TextRecord{}
}

func TestGoStaticStorageTEXTReportMutationGuards(t *testing.T) {
	o, report, _, _, _ := textFixtureRecord(t)
	for name, mutate := range map[string]func(*Report){
		"protocol":       func(r *Report) { r.TextProtocol += "changed" },
		"no protocol":    func(r *Report) { r.TextProtocol = "" },
		"builtin bytes":  func(r *Report) { r.TextBuiltinSource[0] ^= 1 },
		"missing source": func(r *Report) { r.TextBuiltinSource = nil },
		"missing owner":  func(r *Report) { delete(r.TextArchives, fixtureModule) },
		"extra owner":    func(r *Report) { r.TextArchives[fixtureModule+"/other"] = r.TextArchives[fixtureModule] },
		"missing member": func(r *Report) { r.TextArchives[fixtureModule] = r.TextArchives[fixtureModule][:1] },
		"member order": func(r *Report) {
			m := r.TextArchives[fixtureModule]
			m[0], m[1] = m[1], m[0]
		},
		"member offset":  func(r *Report) { r.TextArchives[fixtureModule][1].Offset++ },
		"member flags":   func(r *Report) { r.TextArchives[fixtureModule][1].Flags |= 4 },
		"code":           func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Code[0] ^= 1 },
		"size":           func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Size++ },
		"text index":     func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Index++ },
		"text namespace": func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Namespace = TextSymbolHashed },
		"relative index": func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Relative++ },
		"content hash":   func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Hash = []byte{1, 2, 3} },
		"text ABI":       func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].ABI++ },
		"text kind":      func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Kind++ },
		"addend":         func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Relocations[0].Add++ },
		"relocation offset": func(r *Report) {
			r.TextArchives[fixtureModule][1].Texts[1].Relocations[0].Offset++
		},
		"relocation width": func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Relocations[0].Size++ },
		"relocation kind":  func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Relocations[0].Type++ },
		"known ABI": func(r *Report) {
			r.TextArchives[fixtureModule][1].Texts[1].Relocations[0].Target.ABIKnown = false
		},
		"symbol index":  func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Relocations[0].Target.SymbolIndex++ },
		"symbol kind":   func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Relocations[0].Target.Kind++ },
		"kind known":    func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Relocations[0].Target.KindKnown = true },
		"native symbol": func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Relocations[0].Target.Name += "other" },
		"package":       func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Relocations[2].Target.Package += "/other" },
		"auxiliary":     func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Auxiliary[0].Type++ },
		"PC interval":   func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Positions[0].End++ },
		"source file":   func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Positions[0].File += ".other" },
		"source line":   func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].Positions[0].Line++ },
		"pcfile bytes":  func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].PCFile[0] ^= 1 },
		"pcline bytes":  func(r *Report) { r.TextArchives[fixtureModule][1].Texts[1].PCLine[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneReport(t, report)
			mutate(&changed)
			if !errors.Is(ValidateReport(changed), ErrContext) || !errors.Is(o.CheckReport(context.Background(), changed), ErrContext) {
				t.Fatal("edited TEXT metadata acquired a live/source or binary agreement role")
			}
		})
	}
	o.Close()
	if !errors.Is(o.CheckReport(context.Background(), report), ErrContext) {
		t.Fatal("closed TEXT observation retained authority")
	}
}

func TestGoStaticStorageTEXTBinaryMutationGuards(t *testing.T) {
	_, report, original, view, text := textFixtureRecord(t)
	builtins, err := textBuiltins(report.TextBuiltinSource)
	if err != nil {
		t.Fatal(err)
	}
	blockOffset := func(index int) int { return int(binary.LittleEndian.Uint32(original[20+4*index:])) }
	symbol := blockOffset(3) + int(text.Index)*21
	relocation := blockOffset(14) + int(view.indices[0][text.Index])*23
	auxiliary := blockOffset(15) + int(view.indices[1][text.Index])*9
	pcfile, unusedAux := -1, -1
	for index := 0; index < view.count; index++ {
		for j := view.indices[1][index]; j < view.indices[1][index+1]; j++ {
			position := blockOffset(15) + int(j)*9
			if index == int(text.Index) && original[position] == 8 {
				id := int(binary.LittleEndian.Uint32(original[position+5:])) + len(view.block(3))/21 + len(view.block(4))/21
				pcfile = blockOffset(16) + int(view.indices[2][id])
			}
			if original[blockOffset(3)+index*21+10] != 1 {
				unusedAux = position
			}
		}
	}
	if pcfile < 0 || unusedAux < 0 || len(view.block(17)) < 16 {
		t.Fatal("actual object did not supply the required mutation roles")
	}
	for name, mutate := range map[string]func([]byte){
		"magic":               func(b []byte) { b[0] ^= 1 },
		"flags":               func(b []byte) { b[16] ^= 4 },
		"unordered blocks":    func(b []byte) { binary.LittleEndian.PutUint32(b[20+4*4:], uint32(blockOffset(3)-1)) },
		"block overflow":      func(b []byte) { binary.LittleEndian.PutUint32(b[20+4*6:], math.MaxUint32) },
		"data index overflow": func(b []byte) { binary.LittleEndian.PutUint32(b[blockOffset(13)+4*int(text.Index):], math.MaxUint32) },
		"unknown relocation":  func(b []byte) { binary.LittleEndian.PutUint16(b[relocation+5:], math.MaxUint16) },
		"relocation extent":   func(b []byte) { binary.LittleEndian.PutUint32(b[relocation:], uint32(len(text.Code)+1)) },
		"negative relocation": func(b []byte) { binary.LittleEndian.PutUint32(b[relocation:], math.MaxUint32) },
		"invalid nil reference": func(b []byte) {
			binary.LittleEndian.PutUint32(b[relocation+15:], 0)
			binary.LittleEndian.PutUint32(b[relocation+19:], 1)
		},
		"unknown package": func(b []byte) { binary.LittleEndian.PutUint32(b[relocation+15:], math.MaxUint32) },
		"self index":      func(b []byte) { binary.LittleEndian.PutUint32(b[relocation+19:], math.MaxUint32) },
		"builtin index": func(b []byte) {
			binary.LittleEndian.PutUint32(b[relocation+15:], 2147483644)
			binary.LittleEndian.PutUint32(b[relocation+19:], uint32(len(builtins)))
		},
		"unknown symbol kind": func(b []byte) { b[symbol+10] = 255 },
		"defined symbol string": func(b []byte) {
			binary.LittleEndian.PutUint32(b[symbol+4:], math.MaxUint32)
		},
		"unknown TEXT aux":   func(b []byte) { b[auxiliary] = 255 },
		"unknown unused aux": func(b []byte) { b[unusedAux] = 255 },
		"PC file index":      func(b []byte) { b[pcfile] = 126 },
		"PC zero delta":      func(b []byte) { b[pcfile+1] = 0 },
		"PC extent overflow": func(b []byte) { b[pcfile+1]++ },
		"PC varint overflow": func(b []byte) { b[pcfile] = 128; b[pcfile+1] = 128; b[pcfile+2] = 128 },
		"code extent":        func(b []byte) { binary.LittleEndian.PutUint32(b[symbol+13:], uint32(text.Size+1)) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]byte(nil), original...)
			mutate(changed)
			if _, err := readTextObject(changed, "linux/amd64", 0, false, builtins); !errors.Is(err, ErrContext) {
				t.Fatal("malformed original Go object metadata was admitted", err)
			}
		})
	}
	t.Run("duplicate reference", func(t *testing.T) {
		changed := append(append([]byte(nil), original...), view.block(17)[:16]...)
		binary.LittleEndian.PutUint32(changed[20+4*18:], uint32(len(changed)))
		if _, err := readTextObject(changed, "linux/amd64", 0, false, builtins); !errors.Is(err, ErrContext) {
			t.Fatal("duplicate complete reference-name record was admitted", err)
		}
	})
}

func TestGoStaticStorageTEXTPCTableBounds(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":          nil,
		"truncated":      {128},
		"overflow":       {128, 128, 128, 128, 16},
		"noncanonical":   {130, 0, 2, 0},
		"zero distance":  {2, 0, 0},
		"incomplete":     {2, 1, 0},
		"tail":           {2, 2, 0, 0},
		"outside extent": {2, 3, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := textPCTable(data, 2, 1); !errors.Is(err, ErrContext) {
				t.Fatal("malformed bounded source-PC table acquired an observation", err)
			}
		})
	}
	if spans, err := textPCTable([]byte{2, 2, 0}, 2, 1); err != nil || !reflect.DeepEqual(spans, []pcValueSpan{{0, 2, 0}}) {
		t.Fatal("valid complete source-PC table was rejected", spans, err)
	}
	for _, input := range [][2]int64{{-1, 1}, {0, 1}, {archiveLimit + 1, 1}, {2, 0}, {2, math.MaxInt64}} {
		if _, err := textPCTable([]byte{2, 2, 0}, input[0], input[1]); !errors.Is(err, ErrContext) {
			t.Fatal("invalid logical extent/quantum was accepted", input, err)
		}
	}
}

func TestGoStaticStorageTEXTWasmDistinctExtents(t *testing.T) {
	dir, driver, _ := fixture(t)
	_, report := captured(t, request(t, dir, driver, "js/wasm"))
	members, err := archiveMembers(report.Archives[fixtureModule])
	if err != nil {
		t.Fatal(err)
	}
	body, err := objectBody(members[1].data, report.Target)
	if err != nil {
		t.Fatal(err)
	}
	view, err := checkedObject(body, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	builtins, err := textBuiltins(report.TextBuiltinSource)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range report.TextArchives[fixtureModule][1].Texts {
		if text.Name != fixtureModule+".Read" {
			continue
		}
		if text.Size <= 0 || text.Size >= int64(len(text.Code)) || len(text.Positions) == 0 || text.Positions[len(text.Positions)-1].End != text.Size {
			t.Fatal("actual wasm object lacks distinct complete virtual-PC/physical-code axes", text)
		}
		physicalBeyondPC := false
		for _, r := range text.Relocations {
			physicalBeyondPC = physicalBeyondPC || r.Offset >= text.Size && r.Offset+r.Size <= int64(len(text.Code))
		}
		if !physicalBeyondPC {
			t.Fatal("actual wasm relocations did not witness physical offsets beyond virtual PCs")
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		retainTextArtifact(t, report.Target, "wasm-boundaries", map[string][]byte{
			"text-report.json": encoded, "text-original.a": report.Archives[fixtureModule], "text-original.goobj": body,
		})
		// These direct parser mutations are structural controls only. Neither
		// acquires a live source seal or a native/read permission.
		symbol := int(binary.LittleEndian.Uint32(body[32:])) + int(text.Index)*21
		for _, extent := range []int64{text.Size + 1, 0} {
			changed := append([]byte(nil), body...)
			binary.LittleEndian.PutUint32(changed[symbol+13:], uint32(extent))
			if _, err := readTextObject(changed, report.Target, 0, false, builtins); !errors.Is(err, ErrContext) {
				t.Error("wasm physical bytes masked invalid virtual PC coverage", extent, err)
			}
		}
		changed := append([]byte(nil), body...)
		relocation := int(binary.LittleEndian.Uint32(body[20+4*14:])) + int(view.indices[0][text.Index])*23
		binary.LittleEndian.PutUint32(changed[relocation:], uint32(len(text.Code)+1))
		if _, err := readTextObject(changed, report.Target, 0, false, builtins); !errors.Is(err, ErrContext) {
			t.Fatal("wasm logical PC size masked an out-of-code physical relocation", err)
		}
		t.Logf("actual wasm virtualPC=%d physicalCode=%d relocations=%d", text.Size, len(text.Code), len(text.Relocations))
		return
	}
	t.Fatal("actual wasm Read TEXT was absent")
}

func TestGoStaticStorageTEXTZeroPCMetadataRole(t *testing.T) {
	// No logical PCs means there is no positive pc-value interval. A lone zero
	// is truncated because the first zero is a value delta, not termination.
	for _, tables := range [][2][]byte{
		{{0}, nil}, {nil, {0}}, {{0}, {0}}, {{2, 1, 0}, {2, 1, 0}},
	} {
		if _, err := textPositions(tables[0], tables[1], 0, 1, nil); !errors.Is(err, ErrContext) {
			t.Error("nonempty PC AUX data was ignored at zero logical extent", tables, err)
		}
	}
	if positions, err := textPositions(nil, nil, 0, 1, nil); err != nil || positions != nil {
		t.Fatal("canonical no-PC metadata role was rejected", positions, err)
	}
	if spans, err := textPCTable([]byte{2, 0, 0}, 0, 1); err != nil || !reflect.DeepEqual(spans, []pcValueSpan{{0, 0, 0}}) {
		t.Fatal("actual Go's zero-PC value/distance/terminator role was rejected", spans, err)
	}
}

func TestGoStaticStorageTEXTReferenceAndKindIdentity(t *testing.T) {
	_, report, _, _, text := textFixtureRecord(t)
	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &record); err != nil || string(record["Kind"]) != "1" {
		t.Error("TEXT/FIPS TEXT kind identity was omitted", err)
	}
	var relocations []struct {
		Target struct {
			PackageIndex uint32
			ABIKnown     bool
		}
	}
	if err := json.Unmarshal(record["Relocations"], &relocations); err != nil {
		t.Fatal(err)
	}
	for _, r := range relocations {
		if r.Target.ABIKnown != (r.Target.PackageIndex >= 2147483643) {
			t.Error("an unobserved foreign ABI zero was indistinguishable from an actual local ABI0")
		}
	}
	if report.TextProtocol != TextProtocol {
		t.Fatal("TEXT observations lost their separate protocol")
	}
}
