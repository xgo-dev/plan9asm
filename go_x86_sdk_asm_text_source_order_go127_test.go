//go:build go1.27

package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoX86SDKASMDataOriginalBytealgTextSourceOrder(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "internal/bytealg")
	source, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal("complete actual original SDK DATA/TEXT metadata", err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	observed := source.observation.Objects
	if len(observed.Sources) != len(source.guard.selection.SFiles) || len(observed.Sources) < 5 {
		t.Fatal("metadata dropped an original selected source")
	}
	found := false
	for ordinal, original := range observed.Sources {
		if len(original.TextOrder) != len(original.Original.Texts) ||
			!reflect.DeepEqual(original.Original.Texts, original.Expanded.Texts) ||
			!reflect.DeepEqual(original.Original.Texts, observed.Members[ordinal+2].Texts) {
			t.Fatal("association replaced complete original/expanded/compiler code/PC/relocation evidence")
		}
		if original.Name != "equal_amd64.s" {
			continue
		}
		found = true
		if len(original.TextOrder) != 3 || original.Original.Texts[0].Name != "memeqbody" ||
			original.Original.Texts[0].ABI != 65535 || original.Original.Texts[0].Namespace != gostaticstorage.TextSymbolSelf {
			t.Fatal("the actual private helper was moved out of its original physical bank")
		}
		var order []int
		var names []string
		for _, association := range original.TextOrder {
			order = append(order, association.ObjectOrdinal)
			names = append(names, association.Name)
		}
		if !reflect.DeepEqual(order, []int{1, 2, 0}) ||
			!reflect.DeepEqual(names, []string{"runtime.memequal", "runtime.memequal_varlen", "memeqbody"}) {
			t.Fatal("complete source TEXT ordinal mapping differs", order, names)
		}
	}
	if !found || source.guard.ready || source.guard.request.NumericalReads != nil {
		t.Fatal("TEXT association omitted source or granted numerical/native authority")
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("live original source/code/PC/relocation observation changed", err)
	}
	// A source-ordinal association cannot replace original code equality.
	for _, role := range []string{"original", "expanded"} {
		var changed gostaticstorage.SDKASMDataObservationRequest
		raw, err := json.Marshal(source.observation.ObjectInputs)
		if err != nil || json.Unmarshal(raw, &changed) != nil {
			t.Fatal("clone complete original observation", err)
		}
		for index, original := range observed.Sources {
			if original.Name != "equal_amd64.s" {
				continue
			}
			code := original.Original.Texts[0].Code
			object := &changed.Sources[index].OriginalObject
			if role == "expanded" {
				object = &changed.Sources[index].ExpandedObject
			}
			start := bytes.Index(*object, code)
			if start < 0 || len(code) == 0 || bytes.Index((*object)[start+1:], code) >= 0 {
				t.Fatal("actual complete helper code lacks a unique physical interval")
			}
			(*object)[start] ^= 1
		}
		if value, err := gostaticstorage.ObserveX86SDKCPPASMData(changed); value != nil || !errors.Is(err, gostaticstorage.ErrContext) {
			t.Fatal("source mapping disguised changed original/expanded machine code", role, err)
		}
	}
	source.observation.Objects.Sources[0].TextOrder[0].SourceOrdinal++
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("mutated source/object ordinal association survived live verification", err)
	}
}
