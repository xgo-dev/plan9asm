package plan9asm

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This test-only inventory checks retained records, not argument placement or
// source authority. In particular, no wrapper is manufactured when one is
// absent, and a returned record never becomes a carrier or entry certificate.
func amd64ArgumentWrapperInventory(generated, selected []gostaticstorage.TextRecord, native string) (gostaticstorage.TextRecord, bool, error) {
	fail := func() (gostaticstorage.TextRecord, bool, error) {
		return gostaticstorage.TextRecord{}, false, amd64GoArgumentContext("incomplete or ambiguous original wrapper inventory")
	}
	if native == "" || len(generated) == 0 || len(selected) == 0 ||
		len(generated) > gostaticstorage.ObjectSymbolInventoryLimit || len(selected) > gostaticstorage.ObjectSymbolInventoryLimit {
		return fail()
	}
	find := func(records []gostaticstorage.TextRecord) (gostaticstorage.TextRecord, int) {
		var result gostaticstorage.TextRecord
		count := 0
		for _, record := range records {
			if record.Name == native && record.ABI == 0 {
				result, count = record, count+1
			}
		}
		return result, count
	}
	first, firstCount := find(generated)
	second, secondCount := find(selected)
	if firstCount == 0 && secondCount == 0 {
		return gostaticstorage.TextRecord{}, false, nil // An explicit absence, not a successful placement proof.
	}
	if firstCount != 1 || secondCount != 1 || first.Kind != 1 || first.Flags2&64 == 0 ||
		first.Namespace != gostaticstorage.TextSymbolSelf && first.Namespace != gostaticstorage.TextSymbolNonpkgDefinition ||
		first.Size <= 0 || first.Size != int64(len(first.Code)) || first.Namespace != second.Namespace ||
		first.Kind != second.Kind || first.Flags != second.Flags || first.Flags2 != second.Flags2 ||
		first.Size != second.Size || !bytes.Equal(first.Code, second.Code) || !reflect.DeepEqual(first.Relocations, second.Relocations) {
		return fail()
	}
	calls := 0
	for _, relocation := range first.Relocations {
		if relocation.Target.Name != native {
			continue
		}
		// Go1.27's already registered R_CALL record must identify an actual
		// direct near CALL field. This does not decode or certify its inputs.
		if relocation.Type != 7 || relocation.Size != 4 || relocation.Add != 0 ||
			relocation.Offset < 1 || relocation.Offset > int64(len(first.Code))-4 ||
			first.Code[relocation.Offset-1] != 0xe8 || !relocation.Target.ABIKnown || relocation.Target.ABI != 1 {
			return fail()
		}
		calls++
	}
	if calls != 1 {
		return fail()
	}
	return first, true, nil
}

func TestAMD64GoArgumentWrapperInventoryCompleteRecords(t *testing.T) {
	for _, namespace := range []gostaticstorage.TextSymbolNamespace{gostaticstorage.TextSymbolSelf, gostaticstorage.TextSymbolNonpkgDefinition} {
		input := numericalCompilerAliasModel(false)
		input.Generated[0].Namespace = namespace
		input.Selected[0].Namespace = namespace
		if namespace == gostaticstorage.TextSymbolSelf {
			input.Generated[0].Flags2, input.Selected[0].Flags2 = 64, 64
		}
		if _, present, err := amd64ArgumentWrapperInventory(input.Generated, input.Selected, input.Native); err != nil || !present {
			t.Fatal("matched original candidate was not inventoried", err)
		}
		if record, present, err := amd64ArgumentWrapperInventory(input.Generated, input.Selected, "example.invalid/remote.Absent"); err != nil || present || record.Name != "" {
			t.Fatal("absence was replaced with a manufactured wrapper", record, present, err)
		}
	}
}

func TestAMD64GoArgumentWrapperInventoryRejectsPartialOrAmbiguousRecords(t *testing.T) {
	for name, mutate := range map[string]func(*numericalCompilerAliasInput){
		"missing-generated": func(input *numericalCompilerAliasInput) { input.Generated = nil },
		"missing-selected":  func(input *numericalCompilerAliasInput) { input.Selected = nil },
		"one-sided-absence": func(input *numericalCompilerAliasInput) { input.Generated[0].Name += "Other" },
		"duplicate-generated": func(input *numericalCompilerAliasInput) {
			input.Generated = append(input.Generated, input.Generated[0])
		},
		"duplicate-selected": func(input *numericalCompilerAliasInput) {
			input.Selected = append(input.Selected, input.Selected[0])
		},
		"not-wrapper": func(input *numericalCompilerAliasInput) { input.Generated[0].Flags2 &^= 64 },
		"wrong-kind":  func(input *numericalCompilerAliasInput) { input.Generated[0].Kind = 2 },
		"wrong-code":  func(input *numericalCompilerAliasInput) { input.Generated[0].Code = []byte{0xcc} },
		"namespace": func(input *numericalCompilerAliasInput) {
			input.Generated[0].Namespace = gostaticstorage.TextSymbolHashed
		},
		"not-call-opcode": func(input *numericalCompilerAliasInput) {
			input.Generated[0].Code = []byte{0xe9, 0, 0, 0, 0, 0xc3}
			input.Selected[0].Code = append([]byte(nil), input.Generated[0].Code...)
		},
		"wrong-call-relocation": func(input *numericalCompilerAliasInput) {
			input.Generated[0].Relocations = append([]gostaticstorage.TextRelocation(nil), input.Generated[0].Relocations...)
			input.Generated[0].Relocations[0].Type = 14
			input.Selected[0].Relocations = append([]gostaticstorage.TextRelocation(nil), input.Generated[0].Relocations...)
		},
		"unknown-call-ABI": func(input *numericalCompilerAliasInput) {
			input.Generated[0].Relocations = append([]gostaticstorage.TextRelocation(nil), input.Generated[0].Relocations...)
			input.Generated[0].Relocations[0].Target.ABIKnown = false
			input.Selected[0].Relocations = append([]gostaticstorage.TextRelocation(nil), input.Generated[0].Relocations...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := numericalCompilerAliasModel(false)
			mutate(&input)
			if _, present, err := amd64ArgumentWrapperInventory(input.Generated, input.Selected, input.Native); present || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("partial records became an original wrapper candidate", present, err)
			}
		})
	}
}
