package plan9asm

import (
	"errors"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// These deliberately synthetic records exercise comparison rules only. They
// do not create a ready Source, compiler capture, binding or LLVM permission.
func numericalCompilerAliasModel(standard bool) numericalCompilerAliasInput {
	flag := uint8(16) // Go1.27's separately registered ordinary linkname bit.
	if standard {
		flag = 32
	}
	text := gostaticstorage.TextRecord{Name: "example.invalid/remote.Entry", ABI: 0,
		Namespace: gostaticstorage.TextSymbolNonpkgDefinition, Kind: 1,
		Flags2: flag | 64, Size: 6, Code: []byte{0xe8, 0, 0, 0, 0, 0xc3},
		Relocations: []gostaticstorage.TextRelocation{{Offset: 1, Size: 4, Type: 7,
			Target: gostaticstorage.TextReference{Name: "example.invalid/remote.Entry", ABI: 1, ABIKnown: true}}}}
	return numericalCompilerAliasInput{Native: text.Name, ABI: 1, Standard: standard,
		SymABI:    []byte("def example.invalid/remote.Entry ABIInternal\n"),
		Generated: []gostaticstorage.TextRecord{text}, Selected: []gostaticstorage.TextRecord{text}}
}

func TestNumericalSDKCompilerAliasCompleteComparisonModel(t *testing.T) {
	for _, standard := range []bool{false, true} {
		if err := numericalCompilerAliasAssociation(numericalCompilerAliasModel(standard)); err != nil {
			t.Fatal("complete modeled compiler/selected native association did not join", standard, err)
		}
	}
}

func TestNumericalSDKCompilerAliasCannotBorrowDirectiveOrPartialObject(t *testing.T) {
	for _, standard := range []bool{false, true} {
		for name, change := range map[string]func(*numericalCompilerAliasInput){
			"directive-only":      func(v *numericalCompilerAliasInput) { v.Generated, v.Selected = nil, nil },
			"no-generated-object": func(v *numericalCompilerAliasInput) { v.Generated = nil },
			"no-selected-object":  func(v *numericalCompilerAliasInput) { v.Selected = nil },
			"no-symabi":           func(v *numericalCompilerAliasInput) { v.SymABI = nil },
			"foreign-symabi": func(v *numericalCompilerAliasInput) {
				v.SymABI = []byte("def example.invalid/remote.Other ABIInternal\n")
			},
			"wrong-symabi-ABI": func(v *numericalCompilerAliasInput) {
				v.SymABI = []byte("def example.invalid/remote.Entry ABI0\n")
			},
			"duplicate-symabi":         func(v *numericalCompilerAliasInput) { v.SymABI = append(v.SymABI, v.SymABI...) },
			"unknown-native-ABI":       func(v *numericalCompilerAliasInput) { v.ABI = 65535 },
			"foreign-generated-name":   func(v *numericalCompilerAliasInput) { v.Generated[0].Name += "Other" },
			"missing-linkname-bit":     func(v *numericalCompilerAliasInput) { v.Generated[0].Flags2 = 64 },
			"swapped-directive-kind":   func(v *numericalCompilerAliasInput) { v.Standard = !v.Standard },
			"not-ABI-wrapper":          func(v *numericalCompilerAliasInput) { v.Generated[0].Flags2 &^= 64 },
			"wrong-wrapper-ABI":        func(v *numericalCompilerAliasInput) { v.Generated[0].ABI = 1 },
			"static-wrapper":           func(v *numericalCompilerAliasInput) { v.Generated[0].Namespace = gostaticstorage.TextSymbolSelf },
			"duplicate-wrapper":        func(v *numericalCompilerAliasInput) { v.Generated = append(v.Generated, v.Generated[0]) },
			"unknown-code":             func(v *numericalCompilerAliasInput) { v.Generated[0].Code = nil },
			"different-selected-code":  func(v *numericalCompilerAliasInput) { v.Selected[0].Code = []byte{0xcc} },
			"missing-native-reference": func(v *numericalCompilerAliasInput) { v.Generated[0].Relocations = nil },
			"foreign-native-reference": func(v *numericalCompilerAliasInput) {
				v.Generated[0].Relocations = append([]gostaticstorage.TextRelocation(nil), v.Generated[0].Relocations...)
				v.Generated[0].Relocations[0].Target.Name += "Other"
			},
			"unknown-reference-ABI": func(v *numericalCompilerAliasInput) {
				v.Generated[0].Relocations = append([]gostaticstorage.TextRelocation(nil), v.Generated[0].Relocations...)
				v.Generated[0].Relocations[0].Target.ABIKnown = false
			},
		} {
			t.Run(name+map[bool]string{false: "/linkname", true: "/linknamestd"}[standard], func(t *testing.T) {
				input := numericalCompilerAliasModel(standard)
				change(&input)
				if err := numericalCompilerAliasAssociation(input); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("directive or incomplete compiler object became declaration authority", err)
				}
			})
		}
	}
}
