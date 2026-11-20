package gostaticstorage

import (
	"errors"
	"testing"
)

func TestSDKCallTextProjectionKeepsStorageAndRequestedNamesSeparate(t *testing.T) {
	calls := map[string]bool{"fixture.Callee": true}
	for _, name := range []string{"unrelated-compiler-DUPok", "unrelated-assembly-DUPok"} {
		t.Run(name, func(t *testing.T) {
			first := indexedObjectSymbol{Namespace: TextSymbolNonpkgDefinition, Name: "fixture.funcdata", ABI: 0, Kind: 3, Flags: 1, Index: 1}
			second := first
			second.Index = 2
			projection := make(sdkAssemblyNamedDefinitions)
			for _, symbol := range []indexedObjectSymbol{first, second} {
				if err := projection.observeCallText(symbol, name == "unrelated-assembly-DUPok", calls); err != nil {
					t.Fatal("unrelated storage blocked a TEXT-only projection", err)
				}
			}
			if len(projection) != 0 {
				t.Fatal("unrelated storage acquired a selected named identity", projection)
			}
			strict := make(sdkAssemblyNamedDefinitions)
			if err := strict.observe(first, false); err != nil {
				t.Fatal(err)
			}
			if err := strict.observe(second, false); !errors.Is(err, ErrContext) {
				t.Fatal("the existing full storage collision observer was weakened", err)
			}
		})
	}
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "requested-TEXT-then-storage", true: "requested-storage-then-TEXT"}[reverse], func(t *testing.T) {
			text := indexedObjectSymbol{Namespace: TextSymbolNonpkgDefinition, Name: "fixture.Callee", Kind: 1}
			storage := text
			storage.Kind, storage.Flags = 3, 1
			first, second := text, storage
			if reverse {
				first, second = second, first
			}
			projection := make(sdkAssemblyNamedDefinitions)
			if err := projection.observeCallText(first, false, calls); err != nil {
				t.Fatal(err)
			}
			if err := projection.observeCallText(second, false, calls); !errors.Is(err, ErrContext) {
				t.Fatal("a requested name crossed TEXT/storage roles", err)
			}
		})
	}
	t.Run("unrelated-TEXT-stays-strict", func(t *testing.T) {
		text := indexedObjectSymbol{Namespace: TextSymbolNonpkgDefinition, Name: "fixture.Other", Kind: 1}
		projection := make(sdkAssemblyNamedDefinitions)
		if err := projection.observeCallText(text, false, calls); err != nil {
			t.Fatal(err)
		}
		if err := projection.observeCallText(text, false, calls); !errors.Is(err, ErrContext) {
			t.Fatal("unrelated duplicate TEXT was hidden by the requested-name projection", err)
		}
	})
}
