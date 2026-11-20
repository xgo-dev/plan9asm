//go:build go1.27

package plan9asm

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoX86SDKLiteralAlignmentIndependentArchiveAndImageGuards(t *testing.T) {
	ctx, _, owner, observed := sdkLiteralAlignmentCapture(t)
	var initializers sdkReadonlyLiteralDataReport
	if json.Unmarshal(owner.report, &initializers) != nil {
		t.Fatal("actual initializer report")
	}
	archives := make(map[string]gostaticstorage.SDKReferencedArchive)
	for path, selection := range observed.guard.imports {
		if path == "unsafe" {
			continue
		}
		data, err := os.ReadFile(selection.Export)
		if err != nil {
			t.Fatal(err)
		}
		archives[path] = gostaticstorage.SDKReferencedArchive{PackagePath: path, Sources: selection.SFiles, Archive: data}
	}
	inventory, err := gostaticstorage.SDKArchiveDefinitionInventory(archives, observed.observation.Target)
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(filepath.Join(observed.guard.owned, "original-linked"))
	if err != nil {
		t.Fatal(err)
	}
	minima, err := sdkLiteralLinkedMinima(image, observed.observation.Target, observed.observation.PackagePath, initializers.Initializers, inventory)
	if err != nil || len(minima) != 2 {
		t.Fatal("independent original source/object/image replay", err)
	}
	duplicated := append([]gostaticstorage.SDKArchiveDefinitionIdentity(nil), inventory...)
	for _, definition := range inventory {
		for _, literal := range initializers.Initializers {
			if definition.Name == literal.Definition.Name {
				definition.PackagePath = "independent/other/source"
				duplicated = append(duplicated, definition)
			}
		}
	}
	if minima, err := sdkLiteralLinkedMinima(image, observed.observation.Target, observed.observation.PackagePath, initializers.Initializers, duplicated); err != nil || len(minima) != 0 {
		t.Fatal("equal source/name/bytes selected a winner from distinct object namespaces", len(minima), err)
	}
	if minima, err := sdkLiteralLinkedMinima(image, "windows/amd64", observed.observation.PackagePath, initializers.Initializers, inventory); minima != nil || err == nil {
		t.Fatal("cross-target linked bytes borrowed a layout role")
	}
	file, err := elf.NewFile(bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	symbols, err := file.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"misaligned-symbol", "writable-section", "insufficient-section-alignment", "changed-initializer"} {
		t.Run(mutation, func(t *testing.T) {
			changed := append([]byte(nil), image...)
			index, sectionIndex := -1, -1
			for ordinal, symbol := range symbols {
				if symbol.Name == initializers.Initializers[0].Definition.Name {
					index, sectionIndex = ordinal, int(symbol.Section)
					break
				}
			}
			if index < 0 || sectionIndex < 0 {
				t.Fatal("independent original ELF symbol")
			}
			section := file.Sections[sectionIndex]
			symbol := symbols[index]
			header := binary.LittleEndian.Uint64(changed[40:]) + uint64(sectionIndex)*uint64(binary.LittleEndian.Uint16(changed[58:]))
			switch mutation {
			case "misaligned-symbol":
				position := file.Section(".symtab").Offset + uint64(index+1)*24 + 8
				binary.LittleEndian.PutUint64(changed[position:], symbol.Value+1)
			case "writable-section":
				binary.LittleEndian.PutUint64(changed[header+8:], uint64(section.Flags|elf.SHF_WRITE))
			case "insufficient-section-alignment":
				binary.LittleEndian.PutUint64(changed[header+48:], 16)
			case "changed-initializer":
				changed[section.Offset+symbol.Value-section.Addr] ^= 1
			}
			if minima, err := sdkLiteralLinkedMinima(changed, observed.observation.Target, observed.observation.PackagePath, initializers.Initializers, inventory); minima != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed actual linked identity/bytes/permissions/placement supplied minimum alignment", len(minima), err)
			}
		})
	}
	var restored GoX86SDKLiteralAlignment
	if json.Unmarshal(observed.report, &restored) != nil || !errors.Is(restored.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("public report reconstructed a private producer")
	}
	if err := observed.Verify(ctx); err != nil {
		t.Fatal("offline controls changed the real original producer", err)
	}
}

func TestGoX86SDKLiteralAlignmentContextReentry(t *testing.T) {
	ctx, source, owner, _ := sdkLiteralAlignmentCapture(t)
	for _, method := range []string{"Err", "Done", "Deadline"} {
		for _, action := range []string{"Verify", "Readback", "Close"} {
			t.Run(method+"/"+action, func(t *testing.T) {
				callback := &sdkASMDataReentrantContext{Context: ctx, method: method}
				observed, err := CaptureGoX86SDKLiteralAlignment(callback, owner)
				if err != nil {
					t.Fatal(err)
				}
				defer observed.Close()
				var nested error
				callback.callback = func() {
					switch action {
					case "Verify":
						nested = observed.Verify(ctx)
					case "Readback":
						_, nested = observed.Readback(ctx)
					case "Close":
						nested = observed.Close()
					}
				}
				callback.armed.Store(true)
				finished := make(chan error, 1)
				go func() { finished <- errors.Join(observed.Verify(callback), nested) }()
				select {
				case err := <-finished:
					if action == "Close" {
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("reentrant close published minimum alignment", err)
						}
					} else if err != nil {
						t.Fatal("link observation callback deadlocked/rejected genuine independent replay", err)
					}
				case <-ctx.Done():
					// The existing original producer budget is unchanged. Join the
					// worker before ending, rather than hiding a leaked command.
					err := <-finished
					t.Fatal("linker callback exceeded its original bounded context", ctx.Err(), err)
				}
				if err := source.Verify(ctx); err != nil {
					t.Fatal("reentry disposed the independent original SDK source", err)
				}
			})
		}
	}
}
