//go:build go1.27

package plan9asm

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestARM64ByteCarrierActualTypedEntryFootprint(t *testing.T) {
	directory, packagePath, cases := arm64ByteCarrierFixture(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoARM64ByteCarrierSource(ctx, arm64ByteCarrierRequest(t, directory, packagePath))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	entries := make(map[string]gostaticstorage.TextRecord)
	for _, text := range source.report.Archive[1].Texts {
		if text.ABI == 1 {
			entries[text.Name] = text
		}
	}
	for _, width := range cases {
		for _, observer := range []bool{false, true} {
			name := strings.ToLower(width.name())
			allocation := int64(32)
			if observer {
				name = "observe_" + name
				allocation = 48
			}
			t.Run(name, func(t *testing.T) {
				declaration := source.declarations[name]
				text := entries[packagePath+"."+name]
				if text.Name == "" {
					t.Fatal("complete actual compiler entry is missing")
				}
				observed, err := arm64ByteCarrierTypedEntry(text, declaration)
				if err != nil {
					t.Fatalf("actual compiler entry footprint/effects are not closed: %v", err)
				}
				if observed.allocation != allocation || observed.dataStart != 8 || observed.dataBytes != allocation-16 ||
					observed.callPC != 16 || observed.continuationPC != 20 || len(observed.parameterStores) != 1 ||
					observed.parameterStores[0].Offset != 8 || observed.parameterStores[0].Bytes != 8 ||
					len(observed.resultLoads) != len(declaration.Frame.Results) {
					t.Fatalf("actual entry region/continuation/typed effects differ: %+v", observed)
				}
				for index, memory := range observed.resultLoads {
					field := declaration.Frame.Results[index]
					if memory.Offset != field.Offset+8 || memory.Bytes != frameTypeSize(field.Type, 8) {
						t.Fatalf("typed entry loaded bytes outside its declared result: %+v", memory)
					}
				}
			})
		}
	}
}

func TestARM64ByteCarrierTypedEntryRejectsIncompleteEffects(t *testing.T) {
	directory, packagePath, cases := arm64ByteCarrierFixture(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoARM64ByteCarrierSource(ctx, arm64ByteCarrierRequest(t, directory, packagePath))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	name := strings.ToLower(cases[0].name())
	var original gostaticstorage.TextRecord
	for _, text := range source.report.Archive[1].Texts {
		if text.Name == packagePath+"."+name && text.ABI == 1 {
			original = text
		}
	}
	if original.Name == "" || len(original.Code) < 36 || len(original.Relocations) != 1 {
		t.Fatal("actual original entry control is missing")
	}
	for _, test := range []struct {
		name   string
		mutate func(*gostaticstorage.TextRecord, *FuncSig)
	}{
		{"foreign-entry", func(text *gostaticstorage.TextRecord, _ *FuncSig) { text.Name += ".foreign" }},
		{"wrong-ABI", func(text *gostaticstorage.TextRecord, _ *FuncSig) { text.ABI = 0 }},
		{"no-allocation", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code, 0xd503201f)
		}},
		{"no-FP-save", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[4:], 0xd503201f)
		}},
		{"no-FP-binding", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[8:], 0xd503201f)
		}},
		{"wrong-param-cell", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[12:], 0xf9000be0)
		}},
		{"missing-direct-call", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[16:], 0xd503201f)
		}},
		{"wrong-call-target", func(text *gostaticstorage.TextRecord, _ *FuncSig) { text.Relocations[0].Target.Name += ".foreign" }},
		{"wrong-call-ABI", func(text *gostaticstorage.TextRecord, _ *FuncSig) { text.Relocations[0].Target.ABI = 1 }},
		{"unknown-call-ABI", func(text *gostaticstorage.TextRecord, _ *FuncSig) { text.Relocations[0].Target.ABIKnown = false }},
		{"call-addend", func(text *gostaticstorage.TextRecord, _ *FuncSig) { text.Relocations[0].Add = 4 }},
		{"call-continuation", func(text *gostaticstorage.TextRecord, _ *FuncSig) { text.Relocations[0].Offset += 4 }},
		{"result-outside-region", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[20:], 0x394083e0)
		}},
		{"lost-FP-restore", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[24:], 0xd503201f)
		}},
		{"wrong-SP-restore", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[28:], 0xf84107fe)
		}},
		{"no-return", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[32:], 0xd503201f)
		}},
		{"executable-tail", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[len(text.Code)-4:], 0xd503201f)
		}},
		{"overlapping-param", func(_ *gostaticstorage.TextRecord, signature *FuncSig) { signature.Frame.Params[0].Offset = 8 }},
		{"padding-as-result", func(_ *gostaticstorage.TextRecord, signature *FuncSig) { signature.Frame.Results[0].Type = I64 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			text := original
			text.Code = append([]byte(nil), original.Code...)
			text.Relocations = append([]gostaticstorage.TextRelocation(nil), original.Relocations...)
			declaration := source.declarations[name]
			declaration.Frame.Params = append([]FrameSlot(nil), declaration.Frame.Params...)
			declaration.Frame.Results = append([]FrameSlot(nil), declaration.Frame.Results...)
			test.mutate(&text, &declaration)
			if _, err := arm64ByteCarrierTypedEntry(text, declaration); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("incomplete/cross-role entry granted a region: %v", err)
			}
		})
	}
}
