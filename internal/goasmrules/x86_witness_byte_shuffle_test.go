package goasmrules

import (
	"bytes"
	"reflect"
	"testing"
)

func TestX86PackedByteShuffleRowsShareBinaryWitnesses(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t, X86PackedByteShuffleRows,
		`^V?PSHUFB$`, `^$`, x86PackedRowCounts{
			names: 2,
			rows:  [3]int{1, 2, 6}, formats: [3]int{2, 4, 18}, widths: [3]int{10, 8, 6},
		})
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"PSHUFB X0,X1", []byte{0x66, 0x0f, 0x38, 0x00, 0xc8}},
		{"PSHUFB (AX),X1", []byte{0x66, 0x0f, 0x38, 0x00, 0x08}},
		{"VPSHUFB X0,X1,X2", []byte{0xc4, 0xe2, 0x71, 0x00, 0xd0}},
		{"VPSHUFB (AX),Y1,Y2", []byte{0xc4, 0xe2, 0x75, 0x00, 0x10}},
		{"VPSHUFB X16,X17,X18", []byte{0x62, 0xa2, 0x75, 0x00, 0x00, 0xd0}},
		{"VPSHUFB Y16,Y17,K1,Y18", []byte{0x62, 0xa2, 0x75, 0x21, 0x00, 0xd0}},
		{"VPSHUFB (AX),Z17,Z18", []byte{0x62, 0xe2, 0x75, 0x40, 0x00, 0x10}},
		{"VPSHUFB.Z (AX),Z17,K1,Z18", []byte{0x62, 0xe2, 0x75, 0xc1, 0x00, 0x10}},
	})
}

func TestX86PackedLegacyTwoByteOpcodeConsumesCompleteTablePayload(t *testing.T) {
	entry := X86LegacyOpcode{Kind: "encoding", Opcode: "PSHUFB", Ytab: "ymshufb", Prefix: "Pq", OpBytes: []string{"0x38", "0x00"}}
	row := X86LegacyOperand{Classes: []string{"Yxm", "Yxr"}, ZCase: "Zm2_r", ZOffset: 2}
	before := entry
	before.OpBytes = append([]string(nil), entry.OpBytes...)
	witnesses, err := x86PackedLegacyRowWitnesses(entry, row)
	if err != nil || len(witnesses) != 2 || !bytes.Equal(witnesses[0].Encoding, []byte{0x66, 0x0f, 0x38, 0x00, 0xc8}) ||
		!bytes.Equal(witnesses[1].Encoding, []byte{0x66, 0x0f, 0x38, 0x00, 0x08}) || !reflect.DeepEqual(entry, before) {
		t.Fatalf("selected two-byte opcode was lost or mutated: %+v/%v", witnesses, err)
	}
	// Perturb only fixture metadata to prove both bytes come from the selected
	// table payload. The independent original-Go join above owns ISA identity.
	changed := entry
	changed.OpBytes = []string{"0x39", "0x07"}
	witnesses, err = x86PackedLegacyRowWitnesses(changed, row)
	if err != nil || len(witnesses) != 2 || !bytes.Equal(witnesses[0].Encoding, []byte{0x66, 0x0f, 0x39, 0x07, 0xc8}) {
		t.Fatal("two-byte encoder substituted a mnemonic-specific opcode", witnesses, err)
	}
}

func TestX86PackedLegacyTwoByteOpcodeRejectsUnknownAxes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*X86LegacyOpcode, *X86LegacyOperand)
	}{
		{"kind", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.Kind = "special" }},
		{"table", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.Ytab = "unknown" }},
		{"prefix", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.Prefix = "Pm" }},
		{"escape", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.EscapeAdjustment = 1 }},
		{"index", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.RowIndex = 1 }},
		{"zcase", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.ZCase = "Zm_r" }},
		{"stride", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.ZOffset = 1 }},
		{"offset", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.UnmatchedOffset = 1 }},
		{"classes", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.Classes = []string{"Ymm", "Ymr"} }},
		{"empty", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes = nil }},
		{"short", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes = []string{"0x38"} }},
		{"extra", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes = []string{"0x38", "0x00", "0x01"} }},
		{"first symbol", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes[0] = "opcode" }},
		{"second symbol", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes[1] = "opcode" }},
		{"first overflow", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes[0] = "0x138" }},
		{"second overflow", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes[1] = "0x100" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := X86LegacyOpcode{Kind: "encoding", Opcode: "PSHUFB", Ytab: "ymshufb", Prefix: "Pq", OpBytes: []string{"0x38", "0x00"}}
			row := X86LegacyOperand{Classes: []string{"Yxm", "Yxr"}, ZCase: "Zm2_r", ZOffset: 2}
			test.mutate(&entry, &row)
			if witnesses, err := x86PackedLegacyRowWitnesses(entry, row); err == nil || len(witnesses) != 0 {
				t.Fatal("unknown official encoding axis was silently accepted", witnesses, err)
			}
		})
	}
}
