package goasmrules

import (
	"bytes"
	"reflect"
	"testing"
)

func TestX86PackedHorizontalIntegerRowsShareBinaryWitnesses(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t, X86PackedHorizontalIntegerRows,
		`^V?PH(ADD|SUB)(W|D|SW)$`, `^$`, x86PackedRowCounts{
			names: 12, mmx: 1,
			rows: [3]int{6, 12, 0}, formats: [3]int{12, 24, 0}, widths: [3]int{24, 12, 0},
		})
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"PHADDW X0,X1", []byte{0x66, 0x0f, 0x38, 0x01, 0xc8}},
		{"PHADDD (AX),X1", []byte{0x66, 0x0f, 0x38, 0x02, 0x08}},
		{"PHADDSW X0,X1", []byte{0x66, 0x0f, 0x38, 0x03, 0xc8}},
		{"PHSUBW (AX),X1", []byte{0x66, 0x0f, 0x38, 0x05, 0x08}},
		{"PHSUBD X0,X1", []byte{0x66, 0x0f, 0x38, 0x06, 0xc8}},
		{"PHSUBSW (AX),X1", []byte{0x66, 0x0f, 0x38, 0x07, 0x08}},
		{"VPHADDW X0,X1,X2", []byte{0xc4, 0xe2, 0x71, 0x01, 0xd0}},
		{"VPHADDD (AX),Y1,Y2", []byte{0xc4, 0xe2, 0x75, 0x02, 0x10}},
		{"VPHADDSW Y0,Y1,Y2", []byte{0xc4, 0xe2, 0x75, 0x03, 0xd0}},
		{"VPHSUBW (AX),X1,X2", []byte{0xc4, 0xe2, 0x71, 0x05, 0x10}},
		{"VPHSUBD X0,X1,X2", []byte{0xc4, 0xe2, 0x71, 0x06, 0xd0}},
		{"VPHSUBSW (AX),Y1,Y2", []byte{0xc4, 0xe2, 0x75, 0x07, 0x10}},
	})
}

func x86HorizontalLiteralFixture() (X86LegacyOpcode, X86LegacyOperand) {
	entry := X86LegacyOpcode{
		Kind: "encoding", Opcode: "PHADDD", Ytab: "ymmxmm0f38", Prefix: "Px", EscapeAdjustment: 1,
		OpBytes: []string{"0x0F", "0x38", "0x02", "0", "0x66", "0x0F", "0x38", "0x02", "0"},
	}
	row := X86LegacyOperand{
		RowIndex: 1, Classes: []string{"Yxm", "Yxr"}, ZCase: "Zlitm_r", ZOffset: 5, UnmatchedOffset: 4,
	}
	return entry, row
}

func TestX86PackedLegacyLiteralOpcodeConsumesSelectedTablePayload(t *testing.T) {
	entry, row := x86HorizontalLiteralFixture()
	before := entry
	before.OpBytes = append([]string(nil), entry.OpBytes...)
	witnesses, err := x86PackedLegacyRowWitnesses(entry, row)
	if err != nil || len(witnesses) != 2 ||
		!bytes.Equal(witnesses[0].Encoding, []byte{0x66, 0x0f, 0x38, 0x02, 0xc8}) ||
		!bytes.Equal(witnesses[1].Encoding, []byte{0x66, 0x0f, 0x38, 0x02, 0x08}) || !reflect.DeepEqual(entry, before) {
		t.Fatal("selected XMM literal payload was lost, confused with MMX or mutated", witnesses, err)
	}
	// Only the independent original-Go join establishes the ISA identity. The
	// encoder must consume the selected table bytes, not replace them by name.
	entry.OpBytes[7] = "0x06"
	witnesses, err = x86PackedLegacyRowWitnesses(entry, row)
	if err != nil || len(witnesses) != 2 || !bytes.Equal(witnesses[0].Encoding, []byte{0x66, 0x0f, 0x38, 0x06, 0xc8}) {
		t.Fatal("literal encoder substituted a mnemonic-specific opcode", witnesses, err)
	}
}

func TestX86PackedLegacyLiteralOpcodeRejectsUnknownAxes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*X86LegacyOpcode, *X86LegacyOperand)
	}{
		{"kind", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.Kind = "special" }},
		{"table", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.Ytab = "unknown" }},
		{"prefix", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.Prefix = "Pq4" }},
		{"escape", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.EscapeAdjustment = 0 }},
		{"index", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.RowIndex = 0 }},
		{"zcase", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.ZCase = "Zm_r" }},
		{"stride", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.ZOffset = 4 }},
		{"offset", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.UnmatchedOffset = 3 }},
		{"MMX row", func(_ *X86LegacyOpcode, r *X86LegacyOperand) {
			r.RowIndex, r.Classes, r.ZOffset, r.UnmatchedOffset = 0, []string{"Ymm", "Ymr"}, 3, 0
		}},
		{"empty", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes = nil }},
		{"short", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes = e.OpBytes[:8] }},
		{"extra", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes = append(e.OpBytes, "0x90") }},
		{"early terminator", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes[6] = "0" }},
		{"missing terminator", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes[8] = "0x90" }},
		{"previous terminator", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes[3] = "0x90" }},
		{"symbol", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes[7] = "opcode" }},
		{"overflow", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes[7] = "0x102" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry, row := x86HorizontalLiteralFixture()
			test.mutate(&entry, &row)
			if witnesses, err := x86PackedLegacyRowWitnesses(entry, row); err == nil || len(witnesses) != 0 {
				t.Fatal("unknown literal row or incomplete payload was silently accepted", witnesses, err)
			}
		})
	}
}
