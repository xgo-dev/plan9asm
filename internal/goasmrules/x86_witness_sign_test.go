package goasmrules

import "testing"

func TestX86PackedSignRowsShareBinaryWitnesses(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t, X86PackedSignRows,
		`^V?PSIGN`, `^$`, x86PackedRowCounts{
			names: 6,
			rows:  [3]int{3, 6, 0}, formats: [3]int{6, 12, 0}, widths: [3]int{12, 6, 0},
		})
	// Every opcode has its own literal anchor; the row inventory above also
	// requires both register and memory sources at every official width.
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"PSIGNB X0,X1", []byte{0x66, 0x0f, 0x38, 0x08, 0xc8}},
		{"PSIGNW (AX),X1", []byte{0x66, 0x0f, 0x38, 0x09, 0x08}},
		{"PSIGND X0,X1", []byte{0x66, 0x0f, 0x38, 0x0a, 0xc8}},
		{"VPSIGNB X0,X1,X2", []byte{0xc4, 0xe2, 0x71, 0x08, 0xd0}},
		{"VPSIGNW Y0,Y1,Y2", []byte{0xc4, 0xe2, 0x75, 0x09, 0xd0}},
		{"VPSIGND (AX),Y1,Y2", []byte{0xc4, 0xe2, 0x75, 0x0a, 0x10}},
	})
}
