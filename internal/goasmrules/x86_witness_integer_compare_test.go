package goasmrules

import (
	"strings"
	"testing"
)

func TestX86PackedIntegerCompareRowsShareBinaryWitnesses(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t, X86PackedIntegerCompareRows,
		`^V?PCMP(EQ|GT)[BWLQD]$`, `^VPCMP(EQ|GT)[DQ]$`, x86PackedRowCounts{
			names: 16, mmx: 6, broadcast: 24,
			rows: [3]int{8, 16, 48}, formats: [3]int{16, 32, 120}, widths: [3]int{72, 56, 40},
		})
	maskResults := 0
	for _, row := range inventory.rows {
		for _, witness := range row.Witnesses {
			if witness.Generation == "evex" {
				if witness.Destination != "K2" || witness.Zeroing {
					t.Fatal("EVEX compare acquired a vector result or merging/zeroing suffix", witness)
				}
				maskResults++
			} else if strings.HasPrefix(witness.Destination, "K") {
				t.Fatal("legacy/VEX compare lost its vector result", witness)
			}
		}
	}
	if maskResults != 120 {
		t.Fatal("incomplete independent K-result format inventory", maskResults)
	}
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"PCMPEQB X0,X1", []byte{0x66, 0x0f, 0x74, 0xc8}},
		{"PCMPEQW (AX),X1", []byte{0x66, 0x0f, 0x75, 0x08}},
		{"PCMPEQL X0,X1", []byte{0x66, 0x0f, 0x76, 0xc8}},
		{"PCMPEQQ (AX),X1", []byte{0x66, 0x0f, 0x38, 0x29, 0x08}},
		{"PCMPGTB X0,X1", []byte{0x66, 0x0f, 0x64, 0xc8}},
		{"PCMPGTW (AX),X1", []byte{0x66, 0x0f, 0x65, 0x08}},
		{"PCMPGTL X0,X1", []byte{0x66, 0x0f, 0x66, 0xc8}},
		{"PCMPGTQ (AX),X1", []byte{0x66, 0x0f, 0x38, 0x37, 0x08}},
		{"VPCMPEQD X0,X1,X2", []byte{0xc5, 0xf1, 0x76, 0xd0}},
		{"VPCMPGTQ Y0,Y1,Y2", []byte{0xc4, 0xe2, 0x75, 0x37, 0xd0}},
		{"VPCMPEQB X16,X17,K2", []byte{0x62, 0xb1, 0x75, 0x00, 0x74, 0xd0}},
		{"VPCMPEQW (AX),Y17,K1,K2", []byte{0x62, 0xf1, 0x75, 0x21, 0x75, 0x10}},
		{"VPCMPEQD.BCST (AX),Z17,K2", []byte{0x62, 0xf1, 0x75, 0x50, 0x76, 0x10}},
		{"VPCMPEQQ.BCST (AX),Z17,K1,K2", []byte{0x62, 0xf2, 0xf5, 0x51, 0x29, 0x10}},
		{"VPCMPGTB Y16,Y17,K2", []byte{0x62, 0xb1, 0x75, 0x20, 0x64, 0xd0}},
		{"VPCMPGTW Z16,Z17,K1,K2", []byte{0x62, 0xb1, 0x75, 0x41, 0x65, 0xd0}},
		{"VPCMPGTD X16,X17,K1,K2", []byte{0x62, 0xb1, 0x75, 0x01, 0x66, 0xd0}},
		{"VPCMPGTQ Z16,Z17,K2", []byte{0x62, 0xb2, 0xf5, 0x40, 0x37, 0xd0}},
	})
}

func TestX86PackedIntegerCompareRejectsUnknownResultAxes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*X86AVXRule)
	}{
		{"unrelated table", func(r *X86AVXRule) { r.Ytab = "_yvandnpd" }},
		{"vector result", func(r *X86AVXRule) { r.Classes[2] = "YxrEvex" }},
		{"general purpose result", func(r *X86AVXRule) { r.Classes[2] = "Yrl" }},
		{"zeroing", func(r *X86AVXRule) { r.OpBytes[1] += " | evexZeroingEnabled" }},
		{"rounding", func(r *X86AVXRule) { r.OpBytes[1] += " | evexRoundingEnabled" }},
		{"SAE", func(r *X86AVXRule) { r.OpBytes[1] += " | evexSaeEnabled" }},
		{"offset", func(r *X86AVXRule) { r.ZOffset = 3 }},
		{"width", func(r *X86AVXRule) { r.OpBytes[0] = "avxEscape | evex256 | evex66 | evex0F | evexW0" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := X86AVXRule{
				Opcode: "VPCMPEQD", Ytab: "_yvpcmpeqb", Prefix: "Pavx",
				Classes: []string{"YxmEvex", "YxrEvex", "Yk"}, ZCase: "Zevex_rm_v_r",
				OpBytes: []string{"avxEscape | evex128 | evex66 | evex0F | evexW0", "evexN16 | evexBcstN4", "0x76"},
			}
			test.mutate(&rule)
			if witnesses, err := x86PackedAVXRowWitnesses(rule); err == nil || len(witnesses) != 0 {
				t.Fatal("unknown compare result axis was silently accepted", witnesses, err)
			}
		})
	}
}
