package goasmrules

import (
	"bytes"
	"strings"
	"testing"
)

func TestX86PackedAbsRowsShareUnaryWitnesses(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t, X86PackedAbsRows,
		`^V?PABS[BWDQ]$`, `[DQ]$`, x86PackedRowCounts{
			names: 7, broadcast: 18,
			rows: [3]int{3, 6, 24}, formats: [3]int{6, 12, 90}, widths: [3]int{42, 36, 30},
		})
	for _, row := range inventory.rows {
		for _, witness := range row.Witnesses {
			if witness.Generation == "legacy" && witness.Second != witness.Destination ||
				witness.Generation != "legacy" && witness.Second != "" {
				t.Fatal("unary ABS syntax confused its destination and a second source", row.ID, witness)
			}
			if witness.Generation == "evex" && !witness.Memory && !strings.HasSuffix(witness.First, "16") {
				t.Fatal("unary source can lose its original EVEX row", row.ID, witness)
			}
		}
	}
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"PABSB X0,X1", []byte{0x66, 0x0f, 0x38, 0x1c, 0xc8}},
		{"PABSW (AX),X1", []byte{0x66, 0x0f, 0x38, 0x1d, 0x08}},
		{"PABSD X0,X1", []byte{0x66, 0x0f, 0x38, 0x1e, 0xc8}},
		{"VPABSB X0,X2", []byte{0xc4, 0xe2, 0x79, 0x1c, 0xd0}},
		{"VPABSW (AX),Y2", []byte{0xc4, 0xe2, 0x7d, 0x1d, 0x10}},
		{"VPABSD X16,X18", []byte{0x62, 0xa2, 0x7d, 0x08, 0x1e, 0xd0}},
		{"VPABSD.BCST.Z (AX),K1,Z18", []byte{0x62, 0xe2, 0x7d, 0xd9, 0x1e, 0x10}},
		{"VPABSQ.Z Y16,K1,Y18", []byte{0x62, 0xa2, 0xfd, 0xa9, 0x1f, 0xd0}},
	})
}

func x86PackedAbsUnaryFixture() X86AVXRule {
	return X86AVXRule{
		Opcode: "VPABSD", Ytab: "_yvmovddup", Prefix: "Pavx", RowIndex: 3,
		Classes: []string{"YxmEvex", "Yknot0", "YxrEvex"},
		ZCase:   "Zevex_rm_k_r", ZOffset: 3,
		OpBytes: []string{"avxEscape | evex128 | evex66 | evex0F38 | evexW0", "evexN16 | evexBcstN4 | evexZeroingEnabled", "0x1E"},
	}
}

func TestX86PackedUnaryRowEncodingAndFailClosed(t *testing.T) {
	if syntax, err := X86PackedBinarySyntaxWitnesses(x86PackedAbsUnaryFixture()); err == nil || len(syntax) != 0 {
		t.Fatal("the strict public binary grammar acquired unary formats", syntax, err)
	}
	witnesses, err := x86PackedAVXRowWitnesses(x86PackedAbsUnaryFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(witnesses) != 6 || witnesses[0].Instruction != "VPABSD X16,K1,X18" ||
		witnesses[0].Second != "" || witnesses[0].Destination != "X18" ||
		!bytes.Equal(witnesses[0].Encoding, []byte{0x62, 0xa2, 0x7d, 0x09, 0x1e, 0xd0}) ||
		witnesses[5].Instruction != "VPABSD.BCST.Z (AX),K1,X18" ||
		!bytes.Equal(witnesses[5].Encoding, []byte{0x62, 0xe2, 0x7d, 0x99, 0x1e, 0x10}) {
		t.Fatal("unary source, destination or reserved vvvv/V' fields changed", witnesses)
	}
	for _, test := range []struct {
		name   string
		mutate func(*X86AVXRule)
	}{
		{"table", func(r *X86AVXRule) { r.Ytab = "unknown" }},
		{"prefix", func(r *X86AVXRule) { r.Prefix = "Pq4" }},
		{"binary zcase", func(r *X86AVXRule) { r.ZCase = "Zevex_rm_v_k_r" }},
		{"binary arity", func(r *X86AVXRule) { r.Classes = append(r.Classes[:1], "YxrEvex", "Yknot0", "YxrEvex") }},
		{"source class", func(r *X86AVXRule) { r.Classes[0] = "Yxm" }},
		{"destination width", func(r *X86AVXRule) { r.Classes[2] = "YyrEvex" }},
		{"mask class", func(r *X86AVXRule) { r.Classes[1] = "Yk" }},
		{"offset", func(r *X86AVXRule) { r.EncodingOffset = 1 }},
		{"stride", func(r *X86AVXRule) { r.ZOffset = 0 }},
		{"width", func(r *X86AVXRule) { r.OpBytes[0] = strings.Replace(r.OpBytes[0], "evex128", "evex256", 1) }},
		{"tuple", func(r *X86AVXRule) { r.OpBytes[1] = strings.Replace(r.OpBytes[1], "evexN16", "evexN64", 1) }},
		{"broadcast conflict", func(r *X86AVXRule) { r.OpBytes[1] += " | evexBcstN8" }},
		{"rounding", func(r *X86AVXRule) { r.OpBytes[1] += " | evexRoundingEnabled" }},
		{"SAE", func(r *X86AVXRule) { r.OpBytes[1] += " | evexSaeEnabled" }},
		{"future flag", func(r *X86AVXRule) { r.OpBytes[0] += " | futureFlag" }},
		{"repeated flag", func(r *X86AVXRule) { r.OpBytes[0] += " | evex66" }},
		{"W conflict", func(r *X86AVXRule) { r.OpBytes[0] += " | evexW1" }},
		{"map conflict", func(r *X86AVXRule) { r.OpBytes[0] += " | evex0F" }},
		{"opcode literal", func(r *X86AVXRule) { r.OpBytes[2] = "futureOpcode" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := x86PackedAbsUnaryFixture()
			test.mutate(&local)
			if witnesses, err := x86PackedAVXRowWitnesses(local); err == nil || len(witnesses) != 0 {
				t.Fatal("unknown unary format silently accepted", witnesses, err)
			}
		})
	}
}

func TestX86PackedUnaryEVEXOnlyTableRejectsVEX(t *testing.T) {
	rule := X86AVXRule{
		Opcode: "VPABSQ", Ytab: "_yvexpandpd", Prefix: "Pavx",
		Classes: []string{"Yxm", "Yxr"}, ZCase: "Zvex_rm_v_r", ZOffset: 2,
		OpBytes: []string{"avxEscape | vex128 | vex66 | vex0F38 | vexW1", "0x1F"},
	}
	if witnesses, err := x86PackedAVXRowWitnesses(rule); err == nil || len(witnesses) != 0 {
		t.Fatal("EVEX-only unary table acquired VEX", witnesses, err)
	}
}
