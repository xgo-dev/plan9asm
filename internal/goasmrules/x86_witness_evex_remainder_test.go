package goasmrules

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestX86PackedEVEXBinaryRemainderOfficialRowsAndControls(t *testing.T) {
	// Independent official attributes, not a translator registry. Syntax alone
	// does not identify an operation's numerical old-destination dependency.
	members := []struct {
		name         string
		opcode       byte
		w, broadcast int
	}{
		{"VPDPBUSD", 0x50, 0, 4}, {"VPDPBUSDS", 0x51, 0, 4},
		{"VPDPWSSD", 0x52, 0, 4}, {"VPDPWSSDS", 0x53, 0, 4},
		{"VPERMB", 0x8d, 0, 0}, {"VPERMW", 0x8d, 1, 0},
		{"VPERMI2B", 0x75, 0, 0}, {"VPERMI2W", 0x75, 1, 0},
		{"VPERMI2D", 0x76, 0, 4}, {"VPERMI2Q", 0x76, 1, 8},
		{"VPERMI2PS", 0x77, 0, 4}, {"VPERMI2PD", 0x77, 1, 8},
		{"VPERMT2B", 0x7d, 0, 0}, {"VPERMT2W", 0x7d, 1, 0},
		{"VPERMT2D", 0x7e, 0, 4}, {"VPERMT2Q", 0x7e, 1, 8},
		{"VPERMT2PS", 0x7f, 0, 4}, {"VPERMT2PD", 0x7f, 1, 8},
		{"VPMADD52HUQ", 0xb5, 1, 8}, {"VPMADD52LUQ", 0xb4, 1, 8},
		{"VPMULTISHIFTQB", 0x83, 1, 8},
		{"VPROLVD", 0x15, 0, 4}, {"VPROLVQ", 0x15, 1, 8},
		{"VPRORVD", 0x14, 0, 4}, {"VPRORVQ", 0x14, 1, 8},
		{"VPSHLDVW", 0x70, 1, 0}, {"VPSHLDVD", 0x71, 0, 4}, {"VPSHLDVQ", 0x71, 1, 8},
		{"VPSHRDVW", 0x72, 1, 0}, {"VPSHRDVD", 0x73, 0, 4}, {"VPSHRDVQ", 0x73, 1, 8},
	}
	wanted, names, broadcasts := map[string]int{}, []string{}, []string{}
	for index, member := range members {
		wanted[member.name] = index
		names = append(names, member.name)
		if member.broadcast != 0 {
			broadcasts = append(broadcasts, member.name)
		}
	}
	inventory := x86CheckPackedRowInventory(t, X86PackedEVEXBinaryRemainderRows,
		"^("+strings.Join(names, "|")+")$", "^("+strings.Join(broadcasts, "|")+")$", x86PackedRowCounts{
			names: 31, broadcast: 207,
			rows: [3]int{0, 0, 186}, formats: [3]int{0, 0, 765}, widths: [3]int{255, 255, 255},
		})
	existing := regexp.MustCompile(`^(VBLENDM(PS|PD)|VPBLENDM[BWDQ]|VP(ANDN?|OR|XOR)[DQ]|VP(MIN|MAX)[SU]Q|VPMULLQ|VPS(LLVW|RLVW|RAVW|RAVQ))$`)
	classes := []string{"YxmEvex,YxrEvex,YxrEvex", "YxmEvex,YxrEvex,Yknot0,YxrEvex",
		"YymEvex,YyrEvex,YyrEvex", "YymEvex,YyrEvex,Yknot0,YyrEvex", "Yzm,Yzr,Yzr", "Yzm,Yzr,Yknot0,Yzr"}
	var expectedIDs []string
	counts, prior := map[string]int{}, map[string]int{}
	for index, rule := range inventory.avx {
		memberIndex, selected := wanted[rule.Opcode]
		if !selected {
			if rule.Ytab == "_yvblendmpd" {
				if !existing.MatchString(rule.Opcode) {
					t.Fatal("official EVEX grammar acquired an unaccounted member", rule)
				}
				prior[rule.Opcode]++
			}
			continue
		}
		member, row := members[memberIndex], counts[rule.Opcode]
		counts[rule.Opcode]++
		zcase := "Zevex_rm_v_r"
		if row%2 != 0 {
			zcase = "Zevex_rm_v_k_r"
		}
		var payload []string
		for _, width := range []int{128, 256, 512} {
			features := fmt.Sprintf("evexN%d", width/8)
			if member.broadcast != 0 {
				features += fmt.Sprintf(" | evexBcstN%d", member.broadcast)
			}
			payload = append(payload, fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW%d", width, member.w),
				features+" | evexZeroingEnabled", fmt.Sprintf("0x%02X", member.opcode))
		}
		if row >= 6 || rule.RowIndex != row || rule.Ytab != "_yvblendmpd" || rule.Prefix != "Pavx" ||
			rule.ZCase != zcase || rule.ZOffset != row%2*3 || rule.EncodingOffset != row/2*3 ||
			strings.Join(rule.Classes, ",") != classes[row] || !reflect.DeepEqual(rule.OpBytes, payload) {
			t.Fatal("independent complete EVEX row, tuple or opcode attributes changed", rule)
		}
		expectedIDs = append(expectedIDs, fmt.Sprintf("avx/%d/%s/_yvblendmpd/%d", index, rule.Opcode, row))
	}
	var actualIDs []string
	zeroing := 0
	for _, row := range inventory.rows {
		actualIDs = append(actualIDs, row.ID)
		for _, witness := range row.Witnesses {
			if witness.Zeroing {
				zeroing++
			}
			if witness.MaskResult || strings.Contains(witness.Instruction, "SAE") {
				t.Fatal("integer EVEX remainder acquired mask results or FP controls", row.ID, witness)
			}
		}
	}
	if len(counts) != 31 || len(prior) != 23 || len(expectedIDs) != 186 || zeroing != 255 ||
		!reflect.DeepEqual(actualIDs, expectedIDs) {
		t.Fatal("complete remainder lost official row identity, old join exclusions or controls", len(counts), len(prior), zeroing)
	}
	for name, count := range counts {
		if count != 6 {
			t.Fatal("incomplete retained member", name, count)
		}
	}
	for name, count := range prior {
		if count != 6 {
			t.Fatal("previous joined member changed", name, count)
		}
	}
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"VPERMB X16,X17,X18", []byte{0x62, 0xa2, 0x75, 0x00, 0x8d, 0xd0}},
		{"VPERMW.Z (AX),Y17,K1,Y18", []byte{0x62, 0xe2, 0xf5, 0xa1, 0x8d, 0x10}},
		{"VPMULTISHIFTQB.BCST.Z (AX),Z17,K1,Z18", []byte{0x62, 0xe2, 0xf5, 0xd1, 0x83, 0x10}},
		{"VPROLVD (AX),Y17,Y18", []byte{0x62, 0xe2, 0x75, 0x20, 0x15, 0x10}},
		{"VPRORVQ.Z Z16,Z17,K1,Z18", []byte{0x62, 0xa2, 0xf5, 0xc1, 0x14, 0xd0}},
		{"VPDPBUSD.BCST (AX),X17,X18", []byte{0x62, 0xe2, 0x75, 0x10, 0x50, 0x10}},
		{"VPDPWSSDS.Z X16,X17,K1,X18", []byte{0x62, 0xa2, 0x75, 0x81, 0x53, 0xd0}},
		{"VPMADD52HUQ.BCST.Z (AX),Z17,K1,Z18", []byte{0x62, 0xe2, 0xf5, 0xd1, 0xb5, 0x10}},
		{"VPERMI2B X16,X17,X18", []byte{0x62, 0xa2, 0x75, 0x00, 0x75, 0xd0}},
		{"VPERMT2PD.BCST (AX),Y17,Y18", []byte{0x62, 0xe2, 0xf5, 0x30, 0x7f, 0x10}},
		{"VPSHLDVW.Z Z16,Z17,K1,Z18", []byte{0x62, 0xa2, 0xf5, 0xc1, 0x70, 0xd0}},
		{"VPSHRDVD.BCST.Z (AX),X17,K1,X18", []byte{0x62, 0xe2, 0x75, 0x91, 0x73, 0x10}},
	})
}
