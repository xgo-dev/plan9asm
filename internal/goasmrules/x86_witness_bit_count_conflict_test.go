package goasmrules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86PackedBitCountConflictOfficialRowsAndControls(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t, X86PackedBitCountConflictRows,
		`^(VPOPCNT[BWDQ]|VPLZCNT[DQ]|VPCONFLICT[DQ])$`, `[DQ]$`, x86PackedRowCounts{
			names: 8, broadcast: 54,
			rows: [3]int{0, 0, 48}, formats: [3]int{0, 0, 198}, widths: [3]int{66, 66, 66},
		})
	classes := []string{"YxmEvex,YxrEvex", "YxmEvex,Yknot0,YxrEvex",
		"YymEvex,YyrEvex", "YymEvex,Yknot0,YyrEvex", "Yzm,Yzr", "Yzm,Yknot0,Yzr"}
	// Independent complete semantic membership and official byte attributes.
	for _, member := range []struct {
		name         string
		opcode       byte
		w, broadcast int
	}{
		{"VPOPCNTB", 0x54, 0, 0}, {"VPOPCNTW", 0x54, 1, 0},
		{"VPOPCNTD", 0x55, 0, 4}, {"VPOPCNTQ", 0x55, 1, 8},
		{"VPLZCNTD", 0x44, 0, 4}, {"VPLZCNTQ", 0x44, 1, 8},
		{"VPCONFLICTD", 0xc4, 0, 4}, {"VPCONFLICTQ", 0xc4, 1, 8},
	} {
		var payload []string
		for _, width := range []int{128, 256, 512} {
			features := fmt.Sprintf("evexN%d", width/8)
			if member.broadcast != 0 {
				features += fmt.Sprintf(" | evexBcstN%d", member.broadcast)
			}
			payload = append(payload, fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW%d", width, member.w),
				features+" | evexZeroingEnabled", fmt.Sprintf("0x%02X", member.opcode))
		}
		count := 0
		for _, rule := range inventory.avx {
			if rule.Opcode != member.name {
				continue
			}
			zcase := "Zevex_rm_v_r"
			if count%2 != 0 {
				zcase = "Zevex_rm_k_r"
			}
			if count >= 6 || rule.RowIndex != count || rule.Ytab != "_yvexpandpd" || rule.Prefix != "Pavx" ||
				rule.ZCase != zcase || rule.ZOffset != count%2*3 || rule.EncodingOffset != count/2*3 ||
				strings.Join(rule.Classes, ",") != classes[count] || !reflect.DeepEqual(rule.OpBytes, payload) {
				t.Fatal("complete unary row, opcode or tuple attributes changed", member.name, rule)
			}
			count++
		}
		if count != 6 {
			t.Fatal("incomplete unary family member", member.name, count)
		}
	}
	zeroing := 0
	var semanticRows, semanticFormats [2]int // Bit count, then cross-lane conflict.
	for _, row := range inventory.rows {
		semantic := 0
		if strings.HasPrefix(row.Opcode, "VPCONFLICT") {
			semantic = 1
		}
		semanticRows[semantic]++
		semanticFormats[semantic] += len(row.Witnesses)
		for _, witness := range row.Witnesses {
			if witness.Second != "" || witness.MaskResult || strings.Contains(witness.Instruction, "SAE") {
				t.Fatal("unary integer witness acquired another data input or FP controls", row.ID, witness)
			}
			if witness.Zeroing {
				zeroing++
			}
		}
	}
	if semanticRows != [2]int{36, 12} || semanticFormats != [2]int{144, 54} || zeroing != 66 {
		t.Fatal("separate bit-count/conflict or unary control denominator changed", semanticRows, semanticFormats, zeroing)
	}
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"VPOPCNTB.Z X16,K1,X18", []byte{0x62, 0xa2, 0x7d, 0x89, 0x54, 0xd0}},
		{"VPOPCNTW Z16,Z18", []byte{0x62, 0xa2, 0xfd, 0x48, 0x54, 0xd0}},
		{"VPOPCNTD.Z (AX),K1,X18", []byte{0x62, 0xe2, 0x7d, 0x89, 0x55, 0x10}},
		{"VPOPCNTQ.BCST (AX),Y18", []byte{0x62, 0xe2, 0xfd, 0x38, 0x55, 0x10}},
		{"VPLZCNTD (AX),Y18", []byte{0x62, 0xe2, 0x7d, 0x28, 0x44, 0x10}},
		{"VPLZCNTQ.BCST.Z (AX),K1,Z18", []byte{0x62, 0xe2, 0xfd, 0xd9, 0x44, 0x10}},
		{"VPCONFLICTD.BCST.Z (AX),K1,X18", []byte{0x62, 0xe2, 0x7d, 0x99, 0xc4, 0x10}},
		{"VPCONFLICTQ X16,X18", []byte{0x62, 0xa2, 0xfd, 0x08, 0xc4, 0xd0}},
	})
}
