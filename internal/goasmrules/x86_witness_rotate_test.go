package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedRotateCompleteOfficialTransport(t *testing.T) {
	// Use the existing transport, so a missing immediate format is a test
	// failure rather than an undefined future family-selector compilation error.
	inventory := x86CheckPackedRowInventory(t,
		func(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
			return x86PackedBinaryRows(legacy, avx,
				`VPROLD VPROLQ VPRORD VPRORQ VPROLVD VPROLVQ VPRORVD VPRORVQ`)
		}, `^VPRO[LR]V?[DQ]$`, `^VPRO[LR]V?[DQ]$`, x86PackedRowCounts{
			names: 8, broadcast: 72,
			rows: [3]int{0, 0, 48}, formats: [3]int{0, 0, 216}, widths: [3]int{72, 72, 72},
		})
	members := []struct {
		name     string
		bits     int
		left     bool
		variable bool
	}{
		{"VPROLD", 32, true, false}, {"VPROLQ", 64, true, false},
		{"VPRORD", 32, false, false}, {"VPRORQ", 64, false, false},
		{"VPROLVD", 32, true, true}, {"VPROLVQ", 64, true, true},
		{"VPRORVD", 32, false, true}, {"VPRORVQ", 64, false, true},
	}
	var expectedIDs []string
	for _, member := range members {
		table, plain, masked, stride := "_yvprold", "Zevex_i_rm_vo", "Zevex_i_rm_k_vo", 4
		if member.variable {
			table, plain, masked, stride = "_yvblendmpd", "Zevex_rm_v_r", "Zevex_rm_v_k_r", 3
		}
		var payload []string
		for _, width := range []int{128, 256, 512} {
			mapName, opcode := "evex0F", "0x72"
			if member.variable {
				mapName, opcode = "evex0F38", "0x14"
				if member.left {
					opcode = "0x15"
				}
			}
			payload = append(payload,
				fmt.Sprintf("avxEscape | evex%d | evex66 | %s | evexW%d", width, mapName, member.bits/32-1),
				fmt.Sprintf("evexN%d | evexBcstN%d | evexZeroingEnabled", width/8, member.bits/8), opcode)
			if !member.variable {
				extension := "00"
				if member.left {
					extension = "01"
				}
				payload = append(payload, extension)
			}
		}
		count := 0
		for index, rule := range inventory.avx {
			if rule.Opcode != member.name {
				continue
			}
			if count >= 6 {
				t.Fatal("rotate member acquired an unaccounted official row", member.name, rule)
			}
			bank := []string{"YxmEvex,YxrEvex", "YymEvex,YyrEvex", "Yzm,Yzr"}[count/2]
			classes := strings.Split(bank, ",")
			if member.variable {
				classes = []string{classes[0], classes[1], classes[1]}
			} else {
				classes = append([]string{"Yu8"}, classes...)
			}
			zcase := plain
			if count%2 != 0 {
				zcase = masked
				classes = append(classes[:len(classes)-1], "Yknot0", classes[len(classes)-1])
			}
			if rule.RowIndex != count || rule.Ytab != table || rule.Prefix != "Pavx" ||
				rule.ZCase != zcase || rule.ZOffset != count%2*stride || rule.EncodingOffset != count/2*stride ||
				!reflect.DeepEqual(rule.Classes, classes) || !reflect.DeepEqual(rule.OpBytes, payload) {
				t.Fatal("complete rotate count/data format or encoding attributes changed", member.name, rule)
			}
			expectedIDs = append(expectedIDs, fmt.Sprintf("avx/%d/%s/%s/%d", index, member.name, table, count))
			count++
		}
		if count != 6 {
			t.Fatal("complete rotate member lost official rows", member.name, count)
		}
	}
	var actualIDs []string
	var fullVariable []X86PackedBinaryRow
	zeroing := 0
	for _, row := range inventory.rows {
		actualIDs = append(actualIDs, row.ID)
		variable := strings.Contains(row.ID, "/_yvblendmpd/")
		if variable {
			fullVariable = append(fullVariable, row)
		}
		for _, witness := range row.Witnesses {
			operands := strings.Split(strings.Fields(witness.Instruction)[1], ",")
			first := 0
			if !variable {
				first = 1
			}
			wrongSecond := variable && witness.Second == "" || !variable && witness.Second != ""
			if witness.First == "" || witness.First != operands[first] ||
				witness.Memory != (witness.First == "(AX)") || wrongSecond ||
				witness.MaskResult || strings.Contains(witness.Instruction, "SAE") {
				t.Fatal("rotate count source acquired another format's operand role", row.ID, witness)
			}
			if witness.Zeroing {
				zeroing++
			}
		}
	}
	// Both slices follow official source order, not the semantic member order.
	var sourceOrderIDs []string
	wanted := map[string]bool{}
	for _, id := range expectedIDs {
		wanted[id] = true
	}
	for index, rule := range inventory.avx {
		id := fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex)
		if wanted[id] {
			sourceOrderIDs = append(sourceOrderIDs, id)
		}
	}
	if zeroing != 72 || !reflect.DeepEqual(actualIDs, sourceOrderIDs) {
		t.Fatal("complete rotate source IDs or mask-control denominator changed", zeroing)
	}
	previous, err := X86PackedEVEXBinaryRemainderRows(inventory.legacy, inventory.avx)
	if err != nil {
		t.Fatal(err)
	}
	var previousVariable []X86PackedBinaryRow
	for _, row := range previous {
		if strings.HasPrefix(row.Opcode, "VPROLV") || strings.HasPrefix(row.Opcode, "VPRORV") {
			previousVariable = append(previousVariable, row)
		}
	}
	if len(previousVariable) != 24 || !reflect.DeepEqual(fullVariable, previousVariable) {
		t.Fatal("whole-family owner changed previously joined variable rows or witness fields")
	}
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"VPROLD $7,X16,X18", []byte{0x62, 0xb1, 0x6d, 0x00, 0x72, 0xc8, 7}},
		{"VPROLQ.BCST.Z $7,(AX),K1,Z18", []byte{0x62, 0xf1, 0xed, 0xd1, 0x72, 0x08, 7}},
		{"VPRORD $7,X16,X18", []byte{0x62, 0xb1, 0x6d, 0x00, 0x72, 0xc0, 7}},
		{"VPRORQ.BCST $7,(AX),Y18", []byte{0x62, 0xf1, 0xed, 0x30, 0x72, 0x00, 7}},
		{"VPROLVD (AX),Y17,Y18", []byte{0x62, 0xe2, 0x75, 0x20, 0x15, 0x10}},
		{"VPROLVQ.BCST.Z (AX),X17,K1,X18", []byte{0x62, 0xe2, 0xf5, 0x91, 0x15, 0x10}},
		{"VPRORVD X16,X17,X18", []byte{0x62, 0xa2, 0x75, 0x00, 0x14, 0xd0}},
		{"VPRORVQ.Z Z16,Z17,K1,Z18", []byte{0x62, 0xa2, 0xf5, 0xc1, 0x14, 0xd0}},
	})
}

func TestX86PackedRotateTransportRejectsForeignCountFormats(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"signed-immediate", "uniform-count", "narrow-count", "SAE", "immediate-table", "VEX"} {
		t.Run(mutation, func(t *testing.T) {
			name, row := "VPROLD", 0
			if mutation == "narrow-count" || mutation == "immediate-table" {
				name, row = "VPROLVD", 2
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != row {
					continue
				}
				found++
				changed := original
				changed.Classes = append([]string(nil), original.Classes...)
				changed.OpBytes = append([]string(nil), original.OpBytes...)
				switch mutation {
				case "signed-immediate":
					changed.Classes[0] = "Yi8"
				case "uniform-count":
					changed.Classes[0] = "YxmEvex"
				case "narrow-count":
					changed.Classes[0] = "YxmEvex"
				case "SAE":
					changed.OpBytes[1] += " | evexSaeEnabled"
				case "immediate-table":
					changed.Ytab = "_yvprold"
				case "VEX":
					changed.ZCase = "Zvex_i_rm_vo"
					changed.Classes = []string{"Yu8", "Yxr", "Yxr"}
					changed.OpBytes = []string{"avxEscape | vex128 | vex66 | vex0F | vexW0", "0x72", "01"}
				}
				if _, err := x86PackedAVXRowWitnesses(changed); err == nil {
					t.Fatal("rotate transport borrowed another count grammar or FP control", mutation, changed)
				}
			}
			if found != 1 {
				t.Fatal("mutation lost its exact official source row", name, row, found)
			}
		})
	}
}
