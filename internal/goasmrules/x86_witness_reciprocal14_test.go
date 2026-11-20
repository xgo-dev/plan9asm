package goasmrules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86Reciprocal14OfficialRowsAndControls(t *testing.T) {
	build := func(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
		return x86PackedBinaryRows(legacy, avx,
			"VRCP14PS VRCP14PD VRCP14SS VRCP14SD VRSQRT14PS VRSQRT14PD VRSQRT14SS VRSQRT14SD")
	}
	inventory := x86CheckPackedRowInventory(t, build, `^V(RCP|RSQRT)14(P[SD]|S[SD])$`, `P[SD]$`, x86PackedRowCounts{
		names: 8, broadcast: 36,
		rows: [3]int{0, 0, 32}, formats: [3]int{0, 0, 132}, widths: [3]int{60, 36, 36},
	})
	// Complete independent byte attributes. Scalar SS/SD here use 66, not
	// the F3/F2 prefix used by the separate VADDSS/VADDSD scalar format.
	for _, member := range []struct {
		name   string
		opcode byte
		w      int
		scalar bool
	}{
		{"VRCP14PS", 0x4c, 0, false}, {"VRCP14PD", 0x4c, 1, false},
		{"VRCP14SS", 0x4d, 0, true}, {"VRCP14SD", 0x4d, 1, true},
		{"VRSQRT14PS", 0x4e, 0, false}, {"VRSQRT14PD", 0x4e, 1, false},
		{"VRSQRT14SS", 0x4f, 0, true}, {"VRSQRT14SD", 0x4f, 1, true},
	} {
		var payload []string
		widths := []int{128, 256, 512}
		if member.scalar {
			widths = widths[:1]
		}
		for _, width := range widths {
			tuple, features := width/8, ""
			if member.scalar {
				tuple = 4 << member.w
			} else {
				features = fmt.Sprintf(" | evexBcstN%d", 4<<member.w)
			}
			payload = append(payload,
				fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW%d", width, member.w),
				fmt.Sprintf("evexN%d%s | evexZeroingEnabled", tuple, features), fmt.Sprintf("0x%02X", member.opcode))
		}
		count := 0
		for _, rule := range inventory.avx {
			if rule.Opcode != member.name {
				continue
			}
			table, zcase, rows := "_yvexpandpd", "Zevex_rm_v_r", 6
			if member.scalar {
				table, rows = "_yvgetexpsd", 2
			}
			if count%2 != 0 {
				zcase = "Zevex_rm_k_r"
				if member.scalar {
					zcase = "Zevex_rm_v_k_r"
				}
			}
			if count >= rows || rule.RowIndex != count || rule.Ytab != table || rule.Prefix != "Pavx" ||
				rule.ZCase != zcase || rule.ZOffset != count%2*3 || rule.EncodingOffset != count/2*3 ||
				!reflect.DeepEqual(rule.OpBytes, payload) {
				t.Fatal("complete reciprocal14 official row or byte attributes changed", member.name, rule)
			}
			count++
		}
		if count != len(widths)*2 {
			t.Fatal("reciprocal14 member lost an official row", member.name, count)
		}
	}
	for _, row := range inventory.rows {
		scalar := strings.HasSuffix(row.Opcode, "SS") || strings.HasSuffix(row.Opcode, "SD")
		for _, witness := range row.Witnesses {
			if (witness.Second != "") != scalar || witness.MaskResult || strings.Contains(witness.Instruction, "SAE") ||
				scalar && (witness.Width != 128 || witness.Broadcast) {
				t.Fatal("reciprocal14 operand transport acquired another format", row.ID, witness)
			}
		}
	}
}
