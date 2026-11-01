//go:build go1.27

package plan9asm

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86NamedHalfCompleteEighteenOfficialEncoderRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	// Full ordered rows, including zero advances and VEX signed/unsigned
	// immediate overlap. An equal row count or shared ytab is not sufficient.
	type row struct {
		classes, zcase  string
		offset, advance int
	}
	widen := []row{
		{"Yxm,Yxr", "Zvex_rm_v_r", 0, 2},
		{"Yxm,Yyr", "Zvex_rm_v_r", 2, 2},
		{"YymEvex,Yzr", "Zevex_rm_v_r", 4, 0},
		{"YymEvex,Yknot0,Yzr", "Zevex_rm_k_r", 4, 3},
		{"YxmEvex,YxrEvex", "Zevex_rm_v_r", 7, 0},
		{"YxmEvex,Yknot0,YxrEvex", "Zevex_rm_k_r", 7, 3},
		{"YxmEvex,YyrEvex", "Zevex_rm_v_r", 10, 0},
		{"YxmEvex,Yknot0,YyrEvex", "Zevex_rm_k_r", 10, 3},
	}
	narrow := []row{
		{"Yu8,Yxr,Yxm", "Zvex_i_r_rm", 0, 0},
		{"Yi8,Yxr,Yxm", "Zvex_i_r_rm", 0, 2},
		{"Yu8,Yyr,Yxm", "Zvex_i_r_rm", 2, 0},
		{"Yi8,Yyr,Yxm", "Zvex_i_r_rm", 2, 2},
		{"Yu8,Yzr,YymEvex", "Zevex_i_r_rm", 4, 0},
		{"Yu8,Yzr,Yknot0,YymEvex", "Zevex_i_r_k_rm", 4, 3},
		{"Yu8,YxrEvex,YxmEvex", "Zevex_i_r_rm", 7, 0},
		{"Yu8,YxrEvex,Yknot0,YxmEvex", "Zevex_i_r_k_rm", 7, 3},
		{"Yu8,YyrEvex,YxmEvex", "Zevex_i_r_rm", 10, 0},
		{"Yu8,YyrEvex,Yknot0,YxmEvex", "Zevex_i_r_k_rm", 10, 3},
	}
	count := map[string]int{}
	for _, rule := range rules {
		if rule.Opcode != "VCVTPH2PS" && rule.Opcode != "VCVTPS2PH" {
			continue
		}
		expected, table, mapName, opcode := widen, "_yvcvtph2ps", "0F38", "0x13"
		if rule.Opcode == "VCVTPS2PH" {
			expected, table, mapName, opcode = narrow, "_yvcvtps2ph", "0F3A", "0x1D"
		}
		attributes := []string{
			"avxEscape | vex128 | vex66 | vex" + mapName + " | vexW0", opcode,
			"avxEscape | vex256 | vex66 | vex" + mapName + " | vexW0", opcode,
			"avxEscape | evex512 | evex66 | evex" + mapName + " | evexW0",
			"evexN32 | evexSaeEnabled | evexZeroingEnabled", opcode,
			"avxEscape | evex128 | evex66 | evex" + mapName + " | evexW0",
			"evexN8 | evexZeroingEnabled", opcode,
			"avxEscape | evex256 | evex66 | evex" + mapName + " | evexW0",
			"evexN16 | evexZeroingEnabled", opcode,
		}
		index := count[rule.Opcode]
		if index >= len(expected) {
			t.Fatal("unobserved named half encoder row", rule)
		}
		want := expected[index]
		if rule.RowIndex != index || rule.Ytab != table || rule.Prefix != "Pavx" ||
			rule.ZCase != want.zcase || rule.EncodingOffset != want.offset || rule.ZOffset != want.advance ||
			strings.Join(rule.Classes, ",") != want.classes || !reflect.DeepEqual(rule.OpBytes, attributes) {
			t.Fatal("complete named half grammar, generation, tuple, immediate or SAE/zero attributes differ", rule, want)
		}
		count[rule.Opcode]++
	}
	if !reflect.DeepEqual(count, map[string]int{"VCVTPH2PS": 8, "VCVTPS2PH": 10}) {
		t.Fatal("complete eighteen-row named half table differs", count)
	}
}
