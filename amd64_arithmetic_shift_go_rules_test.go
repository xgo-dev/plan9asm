package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Independent complete ordered rows, including zero-offset aliases. Encoding
// attributes are opcode-specific even when operand tables are shared.
func TestX86ArithmeticShiftCompleteGoEncoderRules(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		name, table, mapName, w, immediate, opcode, broadcast string
		uniform, vex                                          bool
	}{
		{"VPSRAW", "_yvpslld", "vex0F", "vexW0", "0x71", "0xE1", "", true, true},
		{"VPSRAD", "_yvpslld", "vex0F", "vexW0", "0x72", "0xE2", "evexBcstN4", true, true},
		{"VPSRAQ", "_yvpsraq", "vex0F", "vexW1", "0x72", "0xE2", "evexBcstN8", true, false},
		{"VPSRAVD", "_yvandnpd", "vex0F38", "vexW0", "", "0x46", "evexBcstN4", false, true},
		{"VPSRAVQ", "_yvblendmpd", "vex0F38", "vexW1", "", "0x46", "evexBcstN8", false, false},
		{"VPSRAVW", "_yvblendmpd", "vex0F38", "vexW1", "", "0x11", "", false, false},
	} {
		var expected []goasmrules.X86AVXRule
		var bytes []string
		offset := 0
		add := func(zcase string, advance int, classes string) {
			expected = append(expected, goasmrules.X86AVXRule{
				Opcode: spec.name, Ytab: spec.table, Prefix: "Pavx", RowIndex: len(expected),
				ZCase: zcase, ZOffset: advance, EncodingOffset: offset, Classes: strings.Split(classes, ","),
			})
			offset += advance
		}
		if spec.vex {
			if spec.uniform {
				for _, bank := range []string{"Yxr", "Yyr"} {
					add("Zvex_i_rm_vo", 0, "Yu8,"+bank+","+bank)
					add("Zvex_i_rm_vo", 3, "Yi8,"+bank+","+bank)
				}
			}
			for index, bank := range []string{"Yxr", "Yyr"} {
				source := []string{"Yxm", "Yym"}[index]
				if spec.uniform {
					source = "Yxm"
				}
				add("Zvex_rm_v_r", 2, source+","+bank+","+bank)
			}
			for pass := 0; pass < 2; pass++ {
				if pass == 0 && !spec.uniform {
					continue
				}
				for _, width := range []int{128, 256} {
					bytes = append(bytes, fmt.Sprintf("avxEscape | vex%d | vex66 | %s | %s", width, spec.mapName, spec.w))
					if pass == 0 {
						bytes = append(bytes, spec.immediate, "04")
					} else {
						bytes = append(bytes, spec.opcode)
					}
				}
			}
		}
		for pass := 0; pass < 2; pass++ {
			if pass == 0 && !spec.uniform {
				continue
			}
			for index, bank := range []string{"YxrEvex", "YyrEvex", "Yzr"} {
				source := []string{"YxmEvex", "YymEvex", "Yzm"}[index]
				if spec.uniform && pass == 1 {
					source = "YxmEvex"
				}
				classes, zcase, masked, advance := source+","+bank+","+bank, "Zevex_rm_v_r", "Zevex_rm_v_k_r", 3
				if pass == 0 {
					classes, zcase, masked, advance = "Yu8,"+source+","+bank, "Zevex_i_rm_vo", "Zevex_i_rm_k_vo", 4
				}
				add(zcase, 0, classes)
				parts := strings.Split(classes, ",")
				add(masked, advance, strings.Join(parts[:len(parts)-1], ",")+",Yknot0,"+bank)
				width := []int{128, 256, 512}[index]
				prefix := strings.ReplaceAll(fmt.Sprintf("avxEscape | evex%d | evex66 | %s | %s", width, spec.mapName, spec.w), "vex0F", "evex0F")
				prefix = strings.ReplaceAll(prefix, "vexW", "evexW")
				tuple := 16
				if !spec.uniform || pass == 0 {
					tuple = width / 8
				}
				attributes := fmt.Sprintf("evexN%d", tuple)
				if (!spec.uniform || pass == 0) && spec.broadcast != "" {
					attributes += " | " + spec.broadcast
				}
				bytes = append(bytes, prefix, attributes+" | evexZeroingEnabled")
				if pass == 0 {
					bytes = append(bytes, spec.immediate, "04")
				} else {
					bytes = append(bytes, spec.opcode)
				}
			}
		}
		var actual []goasmrules.X86AVXRule
		for _, rule := range rules {
			if rule.Opcode == spec.name {
				actual = append(actual, rule)
			}
		}
		for index := range expected {
			expected[index].OpBytes = bytes
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("complete ordered arithmetic encoder rules changed: %s\ngot %+v\nwant %+v", spec.name, actual, expected)
		}
	}
}

func TestX86PackedShiftEVEXUnsignedImmediateGrammar(t *testing.T) {
	for _, name := range []string{"VPSLLD", "VPSLLQ", "VPSRLD", "VPSRLQ", "VPSRAD", "VPSRAQ"} {
		for _, count := range []int{-128, -1} {
			row := fmt.Sprintf("%s.BCST $%d,(AX),X2", name, count)
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			ins := x86ScalarLaneInstruction(t, row)
			if _, known, err := x86PackedShiftProperties(ins.Op, ins, "amd64"); !known || err == nil {
				t.Errorf("EVEX-only Yu8 broadcast accepted signed count: %s: %v", row, err)
			}
		}
	}
}
