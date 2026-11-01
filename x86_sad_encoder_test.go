package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86SADIndependentEncoderAttributes(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"VPSADBW", "VMPSADBW", "VDBPSADBW"} {
		var expected []goasmrules.X86AVXRule
		var encoding []string
		offset := 0
		add := func(table, zcase string, advance int, classes string) {
			expected = append(expected, goasmrules.X86AVXRule{
				Opcode: op, Ytab: table, Prefix: "Pavx", Classes: strings.Split(classes, ","),
				RowIndex: len(expected), ZCase: zcase, ZOffset: advance, EncodingOffset: offset,
			})
			offset += advance
		}
		for index, bank := range []string{"x", "y", "z"} {
			width := 16 << uint(index)
			if op != "VDBPSADBW" && index < 2 {
				prefix := fmt.Sprintf("avxEscape | vex%d | vex66 | vex0F", 8*width)
				if op == "VMPSADBW" {
					add("_yvblendpd", "Zvex_i_rm_v_r", 2, "Yu8,Y"+bank+"m,Y"+bank+"r,Y"+bank+"r")
					encoding = append(encoding, prefix+"3A | vexW0", "0x42")
				} else {
					add("_yvaesdec", "Zvex_rm_v_r", 2, "Y"+bank+"m,Y"+bank+"r,Y"+bank+"r")
					encoding = append(encoding, prefix+" | vexW0", "0xF6")
				}
			}
		}
		if op != "VMPSADBW" {
			for index, bank := range []string{"x", "y", "z"} {
				width := 16 << uint(index)
				classes := "Y" + bank + "mEvex,Y" + bank + "rEvex,Y" + bank + "rEvex"
				if bank == "z" {
					classes = "Yzm,Yzr,Yzr"
				}
				prefix := fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F", 8*width)
				if op == "VPSADBW" {
					add("_yvaesdec", "Zevex_rm_v_r", 3, classes)
					encoding = append(encoding, prefix+" | evexW0", fmt.Sprintf("evexN%d", width), "0xF6")
				} else {
					add("_yvalignd", "Zevex_i_rm_v_r", 0, "Yu8,"+classes)
					parts := strings.Split(classes, ",")
					add("_yvalignd", "Zevex_i_rm_v_k_r", 3, "Yu8,"+strings.Join(parts[:2], ",")+",Yknot0,"+parts[2])
					encoding = append(encoding, prefix+"3A | evexW0", fmt.Sprintf("evexN%d | evexZeroingEnabled", width), "0x42")
				}
			}
		}
		for index := range expected {
			expected[index].OpBytes = encoding
		}
		var actual []goasmrules.X86AVXRule
		for _, rule := range rules {
			if rule.Opcode == op {
				actual = append(actual, rule)
			}
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s complete original Go encoding rows changed:\ngot %+v\nwant %+v", op, actual, expected)
		}
	}
}
