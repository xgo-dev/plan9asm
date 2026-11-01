package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Independent Intel/Go FMA3 opcode axes. The order changes the encoded opcode,
// not the three consumed operands. W selects precision; it is not WIG.
func x86FMA3CheckCompleteEncoderAttributes(t *testing.T) {
	t.Helper()
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, stem := range []struct {
		name   string
		opcode int
		scalar bool
	}{
		{"VFMADD", 0x98, true}, {"VFMSUB", 0x9a, true},
		{"VFNMADD", 0x9c, true}, {"VFNMSUB", 0x9e, true},
		{"VFMADDSUB", 0x96, false}, {"VFMSUBADD", 0x97, false},
	} {
		for orderIndex, order := range []string{"132", "213", "231"} {
			for _, suffix := range []string{"PS", "PD", "SS", "SD"} {
				scalar := strings.HasPrefix(suffix, "S")
				if scalar && !stem.scalar {
					continue
				}
				op := stem.name + order + suffix
				table, bits, w := "_yvaddpd", 32, 0
				if strings.HasSuffix(suffix, "D") {
					bits, w = 64, 1
				}
				opcode := stem.opcode + orderIndex*16
				vexWidths, evexWidths := []int{128, 256}, []int{512, 128, 256}
				if scalar {
					table, opcode = "_yvaddsd", opcode+1
					vexWidths, evexWidths = []int{128}, []int{128}
				}
				var expected []goasmrules.X86AVXRule
				var encoding []string
				offset := 0
				add := func(zcase string, advance int, classes string) {
					expected = append(expected, goasmrules.X86AVXRule{
						Opcode: op, Ytab: table, Prefix: "Pavx",
						Classes: strings.Split(classes, ","), RowIndex: len(expected),
						ZCase: zcase, ZOffset: advance, EncodingOffset: offset,
					})
					offset += advance
				}
				for _, width := range vexWidths {
					bank := map[int]string{128: "x", 256: "y"}[width]
					add("Zvex_rm_v_r", 2, "Y"+bank+"m,Y"+bank+"r,Y"+bank+"r")
					encoding = append(encoding,
						fmt.Sprintf("avxEscape | vex%d | vex66 | vex0F38 | vexW%d", width, w),
						fmt.Sprintf("0x%X", opcode))
				}
				for _, width := range evexWidths {
					bank := map[int]string{128: "x", 256: "y", 512: "z"}[width]
					memory, register := "Y"+bank+"mEvex", "Y"+bank+"rEvex"
					if width == 512 {
						memory, register = "Yzm", "Yzr"
					}
					add("Zevex_rm_v_r", 0, memory+","+register+","+register)
					add("Zevex_rm_v_k_r", 3, memory+","+register+",Yknot0,"+register)
					attributes := fmt.Sprintf("evexN%d | evexBcstN%d", width/8, bits/8)
					if scalar {
						attributes = fmt.Sprintf("evexN%d", bits/8)
					}
					if scalar || width == 512 {
						attributes += " | evexRoundingEnabled"
					}
					attributes += " | evexZeroingEnabled"
					encoding = append(encoding,
						fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW%d", width, w),
						attributes, fmt.Sprintf("0x%X", opcode))
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
					t.Fatalf("%s complete original Go encoding changed:\ngot %+v\nwant %+v", op, actual, expected)
				}
			}
		}
	}
}
