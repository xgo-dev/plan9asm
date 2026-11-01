package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86SqrtIndependentEncoderAttributes(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"{ASQRTPS, yxm, Pm, opBytes{0x51}}", "{ASQRTPD, yxm, Pe, opBytes{0x51}}",
		"{ASQRTSS, yxm, Pf3, opBytes{0x51}}", "{ASQRTSD, yxm, Pf2, opBytes{0x51}}",
	} {
		if !strings.Contains(string(legacy), row) {
			t.Fatal("original Go legacy SQRT encoding changed", row)
		}
	}
	start := strings.Index(string(legacy), "var yxm = []ytab{")
	if start < 0 || strings.SplitN(string(legacy)[start:], "\n}", 2)[0] !=
		"var yxm = []ytab{\n\t{Zm_r_xm, 1, argList{Yxm, Yxr}}," {
		t.Fatal("original Go complete yxm operand table changed")
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"PS", "PD", "SS", "SD"} {
		op, table := "VSQRT"+suffix, "_yvcvtdq2ps"
		scalar := strings.HasPrefix(suffix, "S")
		prefix, bits, w := "", 32, 0
		if strings.HasSuffix(suffix, "D") {
			prefix, bits, w = "66", 64, 1
		}
		if scalar {
			table, prefix = "_yvaddsd", "F3"
			if bits == 64 {
				prefix = "F2"
			}
		}
		var expected []goasmrules.X86AVXRule
		var encoding []string
		offset := 0
		add := func(zcase string, advance int, classes string) {
			expected = append(expected, goasmrules.X86AVXRule{Opcode: op, Ytab: table, Prefix: "Pavx",
				Classes: strings.Split(classes, ","), RowIndex: len(expected), ZCase: zcase,
				ZOffset: advance, EncodingOffset: offset})
			offset += advance
		}
		vexWidths, evexWidths := []int{128, 256}, []int{512, 128, 256}
		if scalar {
			vexWidths, evexWidths = []int{128}, []int{128}
		}
		pp := func(generation string) string {
			if prefix == "" {
				return ""
			}
			return " | " + generation + prefix
		}
		for _, width := range vexWidths {
			bank := map[int]string{128: "x", 256: "y"}[width]
			classes := "Y" + bank + "m,Y" + bank + "r"
			if scalar {
				classes += ",Yxr"
			}
			add("Zvex_rm_v_r", 2, classes)
			encoding = append(encoding, fmt.Sprintf("avxEscape | vex%d%s | vex0F | vexW0", width, pp("vex")), "0x51")
		}
		for _, width := range evexWidths {
			bank := map[int]string{128: "x", 256: "y", 512: "z"}[width]
			memory, register := "Y"+bank+"mEvex", "Y"+bank+"rEvex"
			if bank == "z" {
				memory, register = "Yzm", "Yzr"
			}
			classes, masked := memory+","+register, memory+",Yknot0,"+register
			zcase := "Zevex_rm_k_r"
			attributes := fmt.Sprintf("evexN%d | evexBcstN%d", width/8, bits/8)
			if scalar {
				classes, masked = memory+","+register+","+register, memory+","+register+",Yknot0,"+register
				zcase, attributes = "Zevex_rm_v_k_r", fmt.Sprintf("evexN%d", bits/8)
			}
			if scalar || width == 512 {
				attributes += " | evexRoundingEnabled"
			}
			attributes += " | evexZeroingEnabled"
			add("Zevex_rm_v_r", 0, classes)
			add(zcase, 3, masked)
			encoding = append(encoding, fmt.Sprintf("avxEscape | evex%d%s | evex0F | evexW%d", width, pp("evex"), w), attributes, "0x51")
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
