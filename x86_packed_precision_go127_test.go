//go:build go1.27

package plan9asm

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86PackedPrecisionCompleteOfficialRowsAndAttributes(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"var yxm = []ytab{\n\t{Zm_r_xm, 1, argList{Yxm, Yxr}},\n}",
		"{ACVTPS2PD, yxm, Pm, opBytes{0x5a}}", "{ACVTPD2PS, yxm, Pe, opBytes{0x5a}}",
	} {
		if !strings.Contains(string(legacy), expected) {
			t.Fatal("complete legacy packed precision row/prefix/opcode changed", expected)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for _, rule := range rules {
		var table string
		var classes [][]string
		var encoding []string
		var offsets, advances []int
		switch rule.Opcode {
		case "VCVTPS2PD":
			table = "_yvcvtph2ps"
			classes = [][]string{{"Yxm", "Yxr"}, {"Yxm", "Yyr"},
				{"YymEvex", "Yzr"}, {"YymEvex", "Yknot0", "Yzr"},
				{"YxmEvex", "YxrEvex"}, {"YxmEvex", "Yknot0", "YxrEvex"},
				{"YxmEvex", "YyrEvex"}, {"YxmEvex", "Yknot0", "YyrEvex"}}
			encoding = []string{"avxEscape | vex128 | vex0F | vexW0", "0x5A",
				"avxEscape | vex256 | vex0F | vexW0", "0x5A",
				"avxEscape | evex512 | evex0F | evexW0", "evexN32 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled", "0x5A",
				"avxEscape | evex128 | evex0F | evexW0", "evexN8 | evexBcstN4 | evexZeroingEnabled", "0x5A",
				"avxEscape | evex256 | evex0F | evexW0", "evexN16 | evexBcstN4 | evexZeroingEnabled", "0x5A"}
			offsets, advances = []int{0, 2, 4, 4, 7, 7, 10, 10}, []int{2, 2, 0, 3, 0, 3, 0, 3}
		case "VCVTPD2PSX", "VCVTPD2PSY":
			table = "_yvcvtpd2dqx"
			operand, vexWidth, evexWidth, tuple := "Yxm", "vex128", "evex128", "evexN16"
			if rule.Opcode == "VCVTPD2PSY" {
				table, operand, vexWidth, evexWidth, tuple = "_yvcvtpd2dqy", "Yym", "vex256", "evex256", "evexN32"
			}
			classes = [][]string{{operand, "Yxr"}, {operand + "Evex", "YxrEvex"}, {operand + "Evex", "Yknot0", "YxrEvex"}}
			encoding = []string{"avxEscape | " + vexWidth + " | vex66 | vex0F | vexW0", "0x5A",
				"avxEscape | " + evexWidth + " | evex66 | evex0F | evexW1", tuple + " | evexBcstN8 | evexZeroingEnabled", "0x5A"}
			offsets, advances = []int{0, 2, 2}, []int{2, 0, 3}
		case "VCVTPD2PS":
			table = "_yvcvtpd2dq"
			classes = [][]string{{"Yzm", "YyrEvex"}, {"Yzm", "Yknot0", "YyrEvex"}}
			encoding = []string{"avxEscape | evex512 | evex66 | evex0F | evexW1",
				"evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled", "0x5A"}
			offsets, advances = []int{0, 0}, []int{0, 3}
		default:
			continue
		}
		index := rule.RowIndex
		if index < 0 || index >= len(classes) {
			t.Fatal("unobserved packed precision encoder row", rule)
		}
		zcase := "Zevex_rm_v_r"
		if strings.HasPrefix(encoding[offsets[index]], "avxEscape | vex") {
			zcase = "Zvex_rm_v_r"
		} else if len(classes[index]) == 3 {
			zcase = "Zevex_rm_k_r"
		}
		if rule.Ytab != table || rule.Prefix != "Pavx" || rule.ZCase != zcase ||
			rule.EncodingOffset != offsets[index] || rule.ZOffset != advances[index] ||
			!reflect.DeepEqual(rule.Classes, classes[index]) || !reflect.DeepEqual(rule.OpBytes, encoding) {
			t.Fatal("complete packed precision row, tuple, width, SAE/ER or mask attribute changed", rule)
		}
		counts[rule.Opcode]++
	}
	if !reflect.DeepEqual(counts, map[string]int{"VCVTPS2PD": 8, "VCVTPD2PSX": 3, "VCVTPD2PSY": 3, "VCVTPD2PS": 2}) {
		t.Fatal("six names / eighteen complete official precision rows changed", counts)
	}
}
