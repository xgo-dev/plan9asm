package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86VNNIIntegerIndependentCompleteGoEncoderRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	classes := []string{"YxmEvex,YxrEvex,YxrEvex", "YxmEvex,YxrEvex,Yknot0,YxrEvex",
		"YymEvex,YyrEvex,YyrEvex", "YymEvex,YyrEvex,Yknot0,YyrEvex", "Yzm,Yzr,Yzr", "Yzm,Yzr,Yknot0,Yzr"}
	for _, member := range x86VNNIIntegerMembers {
		count := 0
		var attributes []string
		for _, bits := range []int{128, 256, 512} {
			attributes = append(attributes, fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW0", bits),
				fmt.Sprintf("evexN%d | evexBcstN4 | evexZeroingEnabled", bits/8), fmt.Sprintf("0x%X", member.opcode))
		}
		for _, rule := range rules {
			if rule.Opcode != member.op {
				continue
			}
			zcase := "Zevex_rm_v_r"
			if count%2 != 0 {
				zcase = "Zevex_rm_v_k_r"
			}
			if count >= 6 || rule.RowIndex != count || rule.Ytab != "_yvblendmpd" || rule.Prefix != "Pavx" ||
				rule.ZCase != zcase || rule.ZOffset != count%2*3 || rule.EncodingOffset != count/2*3 ||
				strings.Join(rule.Classes, ",") != classes[count] || !reflect.DeepEqual(rule.OpBytes, attributes) {
				t.Fatal("complete independent integer-dot Go row/width/tuple/W0 attributes changed", rule)
			}
			count++
		}
		if count != 6 {
			t.Fatal("integer-dot official row denominator changed", member.op, count)
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, want := x86VNNIOracleRows(arch), 108
		if arch == "386" {
			want = 36
		}
		if len(rows) != want {
			t.Fatal("independent concrete syntax denominator changed", arch, len(rows), want)
		}
		var source strings.Builder
		for i, row := range rows {
			fmt.Fprintf(&source, "TEXT VNNI%d(SB),4,$0-0\n%s\nRET\n", i, row.instruction())
		}
		x86LEAActualTargetGoObject(t, arch, testTargetTriple("linux", arch), source.String())
	}
}
