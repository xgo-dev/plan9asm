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

func TestX86ScalarPrecisionCompleteOfficialEncoderRows(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"var yxm = []ytab{\n\t{Zm_r_xm, 1, argList{Yxm, Yxr}},\n}",
		"{ACVTSD2SS, yxm, Pf2, opBytes{0x5a}}", "{ACVTSS2SD, yxm, Pf3, opBytes{0x5a}}",
	} {
		if !strings.Contains(string(legacy), expected) {
			t.Fatal("complete legacy scalar precision grammar/prefix/opcode changed", expected)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rule := range rules {
		if rule.Opcode != "VCVTSS2SD" && rule.Opcode != "VCVTSD2SS" {
			continue
		}
		prefix, w, bytes, control := "F3", "W0", "N4", "Sae"
		if rule.Opcode == "VCVTSD2SS" {
			prefix, w, bytes, control = "F2", "W1", "N8", "Rounding"
		}
		attributes := []string{
			"avxEscape | vex128 | vex" + prefix + " | vex0F | vexW0", "0x5A",
			"avxEscape | evex128 | evex" + prefix + " | evex0F | evex" + w,
			"evex" + bytes + " | evex" + control + "Enabled | evexZeroingEnabled", "0x5A",
		}
		classes := [][]string{{"Yxm", "Yxr", "Yxr"}, {"YxmEvex", "YxrEvex", "YxrEvex"}, {"YxmEvex", "YxrEvex", "Yknot0", "YxrEvex"}}
		index := rule.RowIndex
		if index < 0 || index > 2 {
			t.Fatal("scalar precision acquired an unobserved encoder row", rule)
		}
		offset, zoffset, zcase := 0, 2, "Zvex_rm_v_r"
		if index > 0 {
			offset, zoffset, zcase = 2, 0, "Zevex_rm_v_r"
			if index == 2 {
				zoffset, zcase = 3, "Zevex_rm_v_k_r"
			}
		}
		if rule.Ytab != "_yvaddsd" || rule.Prefix != "Pavx" || rule.EncodingOffset != offset ||
			rule.ZOffset != zoffset || rule.ZCase != zcase || !reflect.DeepEqual(rule.Classes, classes[index]) ||
			!reflect.DeepEqual(rule.OpBytes, attributes) {
			t.Fatal("complete precision control, tuple, zeroing or operand row changed", rule, attributes)
		}
		counts[rule.Opcode]++
	}
	if !reflect.DeepEqual(counts, map[string]int{"VCVTSS2SD": 3, "VCVTSD2SS": 3}) {
		t.Fatal("complete six AVX plus two legacy encoder row inventory changed", counts)
	}
}
