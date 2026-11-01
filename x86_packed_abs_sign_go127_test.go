//go:build go1.27

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

func TestX86PackedAbsSignCompleteOfficialGoRows(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), "var yxm_q4 = []ytab{\n\t{Zm_r, 1, argList{Yxm, Yxr}},\n}") {
		t.Fatal("Go's legacy ABS/sign class must not acquire Intel's separate MMX encodings")
	}
	for index, suffix := range []string{"B", "W", "D"} {
		for _, spec := range []struct {
			stem string
			code int
		}{{"PABS", 0x1c}, {"PSIGN", 8}} {
			entry := fmt.Sprintf("{A%s%s, yxm_q4, Pq4, opBytes{0x%02x}}", spec.stem, suffix, spec.code+index)
			if !strings.Contains(string(legacy), entry) {
				t.Fatal("complete legacy prefix/opcode/operand row changed", entry)
			}
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rule := range rules {
		if !strings.HasPrefix(rule.Opcode, "VPABS") && !strings.HasPrefix(rule.Opcode, "VPSIGN") {
			continue
		}
		sign, quad := strings.HasPrefix(rule.Opcode, "VPSIGN"), rule.Opcode == "VPABSQ"
		index := strings.Index("BWDQ", rule.Opcode[len(rule.Opcode)-1:])
		if index < 0 || sign && index == 3 {
			t.Fatal("official ABS/sign mnemonic inventory expanded", rule.Opcode)
		}
		opcode, table := 0x1c+index, "_yvmovddup"
		if sign {
			opcode, table = 8+index, "_yvaddsubpd"
		} else if quad {
			table = "_yvexpandpd"
		}
		var bytes []string
		if !quad {
			for _, width := range []string{"vex128", "vex256"} {
				bytes = append(bytes, "avxEscape | "+width+" | vex66 | vex0F38 | vexW0", fmt.Sprintf("0x%02X", opcode))
			}
		}
		if !sign {
			for at, width := range []string{"evex128", "evex256", "evex512"} {
				w, attributes := "evexW0", fmt.Sprintf("evexN%d", 16<<at)
				if quad {
					w = "evexW1"
				}
				if index >= 2 {
					attributes += fmt.Sprintf(" | evexBcstN%d", 1<<index)
				}
				bytes = append(bytes, "avxEscape | "+width+" | evex66 | evex0F38 | "+w,
					attributes+" | evexZeroingEnabled", fmt.Sprintf("0x%02X", opcode))
			}
		}
		ordinal, offset, zoffset, zcase := rule.RowIndex, rule.RowIndex*2, 2, "Zvex_rm_v_r"
		var classes []string
		if !quad && ordinal < 2 {
			classes = [][]string{{"Yxm", "Yxr"}, {"Yym", "Yyr"}}[ordinal]
			if sign {
				classes = append(classes, classes[1])
			}
		} else {
			if !quad {
				ordinal -= 2
			}
			offset, zoffset, zcase = ordinal/2*3, 0, "Zevex_rm_v_r"
			if !quad {
				offset += 4
			}
			classes = append([]string(nil), [][]string{{"YxmEvex", "YxrEvex"}, {"YymEvex", "YyrEvex"}, {"Yzm", "Yzr"}}[ordinal/2]...)
			if ordinal%2 != 0 {
				classes, zoffset, zcase = []string{classes[0], "Yknot0", classes[1]}, 3, "Zevex_rm_k_r"
			}
		}
		if rule.Ytab != table || rule.Prefix != "Pavx" || !reflect.DeepEqual(rule.OpBytes, bytes) ||
			rule.EncodingOffset != offset || rule.ZOffset != zoffset || rule.ZCase != zcase || !reflect.DeepEqual(rule.Classes, classes) {
			t.Fatal("complete official ABS/sign operand/encoding/tuple/broadcast/zeroing row changed", rule, classes, bytes)
		}
		counts[rule.Opcode]++
	}
	want := map[string]int{"VPABSB": 8, "VPABSW": 8, "VPABSD": 8, "VPABSQ": 6, "VPSIGNB": 2, "VPSIGNW": 2, "VPSIGND": 2}
	if !reflect.DeepEqual(counts, want) {
		t.Fatal("complete 36 AVX plus six legacy row denominator changed", counts)
	}
}
