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

func TestX86NonTemporalCompleteIndependentEncoderRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Join(strings.Fields(string(data)), "")
	for _, expected := range []string{
		"varyxr_ml=[]ytab{{Zr_m_xm,1,argList{Yxr,Yml}},}",
		"varylddqu=[]ytab{{Zm_r,1,argList{Ym,Yxr}},}",
		"{AMOVNTO,yxr_ml,Pe,opBytes{0xe7}}",
		"{AMOVNTPD,yxr_ml,Pe,opBytes{0x2b}}",
		"{AMOVNTPS,yxr_ml,Pm,opBytes{0x2b}}",
		"{AMOVNTDQA,ylddqu,Pq4,opBytes{0x2a}}",
	} {
		if !strings.Contains(legacy, expected) {
			t.Fatal("complete original Go legacy non-temporal row changed", expected)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []struct {
		name, table, pp, opcode, opcodeMap, evexW string
		load                                      bool
	}{
		{"VMOVNTDQ", "_yvmovntdq", "66", "0xE7", "0F", "0", false},
		{"VMOVNTPD", "_yvmovntdq", "66", "0x2B", "0F", "1", false},
		{"VMOVNTPS", "_yvmovntdq", "", "0x2B", "0F", "0", false},
		{"VMOVNTDQA", "_yvmovntdqa", "66", "0x2A", "0F38", "0", true},
	} {
		var rows []goasmrules.X86AVXRule
		var opbytes []string
		offset := 0
		for index, bank := range []string{"x", "y", "xEvex", "yEvex", "z"} {
			encoding, width, word, zoffset := "vex", 128, "0", 2
			if index >= 2 {
				encoding, word, zoffset = "evex", expected.evexW, 3
			}
			if bank == "y" || bank == "yEvex" {
				width = 256
			} else if bank == "z" {
				width = 512
			}
			prefix := fmt.Sprintf("avxEscape | %s%d", encoding, width)
			if expected.pp != "" {
				prefix += " | " + encoding + expected.pp
			}
			prefix += " | " + encoding + expected.opcodeMap + " | " + encoding + "W" + word
			opbytes = append(opbytes, prefix)
			if encoding == "evex" {
				opbytes = append(opbytes, fmt.Sprintf("evexN%d", width/8))
			}
			opbytes = append(opbytes, expected.opcode)
			register := "Y" + strings.Replace(bank, "Evex", "rEvex", 1)
			if !strings.HasSuffix(bank, "Evex") {
				register += "r"
			}
			classes, zcase := []string{register, "Ym"}, "Z"+encoding+"_r_v_rm"
			if expected.load {
				classes, zcase = []string{"Ym", register}, "Z"+encoding+"_rm_v_r"
			}
			rows = append(rows, goasmrules.X86AVXRule{
				Opcode: expected.name, Ytab: expected.table, Prefix: "Pavx", Classes: classes,
				RowIndex: index, ZCase: zcase, ZOffset: zoffset, EncodingOffset: offset,
			})
			offset += zoffset
		}
		for index := range rows {
			rows[index].OpBytes = opbytes
		}
		var actual []goasmrules.X86AVXRule
		for _, rule := range rules {
			if rule.Opcode == expected.name {
				actual = append(actual, rule)
			}
		}
		if !reflect.DeepEqual(actual, rows) {
			t.Fatalf("complete original Go non-temporal rows/attributes changed: %s\ngot: %+v\nwant: %+v", expected.name, actual, rows)
		}
	}
}
