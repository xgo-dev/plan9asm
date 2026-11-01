package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86ExplicitMaskMoveIndependentCompleteEncoderRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []struct {
		opcode, store, load string
		w                   int
	}{
		{"VMASKMOVPS", "0x2E", "0x2C", 0}, {"VMASKMOVPD", "0x2F", "0x2D", 0},
		{"VPMASKMOVD", "0x8E", "0x8C", 0}, {"VPMASKMOVQ", "0x8E", "0x8C", 1},
	} {
		var expected []goasmrules.X86AVXRule
		var encoding []string
		for index, classes := range []string{"Yxr,Yxr,Ym", "Yyr,Yyr,Ym", "Ym,Yxr,Yxr", "Ym,Yyr,Yyr"} {
			zcase, opcode := "Zvex_r_v_rm", member.store
			if index >= 2 {
				zcase, opcode = "Zvex_rm_v_r", member.load
			}
			expected = append(expected, goasmrules.X86AVXRule{Opcode: member.opcode, Ytab: "_yvmaskmovpd", Prefix: "Pavx",
				Classes: strings.Split(classes, ","), RowIndex: index, ZCase: zcase, ZOffset: 2, EncodingOffset: 2 * index})
			encoding = append(encoding, fmt.Sprintf("avxEscape | vex%d | vex66 | vex0F38 | vexW%d", 128<<(index%2), member.w), opcode)
		}
		for index := range expected {
			expected[index].OpBytes = encoding
		}
		var actual []goasmrules.X86AVXRule
		for _, rule := range rules {
			if rule.Opcode == member.opcode {
				actual = append(actual, rule)
			}
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s complete original Go row/offset/opcode attributes changed:\ngot %+v\nwant %+v", member.opcode, actual, expected)
		}
	}
}

func TestX86ExplicitMaskMoveIndependentNativeISA(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ExplicitMaskMoveIndependentCases() {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction)
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}})
				found := make(map[string]bool)
				for _, feature := range strings.Split(features, ",") {
					found[feature] = true
				}
				want := "+avx"
				if strings.HasPrefix(string(ins.Op), "VPMASK") {
					want = "+avx2"
				}
				if !found[want] || found["+avx512f"] || found["+avx512vl"] {
					t.Fatal("isolated explicit mask move lost its own VEX native ISA", row.name, features, want)
				}
			})
		}
	}
}
