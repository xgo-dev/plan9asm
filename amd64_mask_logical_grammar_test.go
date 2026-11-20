package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86MaskLogicalIndependentEncoderRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, oracle := range x86MaskLogicalOracle() {
		stem := oracle.op[:len(oracle.op)-1]
		opcode := map[string]string{
			"KAND": "0x41", "KANDN": "0x42", "KOR": "0x45", "KXNOR": "0x46",
			"KXOR": "0x47", "KNOT": "0x44", "KTEST": "0x99", "KORTEST": "0x98",
		}[stem]
		table, length, classes := "_ykaddb", "vex256", []string{"Yk", "Yk", "Yk"}
		if len(strings.Split(oracle.operands, ",")) == 2 {
			table, length, classes = "_yknotb", "vex128", []string{"Yk", "Yk"}
		}
		prefix, w := "", "vexW0"
		switch oracle.op[len(oracle.op)-1] {
		case 'B':
			prefix = " | vex66"
		case 'D':
			prefix, w = " | vex66", "vexW1"
		case 'Q':
			w = "vexW1"
		}
		bytes := []string{fmt.Sprintf("avxEscape | %s%s | vex0F | %s", length, prefix, w), opcode}
		found := 0
		for _, row := range rules {
			if row.Opcode != oracle.op {
				continue
			}
			if row.Ytab != table || row.Prefix != "Pavx" || row.RowIndex != 0 || row.EncodingOffset != 0 ||
				row.ZCase != "Zvex_rm_v_r" || row.ZOffset != 2 ||
				!reflect.DeepEqual(row.Classes, classes) || !reflect.DeepEqual(row.OpBytes, bytes) {
				t.Fatalf("complete mask encoding row changed: %+v", row)
			}
			found++
		}
		if found != 1 {
			t.Fatal("missing or additional mask encoding row", oracle.op, found)
		}
		count += found
	}
	if count != 32 || len(amd64MaskLogicalSpecs) != 32 {
		t.Fatal("complete mask family inventory changed", count, len(amd64MaskLogicalSpecs))
	}
}

func TestX86MaskLogicalLowererDispatchIdentity(t *testing.T) {
	for _, row := range x86MaskLogicalOracle() {
		t.Run(row.op, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.op+" "+row.operands)
			ctx, ir := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			ctx.goarch = "amd64"
			if err := ctx.lowerMaskLogical(ins.Op, ins); err != nil {
				t.Fatal("matching source did not reach the actual emitter", err)
			}
			ir.Reset()
			ins.Op = "MOVQ"
			if err := ctx.lowerMaskLogical(Op(row.op), ins); err == nil || ir.Len() != 0 {
				t.Fatal("mismatched source reached mask lowering", err)
			}
		})
	}
}
