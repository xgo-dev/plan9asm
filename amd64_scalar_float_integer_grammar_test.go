package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86ScalarFloatIntegerIndependentCompleteEncoderRows(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"var yxcvfl = []ytab{\n\t{Zm_r_xm, 1, argList{Yxm, Yrl}},\n}",
		"var yxcvfq = []ytab{\n\t{Zm_r_xm, 2, argList{Yxm, Yrl}},\n}",
	} {
		if !strings.Contains(string(legacy), row) {
			t.Fatal("complete legacy operand table changed", row)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		wide, vector := strings.HasSuffix(name, "Q"), strings.HasPrefix(name, "V")
		trunc, unsigned := strings.Contains(name, "CVTT"), strings.Contains(name, "USI")
		pp, bytes := "F3", 4
		if strings.Contains(name, "SD") {
			pp, bytes = "F2", 8
		}
		opcode := "0x2D"
		if trunc {
			opcode = "0x2C"
		}
		if !vector {
			entry := fmt.Sprintf("{A%s, yxcvfl, P%s, opBytes{%s}}", name, strings.ToLower(pp), strings.ToLower(opcode))
			if wide {
				entry = fmt.Sprintf("{A%s, yxcvfq, Pw, opBytes{P%s, %s}}", name, strings.ToLower(pp), strings.ToLower(opcode))
			}
			if !strings.Contains(string(legacy), entry) {
				t.Fatal("legacy opcode attributes changed", entry)
			}
			count++
			continue
		}
		if unsigned {
			opcode = "0x79"
			if trunc {
				opcode = "0x78"
			}
		}
		word, attribute := 0, "evexRoundingEnabled"
		if wide {
			word = 1
		}
		if trunc {
			attribute = "evexSaeEnabled"
		}
		var opbytes []string
		if !unsigned {
			opbytes = append(opbytes, fmt.Sprintf("avxEscape | vex128 | vex%s | vex0F | vexW%d", pp, word), opcode)
		}
		opbytes = append(opbytes, fmt.Sprintf("avxEscape | evex128 | evex%s | evex0F | evexW%d", pp, word), fmt.Sprintf("evexN%d | %s", bytes, attribute), opcode)
		index, offset := 0, 0
		for _, row := range rules {
			if row.Opcode != name {
				continue
			}
			table, class, zcase, advance := "_yvcvtsd2si", "Yxm", "Zvex_rm_v_r", 2
			if unsigned {
				table = "_yvcvtsd2usil"
			}
			if unsigned || index == 1 {
				class, zcase, advance = "YxmEvex", "Zevex_rm_v_r", 3
			}
			if row.Ytab != table || row.Prefix != "Pavx" || row.RowIndex != index || row.EncodingOffset != offset ||
				row.ZCase != zcase || row.ZOffset != advance || !reflect.DeepEqual(row.Classes, []string{class, "Yrl"}) || !reflect.DeepEqual(row.OpBytes, opbytes) {
				t.Fatalf("%s complete independent encoder row changed: %+v", name, row)
			}
			index, offset, count = index+1, offset+advance, count+1
		}
		want := 2
		if unsigned {
			want = 1
		}
		if index != want {
			t.Fatal("missing encoder rows", name, index, want)
		}
	}
	if count != 32 {
		t.Fatal("expected all 32 encoder rows across 24 names", count)
	}
}

func x86ScalarFloatIntegerFormRows(arch string) []string {
	var rows []string
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		vector := strings.HasPrefix(name, "V")
		if arch == "386" && !vector && strings.HasSuffix(name, "Q") {
			continue
		}
		limit := 16
		if vector {
			limit = 32
		} else if arch == "386" {
			limit = 8
		}
		for index := 0; index < limit; index++ {
			rows = append(rows, fmt.Sprintf("%s X%d,AX", name, index))
		}
		gp := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
		if arch == "amd64" {
			gp = append(gp, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
		}
		for _, destination := range gp {
			rows = append(rows, name+" X1,"+destination)
		}
		for _, address := range []string{"-3(BX)", "8(BX)(CX*4)", "value+0(FP)", "local-8(SP)", "·data(SB)", "(FS)", "(GS)"} {
			rows = append(rows, name+" "+address+",AX")
		}
		if vector {
			suffixes := []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}
			if strings.Contains(name, "CVTT") {
				suffixes = []string{"SAE"}
			}
			for _, suffix := range suffixes {
				rows = append(rows, name+"."+suffix+" X0,AX")
			}
		}
	}
	return rows
}

func TestX86ScalarFloatIntegerWholeRegisterAndAddressGrammar(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		rows := x86ScalarFloatIntegerFormRows(arch)
		for index, row := range rows {
			fmt.Fprintf(&source, "TEXT f%d(SB),4,$8-8\n%s\nRET\n", index, row)
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		for _, row := range rows {
			ins := x86ScalarLaneInstruction(t, row)
			_, known, err := x86ScalarFloatIntegerProperties(ins, arch)
			index, xreg := amd64ParseXReg(ins.Args[0].Reg)
			context := arch == "386" && xreg && index >= 8
			if !known || context && !errors.Is(err, ErrProbeNeedsContext) || !context && err != nil {
				t.Fatal("actual Go accepted grammar mismatch", arch, row, err)
			}
		}
		t.Logf("%s: %d independently Go-assembled register/address/suffix witnesses", arch, len(rows))
	}
}
