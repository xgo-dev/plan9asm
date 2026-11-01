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

func TestX86CLMULIndependentCompleteGoRows(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), "{APCLMULQDQ, yxshuf, Pq, opBytes{0x3a, 0x44, 0}}") {
		t.Fatal("complete Go legacy prefix/map/opcode/offset changed")
	}
	start := strings.Index(string(legacy), "var yxshuf = []ytab{")
	if start < 0 {
		t.Fatal("Go omitted yxshuf")
	}
	actual := strings.SplitN(string(legacy)[start:], "\n}", 2)[0]
	actual = strings.SplitN(actual, "[]ytab{", 2)[1]
	if strings.Join(strings.Fields(actual), " ") != "{Zibm_r, 2, argList{Yu8, Yxm, Yxr}}," {
		t.Fatal("complete Go legacy classes/zcase/zoffset changed", actual)
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	classes := []string{
		"Yu8,Yxm,Yxr,Yxr", "Yu8,Yym,Yyr,Yyr",
		"Yu8,YxmEvex,YxrEvex,YxrEvex", "Yu8,YymEvex,YyrEvex,YyrEvex", "Yu8,Yzm,Yzr,Yzr",
	}
	opbytes := []string{
		"avxEscape | vex128 | vex66 | vex0F3A | vexW0", "0x44",
		"avxEscape | vex256 | vex66 | vex0F3A | vexW0", "0x44",
		"avxEscape | evex128 | evex66 | evex0F3A | evexW0", "evexN16", "0x44",
		"avxEscape | evex256 | evex66 | evex0F3A | evexW0", "evexN32", "0x44",
		"avxEscape | evex512 | evex66 | evex0F3A | evexW0", "evexN64", "0x44",
	}
	count := 0
	for _, rule := range rules {
		if rule.Opcode != "VPCLMULQDQ" {
			continue
		}
		zcase := "Zevex_i_rm_v_r"
		if count < 2 {
			zcase = "Zvex_i_rm_v_r"
		}
		if count >= 5 || rule.RowIndex != count || rule.Ytab != "_yvpclmulqdq" || rule.Prefix != "Pavx" ||
			rule.ZCase != zcase || rule.ZOffset != []int{2, 2, 3, 3, 3}[count] ||
			rule.EncodingOffset != []int{0, 2, 4, 7, 10}[count] ||
			strings.Join(rule.Classes, ",") != classes[count] || !reflect.DeepEqual(rule.OpBytes, opbytes) {
			t.Fatal("complete independent Go vector row changed", rule)
		}
		count++
	}
	if count != 5 {
		t.Fatal("incomplete vector family", count)
	}
}

func x86CLMULIndependentRows(arch string) []string {
	var rows []string
	limit := 16
	if arch == "386" {
		limit = 8
	}
	for immediate := 0; immediate < 256; immediate++ {
		rows = append(rows, fmt.Sprintf("PCLMULQDQ $%d,X0,X1", immediate))
	}
	for index := 0; index < limit; index++ {
		rows = append(rows, fmt.Sprintf("PCLMULQDQ $17,X%d,X1", index), fmt.Sprintf("PCLMULQDQ $17,X0,X%d", index))
	}
	for _, memory := range []string{"(AX)", "16(BX)(CX*2)", "value+0(FP)", "local-16(SP)", "·data(SB)", "(FS)", "(GS)"} {
		rows = append(rows, "PCLMULQDQ $255,"+memory+",X1")
	}
	if arch == "386" {
		// cmd/asm classifies TYPE_CONST after mode32 signed truncation.
		rows = append(rows, "PCLMULQDQ $4294967296,X0,X1", "PCLMULQDQ $4294967551,X0,X1")
		return rows
	}
	for _, bank := range []string{"X", "Y", "Z"} {
		for immediate := 0; immediate < 256; immediate++ {
			rows = append(rows, fmt.Sprintf("VPCLMULQDQ $%d,%s0,%s1,%s2", immediate, bank, bank, bank))
		}
		for index := 0; index < 32; index++ {
			for operand := 0; operand < 3; operand++ {
				registers := []string{bank + "0", bank + "1", bank + "2"}
				registers[operand] = fmt.Sprintf("%s%d", bank, index)
				rows = append(rows, "VPCLMULQDQ $255,"+strings.Join(registers, ","))
			}
		}
		for _, memory := range []string{"(AX)", "16(BX)(CX*2)", "value+0(FP)", "local-64(SP)", "·data(SB)", "(FS)", "(GS)"} {
			rows = append(rows, "VPCLMULQDQ $17,"+memory+","+bank+"1,"+bank+"2")
		}
	}
	return rows
}

func TestX86CLMULCompleteGoOperandAxes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rows := x86CLMULIndependentRows(arch)
			var source strings.Builder
			for index, row := range rows {
				fmt.Fprintf(&source, "TEXT f%d(SB),4,$64-64\n%s\nRET\n", index, row)
			}
			goAssemblerOracleOutput(t, arch, source.String(), "", true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			for index, fn := range file.Funcs {
				ins := fn.Instrs[1]
				before := fmt.Sprintf("%#v", ins)
				form, known, err := x86CLMULProperties(ins.Op, ins, arch)
				if !known || err != nil {
					t.Fatal(rows[index], err)
				}
				for operand := range ins.Args {
					width, write, memory := x86InstructionMemoryShape(ins, operand, arch)
					if memory != (operand == form.memory) || memory && (write || width != int64(form.byteWidth)) {
						t.Fatal("native tuple differs from complete operand form", rows[index], operand, width, write, memory)
					}
					if ins.Args[operand].Kind == OpFP {
						width, write, known := X86FPAccessBytes(ins, operand, arch)
						if !known || write || width != int64(form.byteWidth) {
							t.Fatal("FP diagnostic lost full native tuple", rows[index], width, write, known)
						}
					}
				}
				if fmt.Sprintf("%#v", ins) != before {
					t.Fatal("grammar changed its original source")
				}
			}
			t.Logf("%d complete independent Go forms accepted", len(rows))
		})
	}
}

func TestX86CLMULInvalidGrammarAndPrivateBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := []string{
			"PCLMULQDQ $-1,X0,X1", "PCLMULQDQ $256,X0,X1", "PCLMULQDQ $1.5,X0,X1",
			"PCLMULQDQ $1,X16,X0", "PCLMULQDQ $1,Y0,Y1", "PCLMULQDQ $1,M0,M1",
			"PCLMULQDQ.Z $1,X0,X1", "PCLMULQDQ $1,X0,(AX)", "PCLMULQDQ $1,X0",
			"VPCLMULQDQ $-1,X0,X1,X2", "VPCLMULQDQ $256,X0,X1,X2",
			"VPCLMULQDQ.Z $1,X0,X1,X2", "VPCLMULQDQ.BCST $1,(AX),X1,X2",
			"VPCLMULQDQ $1,X0,Y1,Y2", "VPCLMULQDQ $1,X0,X1,K1,X2",
			"VPCLMULQDQ $1,X0,(AX),X2", "VPCLMULQDQ $1,X0,X1,(AX)",
		}
		if arch == "386" {
			rows = append(rows, "PCLMULQDQ $1,X8,X0", "VPCLMULQDQ $1,X0,X1,X2", "VPCLMULQDQ $1,Z0,Z1,Z2")
		}
		for _, row := range rows {
			goAssemblerOracleOutput(t, arch, "TEXT ·invalid(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			ins := x86ScalarLaneInstruction(t, row)
			if _, known, err := x86CLMULProperties(ins.Op, ins, arch); !known || err == nil {
				t.Error("unbound grammar accepted", arch, row)
			}
		}
	}
	for _, mutation := range []string{"float", "unresolved", "dispatch", "address-size", "unknown-displacement", "unknown-index"} {
		ins := x86ScalarLaneInstruction(t, "PCLMULQDQ $1,(AX),X1")
		op := ins.Op
		switch mutation {
		case "float":
			ins.Args[0].ImmIsFloat = true
		case "unresolved":
			ins.Args[0].ImmRaw = "missing"
		case "dispatch":
			ins.Op = "AESENC"
		case "address-size":
			ins.x86AddressBits = 32
		case "unknown-displacement":
			ins.Args[1].Mem.OffRaw = "missing"
		case "unknown-index":
			ins.Args[1].Mem.IndexExt = "unknown"
		}
		if _, known, err := x86CLMULProperties(op, ins, "amd64"); !known || err == nil {
			t.Error("constructed source bypassed complete grammar", mutation)
		}
	}
}
