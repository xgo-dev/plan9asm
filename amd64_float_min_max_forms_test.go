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

func x86FloatingMinMaxFormats(arch string) []string {
	var rows []string
	for _, member := range x86FloatingMinMaxCases {
		if member.legacy {
			rows = append(rows, member.op+" X0,X1", member.op+" (AX),X1")
			continue
		}
		banks := []string{"X", "Y", "Z"}
		if member.scalar {
			banks = banks[:1]
		}
		for _, bank := range banks {
			for _, mode := range []string{"", "merge", "zero"} {
				if arch == "386" && mode != "" {
					continue // Go's named four-operand frontend cap, not a physical ISA claim.
				}
				mask, zero := "", ""
				if mode != "" {
					mask = "K1,"
				}
				if mode == "zero" {
					zero = ".Z"
				}
				registers := bank + "0," + bank + "1," + mask + bank + "2"
				memory := "(AX)," + bank + "1," + mask + bank + "2"
				rows = append(rows, member.op+zero+" "+registers, member.op+zero+" "+memory)
				if !member.scalar {
					rows = append(rows, member.op+".BCST"+zero+" "+memory)
				}
				if member.scalar || bank == "Z" {
					rows = append(rows, member.op+".SAE"+zero+" "+registers)
				}
			}
		}
	}
	return rows
}

func TestX86FloatingMinMaxIndependentCompleteEncoderRows(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), "var yxm = []ytab{\n\t{Zm_r_xm, 1, argList{Yxm, Yxr}},\n}") {
		t.Fatal("complete original MIN/MAX yxm table changed")
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	if x86FloatArithmeticFamilyCount(x86FloatMinimumMaximum) != len(x86FloatingMinMaxCases) {
		t.Fatal("incomplete typed MIN/MAX family")
	}
	for _, member := range x86FloatingMinMaxCases {
		prefix, w, opcode := "", 0, "0x5D"
		if member.bits == 64 {
			prefix, w = "66", 1
		}
		if member.scalar {
			prefix = map[int]string{32: "F3", 64: "F2"}[member.bits]
		}
		if strings.Contains(member.op, "MAX") {
			opcode = "0x5F"
		}
		if member.legacy {
			p := map[string]string{"": "Pm", "66": "Pe", "F2": "Pf2", "F3": "Pf3"}[prefix]
			row := fmt.Sprintf("{A%s, yxm, %s, opBytes{%s}}", member.op, p, strings.ToLower(opcode))
			if !strings.Contains(string(legacy), row) {
				t.Fatal("original legacy MIN/MAX prefix or opcode changed", row)
			}
			continue
		}
		table := "_yvaddpd"
		vexWidths, evexWidths := []int{128, 256}, []int{512, 128, 256}
		if member.scalar {
			table, vexWidths, evexWidths = "_yvaddsd", []int{128}, []int{128}
		}
		var expected []goasmrules.X86AVXRule
		var encoding []string
		offset := 0
		add := func(zcase string, advance int, classes string) {
			expected = append(expected, goasmrules.X86AVXRule{Opcode: member.op, Ytab: table, Prefix: "Pavx",
				Classes: strings.Split(classes, ","), RowIndex: len(expected), ZCase: zcase,
				ZOffset: advance, EncodingOffset: offset})
			offset += advance
		}
		pp := func(generation string) string {
			if prefix == "" {
				return ""
			}
			return " | " + generation + prefix
		}
		for _, width := range vexWidths {
			bank := map[int]string{128: "x", 256: "y"}[width]
			add("Zvex_rm_v_r", 2, "Y"+bank+"m,Y"+bank+"r,Y"+bank+"r")
			encoding = append(encoding, fmt.Sprintf("avxEscape | vex%d%s | vex0F | vexW0", width, pp("vex")), opcode)
		}
		for _, width := range evexWidths {
			bank := map[int]string{128: "x", 256: "y", 512: "z"}[width]
			memory, register := "Y"+bank+"mEvex", "Y"+bank+"rEvex"
			if width == 512 {
				memory, register = "Yzm", "Yzr"
			}
			add("Zevex_rm_v_r", 0, memory+","+register+","+register)
			add("Zevex_rm_v_k_r", 3, memory+","+register+",Yknot0,"+register)
			attributes := fmt.Sprintf("evexN%d | evexBcstN%d", width/8, member.bits/8)
			if member.scalar {
				attributes = fmt.Sprintf("evexN%d", member.bits/8)
			}
			if member.scalar || width == 512 {
				attributes += " | evexSaeEnabled"
			}
			attributes += " | evexZeroingEnabled"
			encoding = append(encoding, fmt.Sprintf("avxEscape | evex%d%s | evex0F | evexW%d", width, pp("evex"), w), attributes, opcode)
		}
		for index := range expected {
			expected[index].OpBytes = encoding
		}
		var actual []goasmrules.X86AVXRule
		for _, rule := range rules {
			if rule.Opcode == member.op {
				actual = append(actual, rule)
			}
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s complete original encoding changed:\ngot %+v\nwant %+v", member.op, actual, expected)
		}
	}
}

func TestX86FloatingMinMaxCompleteNamedGrammar(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86FloatingMinMaxFormats(arch)
		want := 68
		if arch == "amd64" {
			want = 172
		}
		if len(rows) != want {
			t.Fatal("independent MIN/MAX format denominator changed", arch, len(rows))
		}
		requireX86GoAssemblerResult(t, arch, "TEXT Forms(SB),4,$0-0\n"+strings.Join(rows, "\n")+"\nRET\n", true)
		for _, row := range rows {
			ins := x86ScalarLaneInstruction(t, row)
			f, known, err := x86FloatMinMaxProperties(ins, arch)
			if !known || err != nil || f.byteWidth == 0 || f.rounding != "" {
				t.Fatal("complete typed MIN/MAX grammar lost an original row", arch, row, err)
			}
			if f.memory >= 0 {
				logical := ins
				logical.Args = append([]Operand(nil), ins.Args...)
				logical.Args[f.memory] = Operand{Kind: OpFP}
				width, write, valid := X86FPAccessBytes(logical, f.memory, arch)
				if !valid || write || width != int64(f.memoryBytes) {
					t.Fatal("SDK/native-width observer diverged from the complete typed tuple", arch, row, width, valid)
				}
			}
		}
	}
}

func TestX86FloatingMinMaxMalformedAndDispatchBeforeIR(t *testing.T) {
	for _, row := range []string{
		"MINPS X0,Y1", "MAXSD X0,AX", "MINSS X0,X16", "MAXPD.SAE X0,X1",
		"VMINPS X0,X1", "VMAXPD X0,Y1,Y2", "VMINSS Y0,Y1,Y2", "VMAXSD X0,X1,K0,X2",
		"VMINPS.Z X0,X1,X2", "VMAXPS.BCST X0,X1,X2", "VMINSS.BCST (AX),X1,X2",
		"VMAXPS.RN_SAE Z0,Z1,Z2", "VMINPS.SAE X0,X1,X2", "VMAXSD.SAE (AX),X1,X2",
		"VMINPS. X0,X1,X2", "VMAXPS.Z.BCST (AX),Z1,K1,Z2", "VMINSD $1.5,X1,X2",
		"VMINPS $data(SB),X1,X2", "VMAXSS (AX)(SP*2),X1,X2", "VMINPD 2147483648(AX),X1,X2",
	} {
		t.Run(row, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				return
			}
			ins := file.Funcs[0].Instrs[1]
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			known, terminated, err := ctx.lowerFloatMinMax(ins.Op, ins)
			if !known || terminated || err == nil || output.String() != before {
				t.Fatal("malformed MIN/MAX emitted IR", known, terminated, err)
			}
		})
	}
	for _, member := range x86FloatingMinMaxCases {
		row := member.op + " X0,X1,X2"
		if member.legacy {
			row = member.op + " X0,X1"
		}
		ins := x86ScalarLaneInstruction(t, row)
		file := mustParseX86RawReturn(t, "TEXT Value(SB),4,$0-0\n"+row+"\nRET\n")
		ins.Op = "UNKNOWN"
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := output.String()
		known, terminated, err := ctx.lowerFloatMinMax(Op(member.op), ins)
		if !known || terminated || err == nil || output.String() != before {
			t.Fatal("MIN/MAX dispatch changed original identity", member.op, err)
		}
	}
}
