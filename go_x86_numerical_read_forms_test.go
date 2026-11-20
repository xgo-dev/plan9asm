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
)

// This directory is independent of the production spec and shared extension
// grammar. Width/mode expectations come from complete stock-Go encoder rows.
var numericalSBOracleRows = []struct {
	op, table, prefix, bytes string
	source, gp               int64
	rejected386              bool
}{
	{"MOVB", "ymovb", "Pb", "0x88, 0x8a, 0xb0, 0xc6, 00", 1, 1, false},
	{"MOVW", "ymovw", "Pe", "0x89, 0x8b, 0xb8, 0xc7, 00, 0", 2, 2, false},
	{"MOVL", "ymovl", "Px", "0x89, 0x8b, 0xb8, 0xc7, 00, 0x6e, 0x7e, Pe, 0x6e, Pe, 0x7e, 0", 4, 4, false},
	{"MOVQ", "ymovq", "Pw8", "0x6f, 0x7f, Pf2, 0xd6, Pf3, 0x7e, Pe, 0xd6, 0x89, 0x8b, 0xb8, 0xc7, 00, 0x6e, 0x7e, Pe, 0x6e, Pe, 0x7e, 0", 8, 8, true},
	{"MOVBWSX", "ymb_rl", "Pq", "0xbe", 1, 2, false},
	{"MOVBWZX", "ymb_rl", "Pq", "0xb6", 1, 2, false},
	{"MOVBLSX", "ymb_rl", "Pm", "0xbe", 1, 4, false},
	{"MOVBLZX", "ymb_rl", "Pm", "0xb6", 1, 4, false},
	{"MOVBQSX", "ymb_rl", "Pw", "0x0f, 0xbe", 1, 8, true},
	{"MOVBQZX", "ymb_rl", "Pw", "0x0f, 0xb6", 1, 8, true},
	{"MOVWLSX", "yml_rl", "Pm", "0xbf", 2, 4, false},
	{"MOVWLZX", "yml_rl", "Pm", "0xb7", 2, 4, false},
	{"MOVWQSX", "yml_rl", "Pw", "0x0f, 0xbf", 2, 8, true},
	{"MOVWQZX", "yml_rl", "Pw", "0x0f, 0xb7", 2, 8, true},
	{"MOVLQSX", "yml_rl", "Pw", "0x63", 4, 8, true},
	{"MOVLQZX", "yml_rl", "Px", "0x8b", 4, 8, false},
	{"MOVSWW", "ymb_rl", "Pe", "0x0f, 0xbf", 2, 2, false},
	{"MOVZWW", "ymb_rl", "Pe", "0x0f, 0xb7", 2, 2, false},
	{"CMPB", "ycmpb", "Pb", "0x3c, 0x80, 07, 0x38, 0x3a", 1, 1, false},
	{"CMPW", "ycmpl", "Pe", "0x83, 07, 0x3d, 0x81, 07, 0x39, 0x3b", 2, 2, false},
	{"CMPL", "ycmpl", "Px", "0x83, 07, 0x3d, 0x81, 07, 0x39, 0x3b", 4, 4, false},
	{"CMPQ", "ycmpl", "Pw", "0x83, 07, 0x3d, 0x81, 07, 0x39, 0x3b", 8, 8, true},
}

func TestGoX86NumericalSBReadCompleteIndependentGoEncoderAttributes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for table, body := range map[string]string{
		"ymovb": `{Zr_m, 1, argList{Yrb, Ymb}}, {Zm_r, 1, argList{Ymb, Yrb}},
{Zib_rp, 1, argList{Yi32, Yrb}}, {Zibo_m, 2, argList{Yi32, Ymb}},`,
		"ymovw": `{Zr_m, 1, argList{Yrl, Yml}}, {Zm_r, 1, argList{Yml, Yrl}},
{Zil_rp, 1, argList{Yi32, Yrl}}, {Zilo_m, 2, argList{Yi32, Yml}}, {Zaut_r, 2, argList{Yiauto, Yrl}},`,
		"ymovl": `{Zr_m, 1, argList{Yrl, Yml}}, {Zm_r, 1, argList{Yml, Yrl}},
{Zil_rp, 1, argList{Yi32, Yrl}}, {Zilo_m, 2, argList{Yi32, Yml}},
{Zm_r_xm, 1, argList{Yml, Ymr}}, {Zr_m_xm, 1, argList{Ymr, Yml}},
{Zm_r_xm, 2, argList{Yml, Yxr}}, {Zr_m_xm, 2, argList{Yxr, Yml}}, {Zaut_r, 2, argList{Yiauto, Yrl}},`,
		"ymovq": `{Zm_r_xm_nr, 1, argList{Ym, Ymr}}, {Zr_m_xm_nr, 1, argList{Ymr, Ym}},
{Zm_r_xm_nr, 2, argList{Yxr, Ymr}}, {Zm_r_xm_nr, 2, argList{Yxm, Yxr}}, {Zr_m_xm_nr, 2, argList{Yxr, Yxm}},
{Zr_m, 1, argList{Yrl, Yml}}, {Zm_r, 1, argList{Yml, Yrl}}, {Ziq_rp, 1, argList{Yi64, Yrl}},
{Zilo_m, 2, argList{Yi32, Yml}}, {Zm_r_xm, 1, argList{Ymm, Ymr}}, {Zr_m_xm, 1, argList{Ymr, Ymm}},
{Zm_r_xm, 2, argList{Yml, Yxr}}, {Zr_m_xm, 2, argList{Yxr, Yml}}, {Zaut_r, 1, argList{Yiauto, Yrl}},`,
		"ymb_rl": `{Zmb_r, 1, argList{Ymb, Yrl}},`,
		"yml_rl": `{Zm_r, 1, argList{Yml, Yrl}},`,
		"ycmpb": `{Z_ib, 1, argList{Yal, Yi32}}, {Zm_ibo, 2, argList{Ymb, Yi32}},
{Zm_r, 1, argList{Ymb, Yrb}}, {Zr_m, 1, argList{Yrb, Ymb}},`,
		"ycmpl": `{Zm_ibo, 2, argList{Yml, Yi8}}, {Z_il, 1, argList{Yax, Yi32}},
{Zm_ilo, 2, argList{Yml, Yi32}}, {Zm_r, 1, argList{Yml, Yrl}}, {Zr_m, 1, argList{Yrl, Yml}},`,
	} {
		start := strings.Index(string(data), "var "+table+" = []ytab{")
		if start < 0 {
			t.Fatal("actual Go omitted complete scalar table", table)
		}
		actual := strings.SplitN(strings.SplitN(string(data)[start:], "\n}", 2)[0], "[]ytab{", 2)[1]
		actualTokens, err := x86SignedPackedFloatGoOpcodeTokens(actual)
		wantTokens, expectedErr := x86SignedPackedFloatGoOpcodeTokens(body)
		if err != nil || expectedErr != nil || !reflect.DeepEqual(actualTokens, wantTokens) {
			t.Fatal("actual Go complete scalar zcase/zoffset/operand classes changed", table)
		}
	}
	if len(x86NumericalSBReadSpecs) != len(numericalSBOracleRows) {
		t.Fatal("typed numerical read inventory differs from complete independent scalar rows")
	}
	for _, row := range numericalSBOracleRows {
		attribute := fmt.Sprintf("{A%s, %s, %s, opBytes{%s}}", row.op, row.table, row.prefix, row.bytes)
		if !strings.Contains(string(data), attribute) {
			t.Fatal("actual Go opcode prefix/attributes changed", attribute)
		}
	}
}

func TestGoX86NumericalSBReadTypedModeWidthAndLegalPartners(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range numericalSBOracleRows {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				instruction := row.op + " global+4(SB),AX"
				source := "TEXT ·Value(SB),4,$0-0\n" + instruction + "\nRET\n"
				accepted := arch != "386" || !row.rejected386
				goAssemblerOracleOutput(t, arch, source, "", accepted)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				form, valid := x86NumericalSBReadProperties(file.Funcs[0].Instrs[1], arch)
				gp := row.gp
				if arch == "386" && row.op == "MOVLQZX" {
					gp = 4
				}
				if valid != accepted || valid && (form.operand != 0 || form.partner != 1 || form.spec.sourceBytes != row.source || form.spec.gpBytes != gp) {
					t.Fatalf("actual scalar memory/GP bytes or mode differ: %+v valid=%v", form, valid)
				}
			})
		}
		for _, row := range []struct {
			instruction               string
			goAccepted, shapeAccepted bool
		}{
			{"MOVB global(SB),AL", true, true},
			{"MOVB global(SB),AH", true, true},
			{"MOVB global(SB),R8B", arch == "amd64", arch == "amd64"},
			{"MOVW global(SB),R8", arch == "amd64", arch == "amd64"},
			{"CMPB global(SB),AH", true, true},
			{"CMPB AH,global(SB)", true, true},
			{"CMPL global(SB),$4294967295", true, true},
			{"MOVW global(SB),AL", false, false},
			{"MOVL global(SB),AH", false, false},
			{"CMPW global(SB),AH", false, false},
			{"CMPL $1,global(SB)", false, false},
			{"MOVL global(SB),X0", true, false},
			{"MOVQ global(SB),M0", true, false},
			{"MOVL $global(SB),AX", true, false},
			{"MOVL AX,global(SB)", true, false},
		} {
			t.Run(arch+"/"+row.instruction, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-0\n" + row.instruction + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", row.goAccepted)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, _, valid := x86NumericalSBReadShape(file.Funcs[0].Instrs[1], arch)
				if valid != row.shapeAccepted {
					t.Fatal("non-GP/address/store/illegal partner acquired observation shape", valid)
				}
			})
		}
	}
}
