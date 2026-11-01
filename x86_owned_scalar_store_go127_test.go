//go:build go1.27

package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86OwnedScalarStoreCompleteOfficialGoGrammar(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := regexp.MustCompile(`//[^\n]*`).ReplaceAllString(string(data), "")
	compact := func(s string) string { return strings.Join(strings.Fields(s), "") }
	for name, expected := range map[string]string{
		"ymovb": `{Zr_m,1,argList{Yrb,Ymb}}, {Zm_r,1,argList{Ymb,Yrb}},
			{Zib_rp,1,argList{Yi32,Yrb}}, {Zibo_m,2,argList{Yi32,Ymb}},`,
		"ymovw": `{Zr_m,1,argList{Yrl,Yml}}, {Zm_r,1,argList{Yml,Yrl}},
			{Zil_rp,1,argList{Yi32,Yrl}}, {Zilo_m,2,argList{Yi32,Yml}}, {Zaut_r,2,argList{Yiauto,Yrl}},`,
		"ymovl": `{Zr_m,1,argList{Yrl,Yml}}, {Zm_r,1,argList{Yml,Yrl}},
			{Zil_rp,1,argList{Yi32,Yrl}}, {Zilo_m,2,argList{Yi32,Yml}},
			{Zm_r_xm,1,argList{Yml,Ymr}}, {Zr_m_xm,1,argList{Ymr,Yml}},
			{Zm_r_xm,2,argList{Yml,Yxr}}, {Zr_m_xm,2,argList{Yxr,Yml}}, {Zaut_r,2,argList{Yiauto,Yrl}},`,
		"ymovq": `{Zm_r_xm_nr,1,argList{Ym,Ymr}}, {Zr_m_xm_nr,1,argList{Ymr,Ym}},
			{Zm_r_xm_nr,2,argList{Yxr,Ymr}}, {Zm_r_xm_nr,2,argList{Yxm,Yxr}}, {Zr_m_xm_nr,2,argList{Yxr,Yxm}},
			{Zr_m,1,argList{Yrl,Yml}}, {Zm_r,1,argList{Yml,Yrl}},
			{Ziq_rp,1,argList{Yi64,Yrl}}, {Zilo_m,2,argList{Yi32,Yml}},
			{Zm_r_xm,1,argList{Ymm,Ymr}}, {Zr_m_xm,1,argList{Ymr,Ymm}},
			{Zm_r_xm,2,argList{Yml,Yxr}}, {Zr_m_xm,2,argList{Yxr,Yml}}, {Zaut_r,1,argList{Yiauto,Yrl}},`,
	} {
		block := regexp.MustCompile(`(?s)var ` + name + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(text)
		if len(block) != 2 || compact(block[1]) != compact(expected) {
			t.Fatal("complete original Go scalar transport table changed", name)
		}
	}
	for _, row := range []string{
		"{AMOVB,ymovb,Pb,opBytes{0x88,0x8a,0xb0,0xc6,00}}",
		"{AMOVW,ymovw,Pe,opBytes{0x89,0x8b,0xb8,0xc7,00,0}}",
		"{AMOVL,ymovl,Px,opBytes{0x89,0x8b,0xb8,0xc7,00,0x6e,0x7e,Pe,0x6e,Pe,0x7e,0}}",
		"{AMOVQ,ymovq,Pw8,opBytes{0x6f,0x7f,Pf2,0xd6,Pf3,0x7e,Pe,0xd6,0x89,0x8b,0xb8,0xc7,00,0x6e,0x7e,Pe,0x6e,Pe,0x7e,0}}",
	} {
		if strings.Count(compact(text), row) != 1 {
			t.Fatal("original Go opcode/prefix/byte inventory changed", row)
		}
	}
	frontend, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"MOVD", "MOVDQ2Q"} {
		if strings.Count(string(frontend), fmt.Sprintf(`instructions[%q] = x86.AMOVQ`, alias)) != 1 {
			t.Fatal("original Go qword source alias changed", alias)
		}
		for _, op := range []string{"MOVQ", alias} {
			goAssemblerOracleOutput(t, "386", "TEXT ·Value(SB),4,$0-0\n"+op+" AX,·storage(SB)\nRET\n", "", false)
		}
	}
}
