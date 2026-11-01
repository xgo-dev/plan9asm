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

func TestX86FloatingCompareSpecsBindCompleteGoTables(t *testing.T) {
	dir := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86")
	legacy, err := os.ReadFile(filepath.Join(dir, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(dir, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(x86FloatCompareSpecs) != 8 {
		t.Fatalf("comparison family has %d names, want 8", len(x86FloatCompareSpecs))
	}
	const legacyTable = "var yxcmpi = []ytab{\n\t{Zm_r_i_xm, 2, argList{Yxm, Yxr, Yi8}},\n}"
	if !strings.Contains(string(legacy), legacyTable) {
		t.Fatal("Go changed the complete signed-imm8 legacy compare grammar")
	}
	const packedTable = `var _yvcmppd = []ytab{
	{zcase: Zvex_i_rm_v_r, zoffset: 2, args: argList{Yu8, Yxm, Yxr, Yxr}},
	{zcase: Zvex_i_rm_v_r, zoffset: 2, args: argList{Yu8, Yym, Yyr, Yyr}},
	{zcase: Zevex_i_rm_v_r, zoffset: 0, args: argList{Yu8, Yzm, Yzr, Yk}},
	{zcase: Zevex_i_rm_v_k_r, zoffset: 3, args: argList{Yu8, Yzm, Yzr, Yknot0, Yk}},
	{zcase: Zevex_i_rm_v_r, zoffset: 0, args: argList{Yu8, YxmEvex, YxrEvex, Yk}},
	{zcase: Zevex_i_rm_v_k_r, zoffset: 3, args: argList{Yu8, YxmEvex, YxrEvex, Yknot0, Yk}},
	{zcase: Zevex_i_rm_v_r, zoffset: 0, args: argList{Yu8, YymEvex, YyrEvex, Yk}},
	{zcase: Zevex_i_rm_v_k_r, zoffset: 3, args: argList{Yu8, YymEvex, YyrEvex, Yknot0, Yk}},
}`
	const scalarTable = `var _yvcmpsd = []ytab{
	{zcase: Zvex_i_rm_v_r, zoffset: 2, args: argList{Yu8, Yxm, Yxr, Yxr}},
	{zcase: Zevex_i_rm_v_r, zoffset: 0, args: argList{Yu8, YxmEvex, YxrEvex, Yk}},
	{zcase: Zevex_i_rm_v_k_r, zoffset: 3, args: argList{Yu8, YxmEvex, YxrEvex, Yknot0, Yk}},
}`
	for _, table := range []string{packedTable, scalarTable} {
		if !strings.Contains(string(avx), table) {
			t.Fatalf("Go changed complete compare table: %s", strings.SplitN(table, "\n", 2)[0])
		}
	}
	for _, opcode := range x86FloatCompareOpcodes() {
		bits := 32
		if strings.HasSuffix(opcode, "PD") || strings.HasSuffix(opcode, "SD") {
			bits = 64
		}
		scalar, old := strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD"), !strings.HasPrefix(opcode, "V")
		if got := x86FloatCompareSpecs[Op(opcode)]; got != (x86FloatCompareSpec{bits, old, scalar}) {
			t.Fatalf("independent compare axes differ: %s %+v", opcode, got)
		}
		if old {
			if !strings.Contains(string(legacy), "{A"+opcode+", yxcmpi,") {
				t.Fatalf("Go legacy opcode no longer binds yxcmpi: %s", opcode)
			}
			continue
		}
		table := "_yvcmppd"
		if scalar {
			table = "_yvcmpsd"
		}
		marker := "{as: A" + opcode + ", ytab: " + table + ", prefix: Pavx, op: opBytes{"
		start := strings.Index(string(avx), marker)
		if start < 0 {
			t.Fatalf("missing Go compare opcode/table binding: %s", opcode)
		}
		row := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		vex, evex := 0, 0
		for _, line := range strings.Split(row, "\n") {
			if strings.Contains(line, "avxEscape | vex") {
				vex++
				continue
			}
			if !strings.Contains(line, "avxEscape | evex") {
				continue
			}
			evex++
			width := 16
			if strings.Contains(line, "evex256") {
				width = 32
			} else if strings.Contains(line, "evex512") {
				width = 64
			}
			memory := width
			if scalar {
				memory = bits / 8
			}
			if !strings.Contains(line, fmt.Sprintf("evexN%d", memory)) ||
				strings.Contains(line, fmt.Sprintf("evexBcstN%d", bits/8)) != !scalar ||
				strings.Contains(line, "evexSaeEnabled") != (scalar || width == 64) ||
				strings.Contains(line, "evexZeroingEnabled") || strings.Contains(line, "evexRoundingEnabled") {
				t.Fatalf("changed compare tuple/BCST/SAE/no-zero/no-round attributes: %s", line)
			}
		}
		wantVex, wantEvex := 2, 3
		if scalar {
			wantVex, wantEvex = 1, 1
		}
		if vex != wantVex || evex != wantEvex {
			t.Fatalf("%s encoding rows=%d/%d want=%d/%d", opcode, vex, evex, wantVex, wantEvex)
		}
	}
	for _, source := range []string{string(legacy), string(avx)} {
		for _, match := range regexp.MustCompile(`\{(?:as: )?A(V?CMP(?:PS|PD|SS|SD)),`).FindAllStringSubmatch(source, -1) {
			if _, exists := x86FloatCompareSpecs[Op(match[1])]; !exists {
				t.Fatalf("Go added an unregistered compare opcode: %s", match[1])
			}
		}
	}
}
