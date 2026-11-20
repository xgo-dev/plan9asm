package plan9asm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86MXCSRCompleteOriginalGoRows(t *testing.T) {
	for name, rows := range map[string][]string{
		"asm6.go": {
			"{ALDMXCSR, ysvrs_mo, Pm, opBytes{0xae, 02, 0xae, 02}}",
			"{ASTMXCSR, ysvrs_om, Pm, opBytes{0xae, 03, 0xae, 03}}",
			"var ysvrs_mo = []ytab{\n\t{Zm_o, 2, argList{Ym}},\n}",
			"var ysvrs_om = []ytab{\n\t{Zo_m, 2, argList{Ym}},\n}",
		},
		"avx_optabs.go": {
			"var _yvldmxcsr = []ytab{\n\t{zcase: Zvex_rm_v_ro, zoffset: 3, args: argList{Ym}},\n}",
			"{as: AVLDMXCSR, ytab: _yvldmxcsr, prefix: Pavx, op: opBytes{\n\t\tavxEscape | vex128 | vex0F | vexW0, 0xAE, 02,\n\t}}",
			"{as: AVSTMXCSR, ytab: _yvldmxcsr, prefix: Pavx, op: opBytes{\n\t\tavxEscape | vex128 | vex0F | vexW0, 0xAE, 03,\n\t}}",
		},
	} {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if strings.Count(string(data), row) != 1 {
				t.Fatal("complete actual MXCSR operand/encoder row changed", name, row)
			}
		}
	}
}

func TestX86MXCSRByteEffectHasNoIndependentMemoryAuthority(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR"} {
			for _, operand := range []string{"(DI)", "private<>(SB)", "0(SP)"} {
				ins := x86ScalarLaneInstruction(t, op+" "+operand)
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
				state.gp[7], state.pointerGP[7] = 0xff, true
				if x86ResultTransfer(ins, &state, nil, 0, arch) {
					t.Fatal("an m32 descriptor granted pointee, private data or physical stack bytes", arch, op, operand)
				}
			}
			ins := x86ScalarLaneInstruction(t, op+" result+0(FP)")
			for missing := -1; missing < 4; missing++ {
				state := x86ResultState{fp: []bool{true, true, true, true}, flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
				if missing >= 0 {
					state.fp[missing] = false
				}
				write := strings.Contains(op, "STMXCSR")
				if got := x86ResultTransfer(ins, &state, []bool{true, true, true, true}, 0, arch); got != (write || missing < 0) {
					t.Fatal("MXCSR load skipped an input byte or store read its old bytes", arch, op, missing, got)
				}
				if state.flags != x86ByteFlagsAll || state.direction != x86ResultDirectionForward {
					t.Fatal("MXCSR changed integer status or direction knowledge")
				}
			}
		}
	}
}
