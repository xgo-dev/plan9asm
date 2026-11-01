package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedReductionDotCompleteOfficialGoAttributes(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, opcode := range []string{"DPPD", "DPPS", "VDPPD", "VDPPS"} {
		code := "0x41"
		if strings.HasSuffix(opcode, "PS") {
			code = "0x40"
		}
		if opcode[0] != 'V' {
			if !strings.Contains(string(legacy), "{A"+opcode+", yxshuf, Pq, opBytes{0x3a, "+code+", 0}}") ||
				!strings.Contains(string(legacy), "{Zibm_r, 2, argList{Yu8, Yxm, Yxr}}") {
				t.Fatal("complete dot legacy table/opcode attributes changed", opcode)
			}
			continue
		}
		table, widths := "_yvdppd", []string{"vex128"}
		if opcode == "VDPPS" {
			table, widths = "_yvblendpd", []string{"vex128", "vex256"}
		}
		begin := strings.Index(string(avx), "{as: A"+opcode+",")
		if begin < 0 {
			t.Fatal("official Go omitted dot member", opcode)
		}
		row := strings.SplitN(string(avx)[begin:], "\n\t}},", 2)[0]
		if !strings.Contains(row, "ytab: "+table+",") || strings.Contains(row, "evex") {
			t.Fatal("dot borrowed an unsupported width/mask/suffix generation", row)
		}
		for _, width := range widths {
			if !strings.Contains(row, "avxEscape | "+width+" | vex66 | vex0F3A | vexW0, "+code) {
				t.Fatal("complete dot VEX opcode attributes changed", row)
			}
		}
	}
}

func TestX86PackedReductionVoidRetainsMeaningfulInputsAndNativeBoundaries(t *testing.T) {
	for _, row := range x86PackedReductionOracleRows() {
		destination := 1
		if !row.legacy {
			destination = 2
		}
		source, declaration := x86PackedReductionInitializedFixture("Value", "amd64", row.row, destination)
		variants := map[string]string{}
		if strings.Contains(row.row, "(BX)") {
			variants["numeric-is-not-a-pointer"] = strings.Replace(source, "MOVQ p+0(FP),BX", "MOVQ $42,BX", 1)
			variants["unknown-pointer"] = strings.Replace(source, "MOVQ p+0(FP),BX\n", "", 1)
			variants["native-SP"] = strings.Replace(source, row.row, strings.Replace(row.row, "(BX)", "(SP)", 1), 1)
		} else {
			variants["missing-first-data"] = strings.Replace(source, "VPXORD Z0,Z0,Z0\n", "", 1)
		}
		variants["missing-second-or-legacy-old-data"] = strings.Replace(source, "VPXORD Z1,Z1,Z1\n", "", 1)
		for name, changed := range variants {
			t.Run(fmt.Sprintf("%s/%s", row.row, name), func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Error("Void invented a meaningful arithmetic input or native storage permission", api, err)
					}
				}
			})
		}
		if !row.legacy {
			t.Run(row.row+"/VEX-write-only-destination", func(t *testing.T) {
				withoutOld := strings.Replace(source, "VPXORD Z2,Z2,Z2\n", "", 1)
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, withoutOld, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
						t.Fatal("VEX reduction invented a merging destination dependency", api, err)
					}
				}
			})
		}
	}
}
