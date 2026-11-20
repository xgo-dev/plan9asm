package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86MoveMaskCompleteGoEncodingRows(t *testing.T) {
	for filename, rows := range map[string][]string{
		"asm6.go": {
			"{APMOVMSKB, ymskb, Px, opBytes{Pe, 0xd7, 0xd7}}",
			"{AMOVMSKPD, yxrrl, Pq, opBytes{0x50}}",
			"{AMOVMSKPS, yxrrl, Pm, opBytes{0x50}}",
			"var yxrrl = []ytab{ {Zm_r, 1, argList{Yxr, Yrl}}, }",
			"var ymskb = []ytab{ {Zm_r_xm, 2, argList{Yxr, Yrl}}, {Zm_r_xm, 1, argList{Ymr, Yrl}}, }",
		},
		"avx_optabs.go": {
			"var _yvmovmskpd = []ytab{ {zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yxr, Yrl}}, {zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yyr, Yrl}}, }",
			"{as: AVMOVMSKPD, ytab: _yvmovmskpd, prefix: Pavx, op: opBytes{ avxEscape | vex128 | vex66 | vex0F | vexW0, 0x50, avxEscape | vex256 | vex66 | vex0F | vexW0, 0x50, }}",
			"{as: AVMOVMSKPS, ytab: _yvmovmskpd, prefix: Pavx, op: opBytes{ avxEscape | vex128 | vex0F | vexW0, 0x50, avxEscape | vex256 | vex0F | vexW0, 0x50, }}",
			"{as: AVPMOVMSKB, ytab: _yvmovmskpd, prefix: Pavx, op: opBytes{ avxEscape | vex128 | vex66 | vex0F | vexW0, 0xD7, avxEscape | vex256 | vex66 | vex0F | vexW0, 0xD7, }}",
		},
	} {
		contents, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86", filename))
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(contents)), " ")
		for _, row := range rows {
			if !strings.Contains(text, row) {
				t.Fatalf("complete original Go encoding row changed in %s: %s", filename, row)
			}
		}
	}
	if len(amd64MoveMaskSpecs) != 6 {
		t.Fatal("incomplete six-name move-mask family")
	}
}

func TestX86MoveMaskIntrinsicFeatureIsInstructionLocal(t *testing.T) {
	for _, line := range []string{"PMOVMSKB X0,AX", "VPMOVMSKB X0,AX", "VPMOVMSKB Y0,AX"} {
		file, err := Parse(ArchAMD64, "TEXT original(SB),4,$0-0\n"+line+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		instruction := file.Funcs[0].Instrs[1]
		features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "386", Func{Instrs: []Instr{instruction}})
		if features != "+sse2" {
			t.Fatalf("isolated %s cannot borrow a sibling's SSE2 feature: %q", line, features)
		}
	}
}

func TestX86MoveMaskSharedGrammarMatchesActualGo(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, operation := range []string{"PMOVMSKB", "MOVMSKPS", "MOVMSKPD", "VPMOVMSKB", "VMOVMSKPS", "VMOVMSKPD"} {
			for _, source := range []string{"X0", "X7", "X8", "X15", "X16", "Y0", "Y15", "Y16", "Z0", "M0", "M7", "AX", "(AX)", "$1"} {
				for _, destination := range []string{"AX", "R8", "AL", "X1"} {
					line := operation + " " + source + "," + destination
					assembly := "TEXT original(SB),4,$0-0\n" + line + "\nRET\n"
					vex := strings.HasPrefix(operation, "V")
					validSource := source == "X0" || source == "X7" ||
						(source == "X8" || source == "X15") && (arch == "amd64" || vex) ||
						vex && (source == "Y0" || source == "Y15") ||
						operation == "PMOVMSKB" && (source == "M0" || source == "M7")
					valid := validSource && (destination == "AX" || destination == "R8" && arch == "amd64")
					goAssemblerOracleOutput(t, arch, assembly, "", valid)
					file, err := Parse(ArchAMD64, assembly)
					if err != nil {
						t.Fatal(err)
					}
					_, known, err := x86MoveMaskProperties(Op(operation), file.Funcs[0].Instrs[1], arch)
					if !known || (err == nil) != valid {
						t.Fatalf("%s %s shared grammar: known=%t err=%v", arch, line, known, err)
					}
				}
			}
		}
	}
}

func TestX86MoveMaskResultFiveTargetThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86OrderingHintTargets {
		size, typ, move := 8, "uint64", "MOVQ"
		if target.arch == "386" {
			size, typ, move = 4, "uint32", "MOVL"
		}
		var source, declarations strings.Builder
		declarations.WriteString("package masks\n")
		for index, instruction := range x86ResultMoveMaskForms {
			name := fmt.Sprintf("mask%d", index)
			fmt.Fprintf(&declarations, "func %s() %s\n", name, typ)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nVZEROALL\n%s\n%s AX,ret0+0(FP)\nRET\n", name, size, instruction, move)
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), declarations.String(), target.arch, target.triple)
				if err != nil {
					t.Fatal(err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					dir := t.TempDir()
					input, object := filepath.Join(dir, "mask.ll"), filepath.Join(dir, "mask.o")
					if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
						t.Fatal(err)
					}
					x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+target.triple, "-filetype=obj", input, "-o", object))
				}
			})
		}
	}
}
