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

func TestX86ScalarBitCountCompleteGoRows(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := []string{
		"{ALZCNTL, yml_rl, Pf3, opBytes{0xbd}}",
		"{ALZCNTQ, yml_rl, Pfw, opBytes{0xbd}}",
		"{ALZCNTW, yml_rl, Pef3, opBytes{0xbd}}",
		"{APOPCNTW, yml_rl, Pef3, opBytes{0xb8}}",
		"{APOPCNTL, yml_rl, Pf3, opBytes{0xb8}}",
		"{APOPCNTQ, yml_rl, Pfw, opBytes{0xb8}}",
		"{ATZCNTW, ycrc32l, Pe, opBytes{0xf3, 0x0f, 0xbc, 0}}",
		"{ATZCNTL, ycrc32l, Px, opBytes{0xf3, 0x0f, 0xbc, 0}}",
		"{ATZCNTQ, ycrc32l, Pw, opBytes{0xf3, 0x0f, 0xbc, 0}}",
	}
	if len(x86ScalarBitCountSpecs) != len(rows) {
		t.Fatal("incomplete scalar count family")
	}
	for _, row := range append(rows,
		"var yml_rl = []ytab{\n\t{Zm_r, 1, argList{Yml, Yrl}},\n}",
		"var ycrc32l = []ytab{\n\t{Zlitm_r, 0, argList{Yml, Yrl}},\n}") {
		if !strings.Contains(string(table), row) {
			t.Fatal("complete original Go encoding row changed:", row)
		}
	}
	for _, family := range []string{"POPCNT", "LZCNT", "TZCNT"} {
		for _, suffix := range []string{"W", "L", "Q"} {
			op := Op(family + suffix)
			for _, arch := range []string{"amd64", "386"} {
				for _, input := range []string{"AX", "AL", "X0", "$3", "$table(SB)", "4(AX)(CX*2)", "table(SB)"} {
					for _, output := range []string{"BX", "AH", "X1", "4(BX)"} {
						source := fmt.Sprintf("TEXT probe(SB),4,$0-0\n%s %s,%s\nRET\n", op, input, output)
						valid := !(arch == "386" && suffix == "Q") && output == "BX" &&
							(input == "AX" || input == "4(AX)(CX*2)" || input == "table(SB)")
						goAssemblerOracleOutput(t, arch, source, "", valid)
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						_, known, err := x86ScalarBitCountProperties(op, file.Funcs[0].Instrs[1], arch)
						if !known || (err == nil) != valid {
							t.Fatalf("%s %s %s,%s: known=%t error=%v", arch, op, input, output, known, err)
						}
					}
				}
			}
		}
	}
}

func TestX86ScalarBitCountFiveTargetThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86OrderingHintTargets {
		word, typ, move := 8, "uint64", "MOVQ"
		if target.arch == "386" {
			word, typ, move = 4, "uint32", "MOVL"
		}
		var declarations, source strings.Builder
		declarations.WriteString("package ordering\n")
		for _, family := range []string{"POPCNT", "LZCNT", "TZCNT"} {
			for _, suffix := range []string{"W", "L", "Q"} {
				if target.arch == "386" && suffix == "Q" {
					continue // Independently Go-rejected above, not a skipped test.
				}
				op := family + suffix
				name := strings.ToLower(op)
				fmt.Fprintf(&declarations, "func %s(x %s) %s\n", name, typ, typ)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s x+0(FP),AX\n%s $0,BX\n%s AX,BX\n%s BX,ret0+%d(FP)\nRET\n",
					name, 2*word, move, move, op, move, word)
			}
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), declarations.String(), target.arch, target.triple)
				if err != nil {
					t.Fatal(err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					dir := t.TempDir()
					input, object := filepath.Join(dir, "count.ll"), filepath.Join(dir, "count.o")
					if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
						t.Fatal(err)
					}
					x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+target.triple, "-filetype=obj", input, "-o", object))
				}
			})
		}
	}
}
