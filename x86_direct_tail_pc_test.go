package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86DirectTailPCRelativeSourceCoordinates(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, triple := "Q", "uint64", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, typ, triple = "L", "uint32", "i386-unknown-linux-gnu"
		}
		for _, branch := range []string{"JEQ 2(PC)", "JEQ $0, 2(PC)", "JEQ $1, 2(PC)", "JMP 2(PC)"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+branch+"/"+api, func(t *testing.T) {
					width := 8
					if arch == "386" {
						width = 4
					}
					source := fmt.Sprintf(`TEXT ·First(SB),NOSPLIT,$0-%d
 MOV%s a+0(FP),SI
 CMP%s SI,$0
 %s
 MOV%s $9,SI
middle:
 JMP body<>(SB)
TEXT body<>(SB),NOSPLIT,$0-0
 ADD%s $7,SI
 MOV%s SI,ret+%d(FP)
 RET
`, width*2, word, word, branch, word, word, word, width)
					pkg := mustGoPackage(t, "example.com/coordinates", "package p\nfunc First(a "+typ+") "+typ)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					resolve := testResolveSym(pkg.Path)
					sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: arch, TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
					var module llvm.Module
					switch api {
					case "text":
						_, err = Translate(file, options)
					case "module":
						module, err = TranslateModule(file, options)
					case "Go":
						result, goErr := TranslateGoModule(pkg, []byte(source), GoModuleOptions{GOARCH: arch, TargetTriple: triple, ResolveSym: resolve})
						err = goErr
						if result != nil {
							module = result.Module
						}
					}
					if !module.IsNil() {
						module.Dispose()
					}
					if err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86DirectTailPCRelativeDoesNotGrantPCAddress(t *testing.T) {
	for _, branch := range []string{
		"JEQ -4(PC)", // Would land on TEXT, not a continuation instruction.
		"JEQ 20(PC)", "JEQ 9223372036854775807(PC)",
		"JEQ -9223372036854775808(PC)", "JEQ missing(PC)",
		"JEQ 2(PC)(SI*1)", "JEQ $2, 2(PC)", "JEQ $1.0, 2(PC)",
		"MOVQ 2(PC),AX", "LEAQ 2(PC),AX", "CALL 2(PC)",
	} {
		t.Run(branch, func(t *testing.T) {
			file, options := x86DirectTailTestInputs(t)
			file, err := Parse(ArchAMD64, strings.Replace(x86DirectTailTestASM, " JMP shared<>(SB)", " CMPQ SI,$0\n "+branch+"\n JMP shared<>(SB)", 1))
			if err != nil {
				return // The parser independently rejects an invalid source role.
			}
			_, err = PrepareX86DirectTailSource(file, options)
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unclosed PC role accepted: %v", err)
			}
		})
	}
}

func TestX86DirectTailPCRelativeOriginalTextBoundary(t *testing.T) {
	file, err := Parse(ArchAMD64, `TEXT ·First(SB),NOSPLIT,$0-0
 JMP body<>(SB)
TEXT body<>(SB),NOSPLIT,$0-0
start:
 NOP
 JEQ 3(PC)
alias:
 PCDATA $0,$0
 NOP
last:
 RET
`)
	if err != nil {
		t.Fatal(err)
	}
	graph := &x86DirectTailGraph{original: file, goarch: "amd64", helpers: map[string]bool{"body<>": true}}
	view, err := graph.root(0, map[string]int{"·First": 0, "body<>": 1}, 4096, false)
	if err != nil {
		t.Fatal(err)
	}
	for pc, ins := range view.instructions {
		if ins.Op == "JEQ" {
			target := view.edges[pc][1]
			if view.instructions[target].Op != OpRET || view.points[target].text != 1 {
				t.Fatalf("PC counted labels or lost PCDATA: target %+v", view.points[target])
			}
		}
	}
}
