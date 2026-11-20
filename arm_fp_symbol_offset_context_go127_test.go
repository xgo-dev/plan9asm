//go:build go1.27

package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type armFPSymbolTarget struct {
	arch    Arch
	goarch  string
	ops     []string
	suffix  []string
	triples []string
}

var armFPSymbolTargets = []armFPSymbolTarget{
	{ArchARM, "arm", []string{"MOVF", "MOVD"},
		[]string{"", ".U", ".P", ".W", ".U.P", ".U.W", ".P.W", ".U.P.W", ".EQ", ".NE.P", ".EQ.U.W"},
		[]string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"}},
	{ArchARM64, "arm64", []string{"FMOVS", "FMOVD", "FMOVQ"}, []string{""},
		[]string{"aarch64-unknown-linux-gnu", "arm64-apple-macosx", "aarch64-pc-windows-msvc"}},
}

func armFPSymbolRows(target armFPSymbolTarget, expressions []string) []string {
	var rows []string
	for _, op := range target.ops {
		for _, suffix := range target.suffix {
			for _, expression := range expressions {
				rows = append(rows, op+suffix+" ·memory"+expression+"(SB),F0",
					op+suffix+" F0,·memory"+expression+"(SB)")
			}
		}
	}
	return rows
}

func armFPSymbolProgram(rows []string, resolved bool) string {
	prefix := ""
	if resolved {
		prefix = "#define OFFSET 4\nDATA ·memory+0(SB)/8,$0x0123456789abcdef\nGLOBL ·memory(SB),8,$64\n"
	}
	return prefix + "TEXT ·Probe(SB),4,$0-0\nCMP R2,R2\n" + strings.Join(rows, "\n") + "\nRET\n"
}

func TestARMFPSymbolOffsetCompleteOriginalGoRows(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj")
	arm, err := os.ReadFile(filepath.Join(root, "arm", "asm5.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{AMOVF, (C_FREG|C_ADDR), C_NONE, (C_FREG|C_ADDR), (68|69),`).FindAllString(string(arm), -1)
	if len(rows) != 2 || !regexp.MustCompile(`case AMOVF:\s*opset\(AMOVD, r0\)`).Match(arm) {
		t.Fatal("actual ARM symbol FP load/store rows or MOVD alias changed")
	}
	arm64, err := os.ReadFile(filepath.Join(root, "arm64", "asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows64 := regexp.MustCompile(`\{AFMOV([SDQ]), (C_FREG|C_ADDR), C_NONE, C_NONE, (C_FREG|C_ADDR), C_NONE, (64|65),`).FindAllStringSubmatch(string(arm64), -1)
	counts := map[string]int{}
	for _, row := range rows64 {
		if row[2] == row[3] {
			t.Fatal("an unrelated row acquired the C_ADDR FP role", row)
		}
		counts[row[1]]++
	}
	if !reflect.DeepEqual(counts, map[string]int{"S": 2, "D": 2, "Q": 2}) {
		t.Fatal("actual ARM64 complete FP symbol family changed", counts)
	}
	for _, target := range armFPSymbolTargets {
		t.Run(target.goarch, func(t *testing.T) {
			goAssemblerOracleOutput(t, target.goarch,
				armFPSymbolProgram(armFPSymbolRows(target, []string{"+OFFSET", "-OFFSET"}), true), "", true)
		})
	}
}

func TestARMFPSymbolOffsetNeedsOriginalConstants(t *testing.T) {
	for _, target := range armFPSymbolTargets {
		t.Run(target.goarch, func(t *testing.T) {
			rows := armFPSymbolRows(target, []string{"+OFFSET", "+(OFFSET/(OFFSET+1))"})
			// This prior precedes every probe/API, and uses the same complete
			// source with real definitions instead of guessed placeholder bytes.
			goAssemblerOracleOutput(t, target.goarch, armFPSymbolProgram(rows, true), "", true)
			pkg := x86AddSubLiteralPackage(t, target.goarch, "func Probe()\n")
			for _, row := range rows {
				t.Run(row, func(t *testing.T) {
					source := armFPSymbolProgram([]string{row}, false)
					file, err := Parse(target.arch, source)
					if err != nil {
						t.Fatal(err)
					}
					instruction := file.Funcs[0].Instrs[2]
					original := append([]Operand(nil), instruction.Args...)
					for _, err := range []error{
						ProbeInstruction(target.arch, target.goarch, instruction),
						ProbeInstructionSequence(target.arch, target.goarch, []Instr{instruction}),
					} {
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Errorf("valid original FP symbol expression was not contextual: %v", err)
						}
					}
					for _, api := range []string{"text", "module", "GoModule"} {
						ctx := llvm.NewContext()
						module, _, err := goASMIntegerGrammarTranslate(ctx, pkg, source,
							target.arch, target.goarch, target.triples[0], api)
						created := !module.IsNil()
						if created {
							module.Dispose()
						}
						ctx.Dispose()
						if !errors.Is(err, ErrProbeNeedsContext) || created {
							t.Errorf("%s guessed or lost the original generated FP offset: created=%t %v", api, created, err)
						}
					}
					if !reflect.DeepEqual(file.Funcs[0].Instrs[2].Args, original) {
						t.Fatal("the original unresolved operand was rewritten")
					}
				})
			}
		})
	}
}

func TestARMFPSymbolOffsetConcreteOriginalObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required for original resolved FP symbol objects")
	}
	for _, target := range armFPSymbolTargets {
		t.Run(target.goarch, func(t *testing.T) {
			source := armFPSymbolProgram(armFPSymbolRows(target, []string{"+OFFSET", "-OFFSET"}), true)
			goAssemblerOracleOutput(t, target.goarch, source, "", true)
			pkg := x86AddSubLiteralPackage(t, target.goarch, "func Probe()\n")
			for _, triple := range target.triples {
				for _, api := range []string{"text", "module", "GoModule"} {
					t.Run(triple+"/"+api, func(t *testing.T) {
						ctx := llvm.NewContext()
						defer ctx.Dispose()
						module, _, err := goASMIntegerGrammarTranslate(ctx, pkg, source,
							target.arch, target.goarch, triple, api)
						if !module.IsNil() {
							defer module.Dispose()
						}
						if err != nil || module.IsNil() {
							t.Fatal("resolved original symbol source no longer translates", err)
						}
						compileLLVMToObject(t, llc, triple, "fp-symbol.ll", "fp-symbol.o", module.String())
					})
				}
			}
		})
	}
}

func TestARMFPSymbolOffsetDoesNotHideInvalidGrammar(t *testing.T) {
	for _, target := range armFPSymbolTargets {
		t.Run(target.goarch, func(t *testing.T) {
			var rows []string
			for _, op := range target.ops {
				rows = append(rows,
					op+" ·memory+OFFSET(SB),R2", op+" R2,·memory+OFFSET(SB)",
					op+" ·memory+OFFSET(SB),SP", op+".S ·memory+OFFSET(SB),F0",
					op+" $·memory+OFFSET(SB),F0", op+" F0,$·memory+OFFSET(SB)",
					op+" ·memory+OFFSET(SB),·other(SB)", op+" ·memory+(OFFSET+)(SB),F0",
					op+" ·memory+(OFFSET/0)(SB),F0", op+" ·memory+1.5(SB),F0",
					op+" ·memory+OFFSET(XX),F0", op+" ·memory+OFFSET(SB)",
					op+" ·memory+OFFSET(SB),F0,F1")
				if target.arch == ArchARM64 {
					rows = append(rows, op+".P ·memory+OFFSET(SB),F0", op+".W F0,·memory+OFFSET(SB)")
				}
			}
			if target.arch == ArchARM64 {
				for _, op := range []string{"FMOVB", "FMOVH"} {
					rows = append(rows, op+" ·memory+OFFSET(SB),F0", op+" F0,·memory+OFFSET(SB)")
				}
			}
			for _, row := range rows {
				t.Run(row, func(t *testing.T) {
					goAssemblerOracleOutput(t, target.goarch, armFPSymbolProgram([]string{row}, true), "", false)
					file, err := Parse(target.arch, armFPSymbolProgram([]string{row}, false))
					if err != nil {
						return // Actual Go rejection already bound this original row.
					}
					instruction := file.Funcs[0].Instrs[2]
					for _, err := range []error{
						ProbeInstruction(target.arch, target.goarch, instruction),
						ProbeInstructionSequence(target.arch, target.goarch, []Instr{instruction}),
					} {
						if err == nil || errors.Is(err, ErrProbeNeedsContext) {
							t.Errorf("invalid FP operand acquired a contextual instruction role: %v", err)
						}
					}
				})
			}
		})
	}
}
