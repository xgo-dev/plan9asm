package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

const continuationGo = `package p
func initTable()
func run(n uint64) (result uint64)
func step()
func exit()
`

const continuationAsm = `
TEXT ·initTable(SB),$0-0
 LEAQ ·step(SB),AX
 MOVQ AX,table<>(SB)
 RET
GLOBL table<>(SB),$8
TEXT ·run(SB),$0-16
 MOVQ n+0(FP),BX
 TESTQ BX,BX
 JNE start
 JMP ·exit(SB)
start:
 LEAQ table<>(SB),R14
 MOVQ (R14),AX
 JMP AX
TEXT ·step(SB),$0-0
 ADDQ $1,BX
 JMP ·exit(SB)
TEXT ·exit(SB),$0-0
 MOVQ BX,result+8(FP)
 RET
`

func continuationPackage(t *testing.T, source, assembly string) (*packages.Package, string) {
	t.Helper()
	dir := t.TempDir()
	goPath, asmPath := filepath.Join(dir, "p.go"), filepath.Join(dir, "p_amd64.s")
	for name, contents := range map[string]string{goPath: source, asmPath: assembly} {
		if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, goPath, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	config := types.Config{Sizes: types.SizesFor("gc", "amd64")}
	typed, err := config.Check("example.com/continuations", fset, []*ast.File{parsed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &packages.Package{PkgPath: typed.Path(), Types: typed, TypesSizes: config.Sizes,
		GoFiles: []string{goPath}, CompiledGoFiles: []string{goPath}}, asmPath
}

func TestInferPrivateX86Continuations(t *testing.T) {
	for _, test := range []struct {
		name, goSource, asmSource, otherSource string
		want                                   bool
	}{
		{name: "private_table", want: true},
		{name: "go_call", goSource: continuationGo + "func use() { step() }"},
		{name: "go_value", goSource: continuationGo + "var use = step"},
		{name: "linkname", goSource: continuationGo + "\n//go:linkname step remote.step\n"},
		{name: "external_asm", otherSource: "TEXT ·other(SB),$0-0\nJMP ·step(SB)\n"},
		{name: "code_offset", asmSource: strings.Replace(continuationAsm, "LEAQ ·step(SB)", "LEAQ ·step+1(SB)", 1)},
		{name: "partial_table", asmSource: strings.Replace(continuationAsm, "GLOBL table<>(SB),$8", "GLOBL table<>(SB),$16", 1)},
		{name: "table_escape", asmSource: strings.Replace(continuationAsm, " MOVQ (R14),AX", " MOVQ R14,CX\n MOVQ (R14),AX", 1)},
		{name: "table_uninitialized", asmSource: strings.Replace(continuationAsm, "start:\n", "start:\n JMP loaded\n", 1)},
		{name: "table_overwrite", asmSource: strings.Replace(continuationAsm, " MOVQ (R14),AX", " MOVQ $123,R14\n MOVQ (R14),AX", 1)},
		{name: "target_escape", asmSource: strings.Replace(continuationAsm, " JMP AX", " MOVQ AX,leak(SB)\n JMP AX", 1)},
		{name: "label_bypass", asmSource: strings.Replace(continuationAsm, " JMP AX", "bypass:\n JMP AX", 1)},
		{name: "unknown_jump", asmSource: strings.Replace(continuationAsm, " JMP AX", " JMP CX", 1)},
		{name: "helper_call", asmSource: strings.Replace(continuationAsm, " JMP ·exit(SB)", " CALL ·exit(SB)\n JMP ·exit(SB)", 1)},
		{name: "helper_frame", asmSource: strings.Replace(continuationAsm, "TEXT ·step(SB),$0-0", "TEXT ·step(SB),$8-0", 1)},
		{name: "initializer_escape", asmSource: strings.Replace(continuationAsm, " MOVQ AX,table<>(SB)", " MOVQ AX,table<>(SB)\n MOVQ AX,leak(SB)", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			goSource, asmSource := test.goSource, test.asmSource
			if goSource == "" {
				goSource = continuationGo
			}
			if asmSource == "" {
				asmSource = continuationAsm
			}
			if test.name == "table_uninitialized" {
				asmSource = strings.Replace(asmSource, " MOVQ (R14),AX", "loaded:\n MOVQ (R14),AX", 1)
			}
			pkg, path := continuationPackage(t, goSource, asmSource)
			if test.otherSource != "" {
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), "other.s"), []byte(test.otherSource), 0600); err != nil {
					t.Fatal(err)
				}
			}
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, asmSource)
			if err != nil {
				t.Fatal(err)
			}
			resolve := resolveSymFunc(pkg.PkgPath)
			sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			groups, err := inferX86TailGroups(pkg, file, path, "amd64", resolve, sigs)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(groups) == 1; got != test.want {
				t.Fatalf("inferred groups %+v, want inference=%v", groups, test.want)
			}
		})
	}
}

func TestCompileOnePreservesContinuationModule(t *testing.T) {
	pkg, path := continuationPackage(t, continuationGo, continuationAsm)
	config, err := resolveCompileConfig(true, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxFunctions, config.MaxInstructions = 1, 1
	out := filepath.Join(filepath.Dir(path), "continuation.ll")
	if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: path, OutLL: out}, false, config); err != nil {
		t.Fatal(err)
	}
	ir, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(ir), "define ") != 2 || !strings.Contains(string(ir), "blockaddress") {
		t.Fatal("root and its table initializer were not retained together")
	}
	if _, err := os.Stat(strings.TrimSuffix(out, ".ll") + ".o"); !os.IsNotExist(err) {
		t.Fatalf("temporary object not released: %v", err)
	}
}
