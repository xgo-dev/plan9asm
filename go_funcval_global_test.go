package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

var goFuncvalGlobalCases = []struct{ name, declaration string }{
	{"static", "var callback = target"},
	{"named", "type Callback func(uintptr) uintptr\nvar callback Callback = target"},
	{"mutable", "var callback = target\nfunc replace(f func(uintptr) uintptr) { callback = f }"},
	{"captured", "var callback = capture(7)\nfunc capture(n uintptr) func(uintptr) uintptr { return func(x uintptr) uintptr { return x+n } }"},
	{"nil-is-not-proven-nonnull", "var callback func(uintptr) uintptr"},
}

func goFuncvalGlobalDeclarations(declaration string) string {
	return "package ordinaryglobals\nfunc target(x uintptr) uintptr { return x+1 }\n" +
		declaration + "\nfunc view() uintptr\n"
}

func goFuncvalGlobalSource(arch, body string) []byte {
	word, move, extract := 8, "MOVQ", "PEXTRQ"
	if arch == "386" {
		word, move, extract = 4, "MOVL", "PEXTRD"
	}
	// The exact two source loads stay independent of this identity bit view.
	// The latter makes the complete ordinary input audit observable, including
	// when testing a malformed source whose value would otherwise be unused.
	return []byte(fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s\n%s AX,X0\n%s $0,X0,AX\n%s AX,ret+0(FP)\nRET\n",
		word, body, move, extract, move))
}

func goFuncvalGlobalRequest(t *testing.T, pkg GoPackage, source []byte, arch, triple, api string) (string, error) {
	t.Helper()
	if api == "GoModule" {
		return ordinaryGlobalReadRequest(t, pkg, source, arch, triple, "public")
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translated, err := TranslateGoModuleInContext(ctx, pkg, source, GoModuleOptions{
		GOOS: "linux", GOARCH: arch, Sizes: types.SizesFor("gc", arch),
		TargetTriple: triple, ResolveSym: testResolveSym(pkg.Path),
	})
	if translated == nil {
		return "", err
	}
	defer translated.Module.Dispose()
	return translated.Module.String(), err
}

func TestGoModuleFunctionValueCodeWordOriginalGo(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move := "MOVQ"
		if arch == "386" {
			move = "MOVL"
		}
		for _, row := range goFuncvalGlobalCases {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				dir := t.TempDir()
				declarations := goFuncvalGlobalDeclarations(row.declaration)
				declarations = strings.Replace(declarations, "package ordinaryglobals\n", "package ordinaryglobals\nimport \"unsafe\"\n", 1)
				// The actual compiler, rather than go/types or translator
				// metadata, must agree that function storage is one native word.
				declarations += "var _ [unsafe.Sizeof(callback)-unsafe.Sizeof(uintptr(0))]byte\n" +
					"var _ [unsafe.Sizeof(uintptr(0))-unsafe.Sizeof(callback)]byte\n"
				assembly := goFuncvalGlobalSource(arch, move+" ·callback(SB),DI\n"+move+" (DI),AX")
				for name, data := range map[string][]byte{
					"go.mod":   []byte("module " + ordinaryGlobalReadPackage + "\n\ngo 1.20\n"),
					"value.go": []byte(declarations), "value_" + arch + ".s": assembly,
				} {
					if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				archive := filepath.Join(t.TempDir(), "original.a")
				env := append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0",
					"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOPROXY=off")
				output, err := goasmcmd.Run(ctx, dir, env, filepath.Join(runtime.GOROOT(), "bin/go"),
					"build", "-p=1", "-o", archive, ".")
				if err != nil {
					t.Fatalf("actual Go source/variable/assembly compilation: %v\n%s", err, output)
				}
				if info, err := os.Stat(archive); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
					t.Fatal("actual Go produced no complete package archive", err)
				}
				t.Log("complete original Go package archive; no runtime execution claimed")
			})
		}
	}
}

func TestGoModuleFunctionValueCodeWordReads(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		move, triple, word := "MOVQ", "x86_64-unknown-linux-gnu", 8
		if arch == "386" {
			move, triple, word = "MOVL", "i386-unknown-linux-gnu", 4
		}
		for _, row := range goFuncvalGlobalCases {
			for _, api := range []string{"GoModule", "GoModuleInContext"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					pkg := mustGoPackage(t, ordinaryGlobalReadPackage, goFuncvalGlobalDeclarations(row.declaration))
					assembly := goFuncvalGlobalSource(arch, move+" ·callback(SB),DI\n"+move+" (DI),AX")
					ir, err := goFuncvalGlobalRequest(t, pkg, assembly, arch, triple, api)
					if err != nil || ir == "" {
						t.Fatalf("exact typed Go-funcval code-word extraction: output=%t err=%v", ir != "", err)
					}
					if strings.Count(ir, "load volatile ") != 2 ||
						!strings.Contains(ir, fmt.Sprintf("load volatile i%d,", word*8)) {
						t.Fatalf("mutable global/code-word read or nil fault was folded/widened:\n%s", ir)
					}
					compileLLVMToObject(t, llc, triple, "funcval-code-word.ll", "funcval-code-word.o", ir)
				})
			}
		}
	}
}

func TestGoModuleFunctionValueCodeWordDoesNotGrantStorage(t *testing.T) {
	for _, row := range []struct{ name, declaration, body string }{
		{"pointer", "var callback *byte", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX"},
		{"header", "var callback []byte", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX"},
		{"function-symbol", "func callback() {}", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX"},
		{"descriptor-is-not-NUM", "var callback func()", "MOVQ ·callback(SB),AX"},
		{"global-offset", "var callback func()", "MOVQ ·callback+1(SB),DI\nMOVQ (DI),AX"},
		{"partial-global", "var callback func()", "MOVL ·callback(SB),DI\nMOVQ (DI),AX"},
		{"partial-code-word", "var callback func()", "MOVQ ·callback(SB),DI\nMOVB (DI),AX"},
		{"environment-is-not-storage", "var callback func()", "MOVQ ·callback(SB),DI\nMOVQ 8(DI),AX"},
		{"index-is-not-proved", "var callback func()", "MOVQ ·callback(SB),DI\nMOVQ (DI)(SI*1),AX"},
		{"unknown-overwrite", "var callback func()", "MOVQ ·callback(SB),DI\nMOVQ SI,DI\nMOVQ (DI),AX"},
		{"partial-alias-overwrite", "var callback func()", "MOVQ ·callback(SB),DI\nMOVB AL,DI\nMOVQ (DI),AX"},
		{"label-before-code", "var callback func()", "MOVQ ·callback(SB),DI\ncode:\nMOVQ (DI),AX"},
		{"alternate-label-entry", "var callback func()", "MOVL $0,CX\nCMPL CX,$0\nJE code\nMOVQ ·callback(SB),DI\ncode:\nMOVQ (DI),AX"},
		{"numeric-PC-entry", "var callback func()", "MOVL $0,CX\nCMPL CX,$0\nJE 2(PC)\nMOVQ ·callback(SB),DI\nMOVQ (DI),AX"},
		{"dead-unpaired-value", "var callback func()", "MOVQ ·callback(SB),DI\nMOVQ $7,AX"},
		{"descriptor-stays-opaque", "var callback func()", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX\nMOVQ DI,AX"},
		{"no-global-store", "var callback func()", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX\nMOVQ AX,·callback(SB)"},
		{"no-environment-read", "var callback func()", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX\nMOVQ 8(DI),AX"},
	} {
		for _, api := range []string{"GoModule", "GoModuleInContext"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\n"+row.declaration+"\nfunc view() uintptr\n")
				ir, err := goFuncvalGlobalRequest(t, pkg, goFuncvalGlobalSource("amd64", row.body),
					"amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("descriptor read lent a different storage/input role: output=%t err=%v", ir != "", err)
				}
			})
		}
	}
}

func TestGoModuleFunctionValueCodeWordNeedsSourceOwner(t *testing.T) {
	source := goFuncvalGlobalSource("amd64", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX")
	declaration := "package ordinaryglobals\nvar callback func()\nfunc view() uintptr\n"
	for _, mutation := range []string{"missing-types", "missing-syntax", "wrong-type", "wrong-package"} {
		t.Run(mutation, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, declaration)
			switch mutation {
			case "missing-types":
				pkg.Types = nil
			case "missing-syntax":
				pkg.Syntax = nil
			case "wrong-type":
				pkg.Syntax = mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\nvar callback *byte\nfunc view() uintptr\n").Syntax
			case "wrong-package":
				pkg.Syntax[0].Name.Name = "different"
			}
			ir, err := goFuncvalGlobalRequest(t, pkg, source, "amd64", "x86_64-unknown-linux-gnu", "GoModule")
			if mutation == "missing-types" {
				if ir != "" || err == nil || !strings.Contains(err.Error(), "missing types") {
					t.Fatal("missing actual type declaration was accepted", err, ir)
				}
			} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unbound descriptor source: output=%t err=%v", ir != "", err)
			}
		})
	}
	for _, api := range []string{"text", "module"} {
		t.Run("raw-"+api, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, declaration)
			ir, err := x86ScalarFPBitViewPackageAPI(t, string(source), pkg, "amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("raw API borrowed typed global declaration: output=%t err=%v", ir != "", err)
			}
		})
	}
}

func TestGoModuleFunctionValueCodeWordRequiresGoConvention(t *testing.T) {
	var directives []string
	for _, prefix := range []string{"//llgo:", "// llgo:"} {
		for _, padding := range []string{"", " ", "\t"} {
			for _, marker := range []string{"cdecl", "stdcall", "type C", "type stdcall"} {
				directives = append(directives, prefix+padding+marker)
			}
		}
	}
	for _, directive := range directives {
		for _, alias := range []bool{false, true} {
			for _, api := range []string{"GoModule", "GoModuleInContext"} {
				t.Run(fmt.Sprintf("%s/alias=%t/%s", directive, alias, api), func(t *testing.T) {
					typeName := "Native"
					declarations := directive + "\ntype Native func()\n"
					if alias {
						declarations += "type Alias = Native\n"
						typeName = "Alias"
					}
					pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
						"package ordinaryglobals\n"+declarations+"var callback "+typeName+"\nfunc view() uintptr\n")
					ir, err := goFuncvalGlobalRequest(t, pkg,
						goFuncvalGlobalSource("amd64", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX"),
						"amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("native function type inherited Go descriptor layout: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
	for _, comment := range []string{"//   llgo:cdecl", "//\tllgo:stdcall", "/*llgo:cdecl*/", "//llgointernal:cdecl"} {
		t.Run("inactive-comment/"+comment, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
				"package ordinaryglobals\n"+comment+"\ntype Callback func()\nvar callback Callback\nfunc view() uintptr\n")
			ir, err := goFuncvalGlobalRequest(t, pkg,
				goFuncvalGlobalSource("amd64", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX"),
				"amd64", "x86_64-unknown-linux-gnu", "GoModule")
			if err != nil || ir == "" {
				t.Fatal("inactive comment was mistaken for a native type directive", err)
			}
		})
	}
	for _, origin := range []string{"call", "variable"} {
		t.Run("erased-alias/"+origin, func(t *testing.T) {
			declarations := "package ordinaryglobals\n//llgo:cdecl\ntype Native = func()\n" +
				"var other Native\nfunc acquire() Native { return nil }\n"
			initializer := "acquire()"
			if origin == "variable" {
				initializer = "other"
			}
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, declarations+"var callback = "+initializer+"\nfunc view() uintptr\n")
			ir, err := goFuncvalGlobalRequest(t, pkg,
				goFuncvalGlobalSource("amd64", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX"),
				"amd64", "x86_64-unknown-linux-gnu", "GoModule")
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("erased native alias acquired Go representation: output=%t err=%v", ir != "", err)
			}
		})
	}
	t.Run("ordinary-Go-alias", func(t *testing.T) {
		pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
			"package ordinaryglobals\ntype Callback = func()\nvar callback Callback\nfunc view() uintptr\n")
		ir, err := goFuncvalGlobalRequest(t, pkg,
			goFuncvalGlobalSource("amd64", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX"),
			"amd64", "x86_64-unknown-linux-gnu", "GoModule")
		if err != nil || ir == "" {
			t.Fatal("ordinary Go alias lost its source convention", err)
		}
	})
}

func TestGoModuleFunctionValueCodeWordBindingRevocation(t *testing.T) {
	for _, mutation := range []string{"operand", "alias", "label", "owner", "syntax", "resolver"} {
		t.Run(mutation, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
				goFuncvalGlobalDeclarations("var callback = target"))
			assembly := goFuncvalGlobalSource("amd64", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX")
			file, err := Parse(ArchAMD64, string(assembly))
			if err != nil {
				t.Fatal(err)
			}
			changed := false
			resolve := func(symbol string) string {
				if changed && strings.Contains(symbol, "callback") {
					return "different.callback"
				}
				return testResolveSym(pkg.Path)(symbol)
			}
			binding, err := bindGoReadOnlyStorage(pkg, file, types.SizesFor("gc", "amd64"), "amd64", resolve)
			if err != nil || binding == nil || binding.verify() != nil {
				t.Fatal("valid independent source owner did not bind", err)
			}
			fn := x86DirectTailSnapshot(file).Funcs[0]
			reads, err := binding.funcvalReadsFor(fn)
			if err != nil || len(reads) != 2 || binding.readFor(fn.Instrs[0], "amd64") != nil {
				t.Fatal("pair absent or descriptor acquired numerical spans", err)
			}
			sig, err := DeriveGoFuncABI0Signature(fn.Sym, pkg.Types.Scope().Lookup("view").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("paired codegen fact leaked into public source query", err)
			}
			switch mutation {
			case "operand":
				fn.Instrs[1].Args[0].Mem.Off = 8
			case "alias":
				fn.Instrs[1].Args[1].Reg = "BX"
			case "label":
				fn.Instrs = append(fn.Instrs, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: "other"}}})
			case "owner":
				fn.Sym = "other"
			case "syntax":
				pkg.Syntax[0].Name.Name = "changed"
			case "resolver":
				changed = true
			}
			if mutation == "syntax" || mutation == "resolver" {
				if err := binding.verify(); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed source owner retained its binding", err)
				}
			} else if reads, err := binding.funcvalReadsFor(fn); mutation == "owner" {
				if err != nil || len(reads) != 0 {
					t.Fatal("another function inherited source roles", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed instruction/CFG retained pair roles", err)
			}
		})
	}
	t.Run("convention-association", func(t *testing.T) {
		pkg := mustGoPackage(t, ordinaryGlobalReadPackage, `package ordinaryglobals
//llgo:cdecl
type Other func()
type Callback func()
var callback Callback
func view() uintptr
`)
		file, err := Parse(ArchAMD64, string(goFuncvalGlobalSource("amd64", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX")))
		if err != nil {
			t.Fatal(err)
		}
		binding, err := bindGoReadOnlyStorage(pkg, file, types.SizesFor("gc", "amd64"), "amd64", testResolveSym(pkg.Path))
		if err != nil || binding == nil || binding.verify() != nil {
			t.Fatal("ordinary Go representation did not bind", err)
		}
		first := pkg.Syntax[0].Decls[0].(*ast.GenDecl)
		second := pkg.Syntax[0].Decls[1].(*ast.GenDecl)
		first.Doc, second.Doc = second.Doc, first.Doc
		if err := binding.verify(); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("changed convention association retained Go descriptor permission", err)
		}
	})
}

func TestGoModuleFunctionValueCodeWordImportedTypeAndNestedBoundary(t *testing.T) {
	for _, alias := range []string{"", " ="} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("alias=%t/nested=%t", alias != "", nested), func(t *testing.T) {
				dependency := importedGlobalPackage(t, "example.com/callbacktypes", "amd64",
					[]string{"package callbacktypes\n//llgo:cdecl\ntype Callback" + alias + " func()\n"}, nil)
				typ := "dep.Callback"
				if nested {
					typ = "func(dep.Callback) dep.Callback"
				}
				pkg := importedGlobalPackage(t, ordinaryGlobalReadPackage, "amd64",
					[]string{"package ordinaryglobals\nimport dep \"example.com/callbacktypes\"\nvar callback " + typ + "\nfunc view() uintptr\n"},
					map[string]*types.Package{dependency.Path: dependency.Types})
				ir, err := goFuncvalGlobalRequest(t, pkg,
					goFuncvalGlobalSource("amd64", "MOVQ ·callback(SB),DI\nMOVQ (DI),AX"),
					"amd64", "x86_64-unknown-linux-gnu", "GoModule")
				if nested {
					if err != nil || ir == "" {
						t.Fatal("nested callback parameter changed the outer Go representation", err)
					}
				} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unobserved imported function convention accepted: output=%t err=%v", ir != "", err)
				}
			})
		}
	}
}

func TestGoModuleFunctionValueCodeWordRevokesAdjacentAddressBits(t *testing.T) {
	const declarations = `package ordinaryglobals
var callback func()
func view(dst, src *byte) uintptr
`
	const source = `TEXT ·view(SB),4,$0-24
MOVQ dst+0(FP),BX
MOVQ src+8(FP),SI
LEAL 1(SI),DI
MOVQ ·callback(SB),DI
MOVQ (DI),AX
MOVL DI,(BX)
MOVQ AX,X0
PEXTRQ $0,X0,AX
MOVQ AX,ret+16(FP)
RET
`
	for _, api := range []string{"GoModule", "GoModuleInContext"} {
		t.Run(api, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, declarations)
			ir, err := goFuncvalGlobalRequest(t, pkg, []byte(source), "amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("overwritten descriptor borrowed earlier LEA address bits: output=%t err=%v", ir != "", err)
			}
		})
	}
}

func TestGoModuleFunctionValueCodeWordDoesNotGrantCalls(t *testing.T) {
	for _, result := range []bool{false, true} {
		for _, opcode := range []string{"CALL", "JMP"} {
			for _, api := range []string{"GoModule", "GoModuleInContext"} {
				t.Run(fmt.Sprintf("result=%t/%s/%s", result, opcode, api), func(t *testing.T) {
					declaration, frame, tail := "func view()", 0, "RET\n"
					if result {
						declaration, frame, tail = "func view() uintptr", 8, "MOVQ AX,ret+0(FP)\nRET\n"
					}
					pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
						"package ordinaryglobals\nvar callback func()\n"+declaration+"\n")
					source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\nMOVQ ·callback(SB),DI\nMOVQ (DI),AX\n"+
						"MOVQ $1,DI\nMOVQ $2,SI\nMOVQ $3,DX\nMOVQ $4,CX\nMOVQ $5,R8\nMOVQ $6,R9\n%s AX\n%s", frame, opcode, tail)
					ir, err := goFuncvalGlobalRequest(t, pkg, []byte(source), "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("code word acquired guessed indirect ABI: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
}

func TestGoModuleFunctionValueCodeWordRejectsConflictingWordLayout(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, api := range []string{"GoModule", "GoModuleInContext"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				word, move, result, triple := int64(4), "MOVQ", "uint64", "x86_64-unknown-linux-gnu"
				if arch == "386" {
					word, move, result, triple = 8, "MOVL", "uint32", "i386-unknown-linux-gnu"
				}
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\nvar callback func()\nfunc view() "+result+"\n")
				options := GoModuleOptions{GOOS: "linux", GOARCH: arch, TargetTriple: triple,
					Sizes: &types.StdSizes{WordSize: word, MaxAlign: word}, ResolveSym: testResolveSym(pkg.Path)}
				source := goFuncvalGlobalSource(arch, move+" ·callback(SB),DI\n"+move+" (DI),AX")
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				var translated *GoModuleTranslation
				var err error
				if api == "GoModule" {
					translated, err = TranslateGoModule(pkg, source, options)
				} else {
					translated, err = TranslateGoModuleInContext(ctx, pkg, source, options)
				}
				if translated != nil {
					defer translated.Module.Dispose()
				}
				if translated != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("partial/oversized descriptor layout accepted: output=%t err=%v", translated != nil, err)
				}
			})
		}
	}
}
