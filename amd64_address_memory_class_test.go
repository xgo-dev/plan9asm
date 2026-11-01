package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86MemoryClassKeepsAddressImmediatesDistinct(t *testing.T) {
	for _, source := range []string{
		"$·cell(SB)", "$·cell+8(SB)", "$16(AX)", "$16(AX)(CX*4)",
	} {
		t.Run(source, func(t *testing.T) {
			operand, err := parseOperandForArch(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if operand.Kind != OpSym || !strings.HasPrefix(operand.Sym, "$") {
				t.Fatalf("source address identity lost: %#v", operand)
			}
			if isAMD64MemoryOperand(operand) {
				t.Fatalf("Go TYPE_ADDR became a memory operand: %#v", operand)
			}
			// A caller-built operand must obey the same lexical boundary.
			operand.Sym = " \t" + operand.Sym
			if isAMD64MemoryOperand(operand) {
				t.Fatal("whitespace granted address-immediate memory permission")
			}
		})
	}

	for _, source := range []string{
		"·cell(SB)", "·cell+8(SB)", "(AX)", "16(AX)(CX*4)",
		"arg+0(FP)", "local-8(SP)", "(FS)", "(GS)",
	} {
		t.Run("memory/"+source, func(t *testing.T) {
			operand, err := parseOperandForArch(ArchAMD64, source)
			if err != nil || !isAMD64MemoryOperand(operand) {
				t.Fatalf("ordinary memory class changed: %#v: %v", operand, err)
			}
		})
	}
}

func TestX86AddressImmediateMemoryOnlyFormsRejectAcrossAPIs(t *testing.T) {
	// Independent witnesses from Go's Ym/Ymb/Yml, yxchg, SSE memory,
	// scalar-memory and non-temporal rows. The source contains a TYPE_ADDR
	// where a real memory operand is required; relocation is not a load/store.
	rows := []string{
		"XADDB AL,%s", "XADDW CX,%s", "XADDL CX,%s",
		"XCHGB AL,%s", "XCHGW CX,%s", "XCHGL CX,%s",
		"INCB %s", "INCW %s", "INCL %s",
		"DECB %s", "DECW %s", "DECL %s",
		"NEGB %s", "NEGW %s", "NEGL %s",
		"NOTB %s", "NOTW %s", "NOTL %s",
		"BTCL $1,%s", "BTRL $1,%s", "BTSL $1,%s",
		"STMXCSR %s", "LDMXCSR %s", "CLFLUSH %s",
		"MOVNTIL CX,%s", "MOVNTO X0,%s", "MOVNTPS X0,%s",
		"ADDSUBPS %s,X0", "ADDSUBPD %s,X0",
		"AESENC %s,X0", "PSHUFB %s,X0", "LDDQU %s,X0",
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range rows {
			for _, address := range []string{"$·cell(SB)", "$16(AX)"} {
				instruction := fmt.Sprintf(row, address)
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					memorySource := "TEXT ·Value(SB),4,$0-0\n" +
						fmt.Sprintf(row, strings.TrimPrefix(address, "$")) + "\nRET\n"
					goAssemblerOracleOutput(t, arch, memorySource, "", true)
					source := "TEXT ·Value(SB),4,$0-0\n" + instruction + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", false)
					for _, target := range x86AddressMemoryTargets(arch) {
						for _, api := range []string{"text", "module", "go"} {
							t.Run(target+"/"+api, func(t *testing.T) {
								_, err := x86AddressMemoryAPI(t, api, source, arch, target)
								if err == nil {
									t.Fatal("Go-rejected address immediate acquired memory semantics")
								}
							})
						}
					}
				})
			}
		}
	}
}

func TestX86AddressClassActualGoRulesExcludeMemory(t *testing.T) {
	// Read the actual selected assembler's complete classification/coverage
	// relation. This oracle does not use the translator's operand predicate.
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(),
		"src/cmd/internal/obj/x86/asm6.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	classes := make(map[string]bool)
	foundAddress, foundConstant := false, false
	edges := make(map[string][]string)
	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.FuncDecl:
			if node.Name.Name != "oclass" {
				return true
			}
			ast.Inspect(node.Body, func(child ast.Node) bool {
				clause, ok := child.(*ast.CaseClause)
				if !ok {
					return true
				}
				for _, value := range clause.List {
					name, ok := value.(*ast.SelectorExpr)
					if !ok || name.Sel.Name != "TYPE_ADDR" && name.Sel.Name != "TYPE_CONST" {
						continue
					}
					foundAddress = foundAddress || name.Sel.Name == "TYPE_ADDR"
					foundConstant = foundConstant || name.Sel.Name == "TYPE_CONST"
					for _, statement := range clause.Body {
						ast.Inspect(statement, func(inside ast.Node) bool {
							if result, ok := inside.(*ast.ReturnStmt); ok {
								if len(result.Results) != 1 {
									t.Fatal("unexpected Go operand classification return")
								}
								ident, ok := result.Results[0].(*ast.Ident)
								if !ok || !strings.HasPrefix(ident.Name, "Y") {
									t.Fatal("unregistered Go address/constant classifier")
								}
								classes[ident.Name] = true
							}
							return true
						})
					}
				}
				return true
			})
			return false
		case *ast.AssignStmt:
			for _, left := range node.Lhs {
				index, ok := left.(*ast.IndexExpr)
				if !ok {
					continue
				}
				name, ok := index.X.(*ast.Ident)
				if !ok || name.Name != "ycover" {
					continue
				}
				sum, ok := index.Index.(*ast.BinaryExpr)
				if !ok || sum.Op != token.ADD {
					t.Fatal("unregistered Go class coverage index")
				}
				product, ok := sum.X.(*ast.BinaryExpr)
				if !ok || product.Op != token.MUL {
					t.Fatal("unregistered Go class coverage product")
				}
				from, fromOK := product.X.(*ast.Ident)
				size, sizeOK := product.Y.(*ast.Ident)
				to, toOK := sum.Y.(*ast.Ident)
				if !fromOK || !sizeOK || !toOK || size.Name != "Ymax" {
					t.Fatal("unregistered Go class coverage operands")
				}
				if from.Name == "i" && to.Name == "i" {
					continue // The actual diagonal only relates a class to itself.
				}
				if !strings.HasPrefix(from.Name, "Y") || !strings.HasPrefix(to.Name, "Y") {
					t.Fatal("unregistered computed Go class relation")
				}
				edges[from.Name] = append(edges[from.Name], to.Name)
			}
		}
		return true
	})
	if !foundAddress || !foundConstant || !classes["Yiauto"] || !classes["Yi32"] || len(edges) == 0 {
		t.Fatal("incomplete actual Go TYPE_ADDR/constant/coverage inventory")
	}
	for changed := true; changed; {
		changed = false
		for from := range classes {
			for _, to := range edges[from] {
				if !classes[to] {
					classes[to], changed = true, true
				}
			}
		}
	}
	for _, memory := range []string{"Ym", "Ymb", "Yml", "Ymm", "Yxm", "Yxvm", "Yyvm", "Yzvm"} {
		if classes[memory] {
			t.Fatalf("actual Go address immediate acquired memory-class reachability: %s", memory)
		}
	}
}

func TestX86AddressClassPreservesActualMemoryAndRelocationObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		move := "MOVQ"
		if arch == "386" {
			move = "MOVL"
		}
		for _, row := range []struct {
			body         string
			needsContext bool
		}{
			{move + " $·cell(SB),AX", false},
			{move + " $16(AX),BX", false},
			{"XADDL CX,·cell(SB)", true},
			{"XCHGL CX,16(AX)", true},
			{"INCL ·cell(SB)", true},
			{"NEGL 16(AX)", true},
			{"STMXCSR ·cell(SB)", true},
			{"LDMXCSR 16(AX)", true},
			{"PSHUFB ·cell(SB),X0", false},
			{"MOVNTPS X0,16(AX)", true},
		} {
			source := "TEXT ·Value(SB),4,$0-0\n" + row.body + "\nRET\n"
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, target := range x86AddressMemoryTargets(arch) {
				if row.needsContext {
					// Keep every original memory/relocation object. A Void
					// format fixture supplies neither initialized AX nor the
					// external cell's storage role to a public source proof.
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ir := x86ScalarFormatObjectUnit(t, file,
						map[string]FuncSig{"Value": {Name: "Value", Ret: Void}}, arch, target, 0)
					x86ResultInitializationObject(t, llc, target, ir, "original-address-format")
				}
				for _, api := range []string{"text", "module", "go"} {
					t.Run(arch+"/"+row.body+"/"+target+"/"+api, func(t *testing.T) {
						ir, err := x86AddressMemoryAPI(t, api, source, arch, target)
						if row.needsContext {
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("unbound format acquired public storage/input authority", err)
							}
							return
						}
						if err != nil {
							t.Fatal("legitimate memory/address operand lost:", err)
						}
						x86ResultInitializationObject(t, llc, target, ir, "address-class")
					})
				}
			}
		}
	}
}

func TestX86AddressClassInitializedExchangeObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			move, word := "MOVQ", 8
			if target.arch == "386" {
				move, word = "MOVL", 4
			}
			// Keep the discovering operands. The static counterpart supplies
			// its actual mutable DATA; the pointer counterpart binds its entry
			// parameter. Both independently define the numerical CX input.
			fixtures := []x86OriginalGPInitializedFormat{
				{
					source: "DATA ·cell+0(SB)/4,$0\nGLOBL ·cell(SB),16,$4\n" +
						"TEXT ·AddressStatic(SB),4,$0-0\nMOVL $7,CX\nXADDL CX,·cell(SB)\nRET\n",
					declaration: "func AddressStatic()",
				},
				{
					source: fmt.Sprintf("TEXT ·AddressPointer(SB),4,$0-%d\n%s p+0(FP),AX\n"+
						"MOVL $7,CX\nXCHGL CX,16(AX)\nRET\n", word, move),
					declaration: "func AddressPointer(p *[32]byte)",
				},
			}
			x86OriginalGPInitializedFormatObjects(t, fixtures, target.arch, target.triple)
		})
	}
}

func TestX86AddressClassInitializedNonTemporalStoreObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			move, word := "MOVQ", 8
			if target.arch == "386" {
				move, word = "MOVL", 4
			}
			// Keep the discovering row byte-for-byte, including displacement.
			// The new entry explicitly supplies its pointer and vector inputs;
			// neither the declaration nor LLVM zeroed slots supplies them.
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\n"+
				"PXOR X0,X0\nMOVNTPS X0,16(AX)\nRET\n", word, move)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[32]byte)", target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original non-temporal address form rejected", err)
					}
					for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
						if !strings.Contains(text, "asm sideeffect") || !strings.Contains(text, "movntps") {
							t.Fatal("actual non-temporal store/alignment effect disappeared")
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func x86AddressMemoryTargets(arch string) []string {
	if arch == "386" {
		return []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
	}
	return []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	}
}

func x86AddressMemoryAPI(t *testing.T, api, source, arch, target string) (string, error) {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	options := Options{
		Goarch: arch, TargetTriple: target, ResolveSym: resolve,
		Sigs: map[string]FuncSig{"Value": {Name: "Value", Ret: Void}},
	}
	if api == "text" {
		return Translate(file, options)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "module" {
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
		}
		if err != nil {
			return "", err
		}
		return module.String(), nil
	}
	if api != "go" {
		t.Fatalf("unregistered API %q", api)
	}
	pkg := mustGoPackage(t, "example.invalid/addressclass", "package addressclass\nfunc Value()\n")
	translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: arch, TargetTriple: target, ResolveSym: resolve,
	})
	if translated != nil && !translated.Module.IsNil() {
		defer translated.Module.Dispose()
	}
	if err != nil {
		return "", err
	}
	return translated.Module.String(), nil
}
