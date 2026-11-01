//go:build go1.27

package plan9asm

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

// A complete original Go definition supplies the variable's typed identity,
// not a constant value, an ASM DATA object or a private-frame byte extent.
func TestGoAMD64FixedLocalGlobalAddressObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			for _, register := range []string{"SI", "BP", "R14"} {
				t.Run(register, func(t *testing.T) {
					assembly := strings.NewReplacer("SI", register, "DX", register).Replace(fixedLocalGlobalAssembly)
					pkg, request, _, options := fixedLocalTransportFixture(t, assembly,
						fixedLocalGlobalDeclarations, target.name, target.triple)
					// Each API first compiles/captures this complete original Go
					// source independently; only then does it bind and translate.
					fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
						func(t *testing.T, ir string, err error) {
							if err != nil {
								t.Fatal("ordinary mutable global address and private frame must compose", err)
							}
							fixedLocalGlobalCheckExternal(t, ir)
							compileLLVMToObject(t, llc, target.triple, "global.ll", "global.o", ir)
							compileLLVMToObject(t, llc, target.triple, "global-opt.ll", "global-opt.o", x86MulDivRoundOptimize(t, ir))
						})
				})
			}
		})
	}
}

func fixedLocalGlobalCheckExternal(t *testing.T, ir string) {
	t.Helper()
	for _, line := range strings.Split(ir, "\n") {
		if strings.HasPrefix(line, "@") && strings.Contains(line, "framefixture.Table") {
			if !strings.Contains(line, "external global [32 x i8]") {
				t.Fatal("ordinary mutable Go variable was not retained as external storage", line)
			}
			return
		}
	}
	t.Fatal("ordinary mutable Go variable declaration missing")
}

func TestGoAMD64FixedLocalGlobalAddressGuards(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, row := range []struct{ name, old, replacement string }{
		{"partial address", "MOVQ SI,8(SP)", "MOVL SI,8(SP)"},
		{"pointer arithmetic", "ADDQ $16,DX", "ADDQ SI,DX"},
		{"numeric address", "MOVQ $·Table(SB),SI", "MOVQ $1234,SI"},
		{"numeric result", "MOVQ AX,ret+8(FP)", "MOVQ SI,ret+8(FP)"},
		{"write role", "MOVOU (DX),X1", "MOVOU X0,(DX)"},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := strings.Replace(fixedLocalGlobalAssembly, row.old, row.replacement, 1)
			pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
				fixedLocalGlobalDeclarations, "linux/amd64", "x86_64-unknown-linux-gnu")
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("static address acquired unrelated numeric, write or private-frame permission", err)
			}
		})
	}
	for _, declaration := range []string{"var Table [4]*uint64", "var Table [4]float64", "var Table [8]uint64"} {
		t.Run("supplied_type/"+declaration, func(t *testing.T) {
			pkg, request, file, options := fixedLocalTransportFixture(t, fixedLocalGlobalAssembly,
				fixedLocalGlobalDeclarations, "linux/amd64", "x86_64-unknown-linux-gnu")
			source := requireGoAMD64FrameCapture(t, pkg, request)
			fset := token.NewFileSet()
			syntax, err := parser.ParseFile(fset, "fixture.go", "package framefixture\n"+declaration+"\nfunc Value(a uint64) uint64\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			config := types.Config{Sizes: types.SizesFor("gc", "amd64")}
			typed, err := config.Check(pkg.Path, fset, []*ast.File{syntax}, nil)
			if err != nil {
				t.Fatal(err)
			}
			pkg.Types, pkg.Syntax = typed, []*ast.File{syntax}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("supplied variable type replaced the original complete Go source", err)
			}
		})
	}
	t.Run("global and FP slot zero remain typed alternatives", func(t *testing.T) {
		assembly := strings.Replace(fixedLocalGlobalAssembly, "$32-16", "$32-24", 1)
		assembly = strings.Replace(assembly, "a+0(FP)", "a+8(FP)", 1)
		assembly = strings.Replace(assembly, "ret+8(FP)", "ret+16(FP)", 1)
		assembly = strings.Replace(assembly, "MOVQ SI,8(SP)",
			"MOVQ p+0(FP),DI\nCMPQ AX,$0\nJEQ joined\nMOVQ DI,SI\njoined:\nMOVQ SI,8(SP)", 1)
		declarations := "var Table [4]uint64\nfunc Value(p *uint64, a uint64) uint64\n"
		pkg, request, _, options := fixedLocalTransportFixture(t, assembly,
			declarations, "linux/amd64", "x86_64-unknown-linux-gnu")
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc required")
		}
		fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
			func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal("distinct global/input alternatives lost their native read", err)
				}
				fixedLocalGlobalCheckExternal(t, ir)
				compileLLVMToObject(t, llc, options.TargetTriple, "joined-global.ll", "joined-global.o", ir)
				compileLLVMToObject(t, llc, options.TargetTriple, "joined-global-opt.ll", "joined-global-opt.o", x86MulDivRoundOptimize(t, ir))
			})

		changed := strings.Replace(assembly, "joined:\nMOVQ SI,8(SP)", "joined:\nXORQ SI,AX\nMOVQ SI,8(SP)", 1)
		if changed == assembly {
			t.Fatal("machine-bit fixture lost its joined address operand")
		}
		assembly = changed
		pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
			"var Table [4]uint64\nfunc Value(p *uint64, a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
		source := requireGoAMD64FrameCapture(t, pkg, request)
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		if _, err := source.BindFixedLocal(ctx, pkg, file, options); err != nil {
			t.Fatal("original global/input machine-bit arithmetic rejected", err)
		}
		fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
			func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, options.TargetTriple, "global-bits.ll", "global-bits.o", ir)
			})
	})
	t.Run("bound symbol and lifetime", func(t *testing.T) {
		pkg, request, file, options := fixedLocalTransportFixture(t, fixedLocalGlobalAssembly,
			fixedLocalGlobalDeclarations, "linux/amd64", "x86_64-unknown-linux-gnu")
		source := requireGoAMD64FrameCapture(t, pkg, request)
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		bound, err := source.BindFixedLocal(ctx, pkg, file, options)
		if err != nil {
			t.Fatal(err)
		}
		changed := bound
		changed.ResolveSym = func(symbol string) string {
			if symbol == "·Table" {
				return "foreign.Table"
			}
			return bound.ResolveSym(symbol)
		}
		if ir, err := Translate(file, changed); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
			t.Fatal("different variable inherited the original declaration", err)
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		if ir, err := Translate(file, bound); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
			t.Fatal("closed original source retained a static address role", err)
		}
	})
}
