package plan9asm

import (
	"context"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Measure the public Translate call, including its actual module/context
// lifetime and IR printing. Parsing, Go signature derivation and independent
// LLVM verification/object compilation belong to the untimed preflight.
func BenchmarkX86IntegerMinMaxTranslation(b *testing.B) {
	const triple = "x86_64-unknown-linux-gnu"
	for _, row := range []struct {
		name    string
		witness goasmrules.X86PackedBinaryWitness
	}{
		{
			name: "legacy-XMM",
			witness: goasmrules.X86PackedBinaryWitness{
				Instruction: "PMINUB X0,X1", Generation: "legacy",
				First: "X0", Second: "X1", Destination: "X1", Width: 16,
			},
		},
		{
			name: "VEX-Y",
			witness: goasmrules.X86PackedBinaryWitness{
				Instruction: "VPMINUD Y0,Y1,Y2", Generation: "vex",
				First: "Y0", Second: "Y1", Destination: "Y2", Width: 32,
			},
		},
		{
			name: "EVEX-Z-masked",
			witness: goasmrules.X86PackedBinaryWitness{
				Instruction: "VPMAXSQ Z0,Z1,K1,Z2", Generation: "evex",
				First: "Z0", Second: "Z1", Destination: "Z2", Width: 64, Masked: true,
			},
		},
	} {
		b.Run(row.name, func(b *testing.B) {
			// Reuse the official min/max row owner's complete initialized
			// source builder. Retain every input, output and the whole TEXT;
			// repeat only its operation to make a 32-operation kernel.
			source, declaration := x86OfficialPackedAssembly([]x86OfficialPackedCase{{witness: row.witness}})
			instruction := row.witness.Instruction + "\n"
			if strings.Count(source, instruction) != 1 {
				b.Fatal("complete row builder lost its one operation")
			}
			source = strings.Replace(source, instruction, strings.Repeat(instruction, 32), 1)
			file, err := Parse(ArchAMD64, source)
			if err != nil || len(file.Funcs) != 1 || strings.Count(source, instruction) != 32 {
				b.Fatal("benchmark must retain one complete 32-operation source", err)
			}
			fset := token.NewFileSet()
			syntax, err := parser.ParseFile(fset, "minmax.go", "package minmaxbench\n"+declaration, parser.ParseComments)
			if err != nil {
				b.Fatal(err)
			}
			config := types.Config{}
			typed, err := config.Check("minmaxbench", fset, []*ast.File{syntax}, nil)
			if err != nil {
				b.Fatal(err)
			}
			pkg := GoPackage{Path: "minmaxbench", Types: typed, Syntax: []*ast.File{syntax}}
			resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
			signatures, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				b.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: triple, ResolveSym: resolve, Sigs: signatures}
			ir, err := Translate(file, options)
			if err != nil || ir == "" {
				b.Fatal("complete public translation must succeed before timing", err)
			}
			x86IntegerMinMaxBenchmarkPreflight(b, ir, triple)
			b.Logf("complete sourceSHA256=%x declarationSHA256=%x bytes=%d operations=32 target=%s",
				sha256.Sum256([]byte(source)), sha256.Sum256([]byte(declaration)), len(source), triple)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if translated, err := Translate(file, options); err != nil || translated == "" {
					b.Fatal("timed public translation failed", err)
				}
			}
		})
	}
}

func x86IntegerMinMaxBenchmarkPreflight(b *testing.B, ir, triple string) {
	b.Helper()
	func() {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		module, err := parseIRModuleInContext(ctx, ir)
		if err != nil {
			b.Fatal("independent preflight ParseIR failed", err)
		}
		defer module.Dispose()
		if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
			b.Fatal("independent preflight VerifyModule failed", err)
		}
	}()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		b.Fatal("LLVM22 llc is required for the untimed object preflight")
	}
	object := filepath.Join(b.TempDir(), "minmax.o")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, llc, "-O0", "-filetype=obj", "-mtriple="+triple, "-o", object)
	command.Stdin = strings.NewReader(ir)
	if output, err := command.CombinedOutput(); err != nil {
		b.Fatalf("untimed LLVM22 object preflight failed: %v\n%s", err, output)
	}
	if info, err := os.Stat(object); err != nil || info.Size() == 0 {
		b.Fatal("LLVM22 object preflight produced no object", err)
	}
}
