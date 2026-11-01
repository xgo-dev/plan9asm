package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestSigsForAsmFileARM64PaddingUsesActualCompleteDeclaration(t *testing.T) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "p.go", "package p\nfunc Narrow(rhs int16) (res uint64)\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "arm64")
	typed, err := (&types.Config{Sizes: sizes}).Check("test/padding", fset, []*ast.File{parsed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{PkgPath: typed.Path(), Types: typed, TypesSizes: sizes}
	for _, observable := range []bool{false, true} {
		body := "MOVD rhs+0(FP),R2\nMOVH R2,R0\nMOVD R0,res+8(FP)\n"
		if observable {
			body = "MOVD rhs+0(FP),R2\nMOVD R2,res+8(FP)\n"
		}
		file, err := plan9asm.Parse(plan9asm.ArchARM64, "TEXT ·Narrow(SB),4,$0-16\n"+body+"RET\n")
		if err != nil {
			t.Fatal(err)
		}
		resolve := resolveSymFunc(pkg.PkgPath)
		sigs, declared, err := sigsForAsmFile(pkg, file, resolve, "arm64")
		if err != nil || declared[typed.Path()+".Narrow"] != 16 {
			t.Fatalf("complete selected declaration/layout: %v; sizes=%v", err, declared)
		}
		_, err = plan9asm.Translate(file, plan9asm.Options{
			Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: sigs, ResolveSym: resolve,
		})
		if observable {
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("actual declaration authorized observable native padding: %v", err)
			}
		} else if err != nil {
			t.Fatalf("CLI lost actual typed input for dead padding bits: %v", err)
		}
	}
}

func TestSigsForAsmFileARM64PaddingCannotChangeZeroSizedTransport(t *testing.T) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "p.go", "package p\nfunc Narrow(empty [0]byte, rhs int16) (res uint64)\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "arm64")
	typed, err := (&types.Config{Sizes: sizes}).Check("test/padding", fset, []*ast.File{parsed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(typed.Path())
	sig, _, found, err := tryDeclSig(typed.Scope(), "·Narrow", typed.Path()+".Narrow", nil, "arm64", sizes, false)
	if err != nil || !found || len(sig.Args) != 1 || sig.Args[0] != plan9asm.I16 {
		t.Fatalf("read certificate changed existing zero-size transport: %#v; %v", sig, err)
	}
	file, err := plan9asm.Parse(plan9asm.ArchARM64, "TEXT ·Narrow(SB),4,$0-16\nMOVD rhs+0(FP),R2\nMOVH R2,R0\nMOVD R0,res+8(FP)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = plan9asm.Translate(file, plan9asm.Options{
		Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", ResolveSym: resolve,
		Sigs: map[string]plan9asm.FuncSig{sig.Name: sig},
	})
	if err == nil || !strings.Contains(err.Error(), "has no slot") {
		t.Fatalf("incongruent actual/CLI parameter indexing gained padding authority: %v", err)
	}
}
