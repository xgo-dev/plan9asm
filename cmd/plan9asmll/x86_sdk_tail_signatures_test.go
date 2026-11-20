package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sdkfrontend"
	"golang.org/x/tools/go/packages"
)

const x86SDKTailDeclarationGo = `package p
func First(x uint64) (out uint64)
func Second(a uint32, b uint32) (out uint64)
func Ordinary(x uint64) (out uint64) { return x }
func Other(a uint32, b uint32) (out uint64) { return uint64(a)+uint64(b) }
`

const x86SDKTailDeclarationASM = `TEXT ·First(SB),4,$0-16
JMP shared<>(SB)
TEXT ·Second(SB),4,$0-16
JMP shared<>(SB)
TEXT shared<>(SB),4,$0
JMP ·Ordinary(SB)
`

func x86SDKTailTypedDeclarationFixture(t *testing.T, arch, source, assembly string) (plan9asm.GoPackage, *plan9asm.File, plan9asm.Options) {
	t.Helper()
	const path = "example.invalid/taildecl"
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "p.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", arch)
	typed, err := (&types.Config{Sizes: sizes}).Check(path, fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := plan9asm.GoPackage{Path: path, Types: typed, Syntax: []*ast.File{syntax}}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return sdkfrontend.Resolve(path, symbol) }
	return pkg, file, plan9asm.Options{Goarch: arch, ResolveSym: resolve}
}

func x86SDKTailDeclarationFixture(t *testing.T, arch, source, assembly string) (plan9asm.GoPackage, *plan9asm.File, plan9asm.Options) {
	t.Helper()
	pkg, file, options := x86SDKTailTypedDeclarationFixture(t, arch, source, assembly)
	sizes := types.SizesFor("gc", arch)
	loaded := &packages.Package{PkgPath: pkg.Path, Types: pkg.Types, TypesSizes: sizes, Syntax: pkg.Syntax}
	sigs, _, err := sigsForAsmFile(loaded, file, options.ResolveSym, arch)
	if err != nil {
		t.Fatal(err)
	}
	options.Sigs = sigs
	return pkg, file, options
}

func TestX86SDKDirectTailBoundInventoryRetainsStrictTranslationConsumer(t *testing.T) {
	const assembly = `TEXT ·First(SB),4,$0-16
MOVQ x+0(FP),AX
JMP shared<>(SB)
TEXT ·Second(SB),4,$0-16
MOVL a+0(FP),AX
JMP shared<>(SB)
TEXT shared<>(SB),4,$0
MOVQ AX,out+8(FP)
RET
`
	pkg, file, requested := x86SDKTailTypedDeclarationFixture(t, "amd64", x86SDKTailDeclarationGo, assembly)
	loaded := &packages.Package{PkgPath: pkg.Path, Types: pkg.Types, TypesSizes: types.SizesFor("gc", "amd64"), Syntax: pkg.Syntax}
	if _, _, err := sigsForAsmFile(loaded, file, requested.ResolveSym, "amd64"); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("unbound private FP words escaped the generic original-extent check", err)
	}
	actual, _, needed, err := x86SDKDirectTailDeclarationInventory(pkg, file, requested)
	if err != nil || !needed || len(actual) != 2 {
		t.Fatal("actual typed root inventory was replaced by private-node heuristics", needed, err)
	}
	requested.Sigs = actual
	bound, err := x86SDKDirectTailDeclarationOptions(pkg, file, requested)
	if err != nil {
		t.Fatal(err)
	}
	bound.TargetTriple = "x86_64-unknown-linux-gnu"
	config := compileConfig{numericalOptions: &bound}
	task := asmTask{OutLL: filepath.Join(t.TempDir(), "complete.ll")}
	stale := make(map[string]plan9asm.FuncSig)
	for name, sig := range actual {
		stale[name] = sig
	}
	helper := requested.ResolveSym(file.Funcs[2].Sym)
	stale[helper] = fallbackSigForAsmFunc(file.Funcs[2], helper, "amd64") // Deliberately unbound; negative control only.
	// This is the CLI's existing equality handoff, not a numerical source token.
	// The old local inventory must still fail, and forwarding the exact admitted
	// root inventory must reach the ordinary complete-file translator.
	err = translateAndCompileModule(file, bound.TargetTriple, "amd64", task, false, config, requested.ResolveSym, stale)
	if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || !strings.Contains(err.Error(), "options changed after binding") {
		t.Fatal("strict consumer stopped detecting the stale helper signature", err)
	}
	if err := translateAndCompileModule(file, bound.TargetTriple, "amd64", task, false, config, bound.ResolveSym, bound.Sigs); err != nil {
		t.Fatal("exact declaration inventory was not transported to complete source lowering", err)
	}
	if err := translateAndCompileModule(file, bound.TargetTriple, "amd64", task, true, config, bound.ResolveSym, bound.Sigs); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("consumer equality was relaxed for a different translation option", err)
	}
}

func TestX86SDKDirectTailSignaturesUseActualCompleteDeclarations(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, helper := range []string{"shared", "renamed"} {
			t.Run(arch+"/"+helper, func(t *testing.T) {
				assembly := strings.ReplaceAll(x86SDKTailDeclarationASM, "shared", helper)
				pkg, file, options := x86SDKTailDeclarationFixture(t, arch, x86SDKTailDeclarationGo, assembly)
				original := options.Sigs
				if len(original) != 4 {
					t.Fatal("counterexample no longer exercises generic fallback", original)
				}
				bound, err := x86SDKDirectTailDeclarationOptions(pkg, file, options)
				if err != nil || len(bound.Sigs) != 3 {
					t.Fatalf("actual root/terminal inventory includes fabricated helper: %v, %v", bound.Sigs, err)
				}
				for _, name := range []string{"First", "Second", "Ordinary"} {
					resolved := pkg.Path + "." + name
					if !reflect.DeepEqual(bound.Sigs[resolved], original[resolved]) {
						t.Fatal("actual typed role changed", resolved)
					}
				}
				if len(original) != 4 || !reflect.DeepEqual(file.Funcs[2].Sym, helper+"<>") {
					t.Fatal("adapter mutated caller source/signature inventory")
				}
			})
		}
	}
}

func TestX86SDKDirectTailInventoryRetainsOriginalABISelectors(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, selector := range []string{"", "<ABIInternal>"} {
			t.Run(arch+"/"+selector, func(t *testing.T) {
				assembly := strings.ReplaceAll(x86SDKTailDeclarationASM, "·First(SB)", "·First"+selector+"(SB)")
				pkg, file, options := x86SDKTailTypedDeclarationFixture(t, arch, x86SDKTailDeclarationGo, assembly)
				signatures, sizes, needed, err := x86SDKDirectTailDeclarationInventory(pkg, file, options)
				if err != nil || !needed || len(signatures) != 3 || len(sizes) != 3 {
					t.Fatal("original ABI selector hid an actual declaration or invented a private ABI", needed, err)
				}
				if file.Funcs[0].Sym != "·First"+selector {
					t.Fatal("declaration inventory rewrote the original ABI selector")
				}
			})
		}
	}
}

func TestX86SDKDirectTailSignaturesNeverBorrowRootForOrdinaryTarget(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, role := range []string{"missing-declaration", "wrong-target-transport", "changed-root", "extra-entry", "missing-root"} {
			t.Run(arch+"/"+role, func(t *testing.T) {
				assembly := x86SDKTailDeclarationASM
				if role == "missing-declaration" {
					assembly = strings.ReplaceAll(assembly, "·Ordinary(SB)", "·Missing(SB)")
				}
				pkg, file, options := x86SDKTailDeclarationFixture(t, arch, x86SDKTailDeclarationGo, assembly)
				name := pkg.Path + ".Ordinary"
				switch role {
				case "wrong-target-transport":
					candidate := options.Sigs[pkg.Path+".Second"]
					candidate.Name = name
					options.Sigs[name] = candidate
				case "changed-root":
					candidate := options.Sigs[pkg.Path+".First"]
					candidate.Frame.Results[0].Offset++
					options.Sigs[candidate.Name] = candidate
				case "extra-entry":
					options.Sigs[pkg.Path+".Extra"] = plan9asm.FuncSig{Name: pkg.Path + ".Extra", Ret: plan9asm.I64}
				case "missing-root":
					delete(options.Sigs, pkg.Path+".First")
				}
				if _, err := x86SDKDirectTailDeclarationOptions(pkg, file, options); err == nil {
					t.Fatal("unproved declaration/transport acquired numerical-tail entry inventory")
				}
			})
		}
	}
}
