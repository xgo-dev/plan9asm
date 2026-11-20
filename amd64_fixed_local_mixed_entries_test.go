package plan9asm

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One physical source owns both entries. Ordinary dereferences an incoming Go
// pointer, which is deliberately not a private-frame address or numeric input.
func fixedLocalMixedEntriesFixture(t *testing.T, ordinaryFirst bool) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options, string) {
	t.Helper()
	_, request, _, _ := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	name := filepath.Join(request.Directory, request.AssemblyFile)
	frame, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := "TEXT ·Ordinary(SB),4,$0-16\nMOVQ p+0(FP),AX\nMOVQ (AX),AX\nMOVQ AX,ret+8(FP)\nRET\n"
	assembly := string(frame) + ordinary
	if ordinaryFirst {
		assembly = ordinary + string(frame)
	}
	declaration := "package framefixture\nfunc Value(a, b, c, d uint64) uint64\nfunc Ordinary(p *uint64) uint64\n"
	if err := os.WriteFile(name, []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	goFile := filepath.Join(request.Directory, "value.go")
	if err := os.WriteFile(goFile, []byte(declaration), 0600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, goFile, declaration, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes}).Check("example.invalid/framefixture", fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: make(map[string]FuncSig),
		ResolveSym: func(symbol string) string { return typed.Path() + "." + strings.TrimPrefix(symbol, "·") }}
	for _, name := range []string{"Value", "Ordinary"} {
		sig, err := DeriveGoFuncABI0Signature(typed.Path()+"."+name, typed.Scope().Lookup(name).(*types.Func), "amd64", sizes)
		if err != nil {
			t.Fatal(err)
		}
		options.Sigs[sig.Name] = sig
	}
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}}, request, file, options, assembly
}

func TestGoAMD64FixedLocalMixedOrdinaryEntries(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, ordinaryFirst := range []bool{false, true} {
		order := "frame-first"
		if ordinaryFirst {
			order = "ordinary-first"
		}
		t.Run(order, func(t *testing.T) {
			pkg, request, _, options, _ := fixedLocalMixedEntriesFixture(t, ordinaryFirst)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil || strings.Count(ir, "define ") != 2 || strings.Count(ir, "%fixed_local_native = alloca") != 1 ||
					!strings.Contains(ir, pkg.Path+".Value") || !strings.Contains(ir, pkg.Path+".Ordinary") {
					t.Fatal("mixed full source did not retain exactly one private frame and both ordinary ABI0 entries", err)
				}
				compileLLVMToObject(t, llc, options.TargetTriple, "mixed.ll", "mixed.o", ir)
				compileLLVMToObject(t, llc, options.TargetTriple, "mixed-opt.ll", "mixed-opt.o", x86MulDivRoundOptimize(t, ir))
			})
		})
	}
}

func TestGoAMD64FixedLocalMixedEntryInventoryAndRevocation(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	pkg, request, file, options, assembly := fixedLocalMixedEntriesFixture(t, false)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	frameName, ordinaryName := pkg.Path+".Value", pkg.Path+".Ordinary"
	frameBinding := bound.Sigs[frameName].x86FixedLocal
	if len(source.functions) != 2 || len(bound.Sigs) != 2 || frameBinding == nil || bound.Sigs[ordinaryName].x86FixedLocal != nil {
		t.Fatal("complete inventory was confused with per-function private-frame permission")
	}
	for _, mutation := range []string{"omit ordinary", "ordinary signature", "borrow frame", "detach frame", "crop source"} {
		t.Run(mutation, func(t *testing.T) {
			changed := bound
			changed.Sigs, err = cloneFixedLocalSigs(bound.Sigs)
			if err != nil {
				t.Fatal(err)
			}
			frame, ordinary := changed.Sigs[frameName], changed.Sigs[ordinaryName]
			frame.x86FixedLocal = frameBinding
			changedFile := *file
			switch mutation {
			case "ordinary signature":
				ordinary.Args[0] = I64
			case "borrow frame":
				ordinary.x86FixedLocal = frameBinding
			case "detach frame":
				frame.x86FixedLocal = nil
			case "crop source":
				changedFile.Funcs = file.Funcs[:1]
			}
			changed.Sigs[frameName], changed.Sigs[ordinaryName] = frame, ordinary
			if mutation == "omit ordinary" {
				delete(changed.Sigs, ordinaryName)
			}
			ir, err := Translate(&changedFile, changed)
			fixedLocalRequireContext(t, ir, err)
		})
	}
	// A body with no frame capability remains part of the revocable complete
	// source identity. Changing it must revoke the sibling's backing as well.
	changed := strings.Replace(assembly, "MOVQ (AX),AX", "MOVQ 8(AX),AX", 1)
	if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("ordinary sibling mutation retained the complete source owner", err)
	}
	ir, err := Translate(file, bound)
	fixedLocalRequireContext(t, ir, err)
}

func TestGoAMD64FixedLocalMixedEntryRejectsUnclosedRoles(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, role := range []string{"source call", "private helper"} {
		t.Run(role, func(t *testing.T) {
			pkg, request, _, _, assembly := fixedLocalMixedEntriesFixture(t, false)
			if role == "source call" {
				assembly = strings.Replace(assembly, "TEXT ·Value(SB),4,$160-40", "TEXT ·Value(SB),$160-40\nCALL runtime·morestack_noctxt(SB)", 1)
			} else {
				assembly += "TEXT helper<>(SB),4,$0-0\nRET\n"
			}
			if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(assembly), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if source != nil {
				source.Close()
			}
			if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("ordinary sibling invented a source-call or private-entry contract", err)
			}
		})
	}
}
