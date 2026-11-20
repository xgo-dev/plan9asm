package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestDynamicFPDiagnosticRequiresActualSourceFacts(t *testing.T) {
	resolve := resolveSymFunc("example/dynamic")
	name := "example/dynamic.Stub"
	contextErr := fmt.Errorf("translate: %s: %w: bound typed frame storage", name, plan9asm.ErrProbeNeedsContext)
	for _, test := range []struct {
		name   string
		text   string
		source string
		sig    plan9asm.FuncSig
		decl   bool
		size   int64
		err    error
		want   bool
	}{
		{name: "dynamic", source: "LEAL argframe+0(FP), AX", decl: true, err: contextErr, want: true},
		{name: "explicit_zero_size", text: "20-0", source: "LEAL argframe+0(FP), AX", decl: true, err: contextErr},
		{name: "no_FP", source: "MOVL $0, AX", decl: true, err: contextErr},
		{name: "fallback_not_declaration", source: "LEAL argframe+0(FP), AX", err: contextErr},
		{name: "nonempty_declaration", source: "LEAL argframe+0(FP), AX", decl: true, size: 4, err: contextErr},
		{name: "ordinary_argument", source: "LEAL argframe+0(FP), AX", decl: true, sig: plan9asm.FuncSig{Args: []plan9asm.LLVMType{plan9asm.I32}}, err: contextErr},
		{name: "ordinary_result", source: "LEAL argframe+0(FP), AX", decl: true, sig: plan9asm.FuncSig{Ret: plan9asm.I32}, err: contextErr},
		{name: "bound_frame", source: "LEAL argframe+0(FP), AX", decl: true, sig: plan9asm.FuncSig{Frame: plan9asm.FrameLayout{Params: []plan9asm.FrameSlot{{Type: plan9asm.I32}}}}, err: contextErr},
		{name: "different_failed_function", source: "LEAL argframe+0(FP), AX", decl: true, err: fmt.Errorf("translate: other: %w: bound typed frame storage", plan9asm.ErrProbeNeedsContext)},
		{name: "different_context", source: "LEAL argframe+0(FP), AX", decl: true, err: fmt.Errorf("translate: %s: %w: missing call ABI", name, plan9asm.ErrProbeNeedsContext)},
		{name: "source_error", source: "LEAL argframe+0(FP), AX", decl: true, err: errors.New("source declaration rejected")},
		{name: "success", source: "LEAL argframe+0(FP), AX", decl: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			text := test.text
			if text == "" {
				text = "20"
			}
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT ·Stub(SB),4,$"+text+"\n"+test.source+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			sig := test.sig
			sig.Name = name
			if sig.Ret == "" {
				sig.Ret = plan9asm.Void
			}
			declared := map[string]int64{}
			if test.decl {
				declared[name] = test.size
			}
			got := annotateUnboundCallerFrame(file, resolve, map[string]plan9asm.FuncSig{name: sig}, declared, test.err)
			annotated := got != nil && strings.Contains(got.Error(), "empty Go declaration does not bind a dynamic caller frame")
			if annotated != test.want {
				t.Fatalf("diagnostic annotation=%v want=%v: %v", annotated, test.want, got)
			}
			if test.want {
				if !errors.Is(got, test.err) || !errors.Is(got, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("diagnostic changed the original failure identity: %v", got)
				}
			} else if got != test.err {
				t.Fatalf("unrelated outcome was rewritten: %v", got)
			}
		})
	}
}

// A result-only, non-pointer function has argLen=0 and no pointer bits, yet it
// needs real result storage. Its dynamic stub's separate func() declaration
// cannot infer that storage from either zero or from TEXT's outgoing locals.
func TestDynamicFPMetadataCannotSubstituteForCallerFrame(t *testing.T) {
	for _, goarch := range []string{"386", "amd64", "arm"} {
		t.Run(goarch, func(t *testing.T) {
			fset := token.NewFileSet()
			syntax, err := parser.ParseFile(fset, "contract.go", `package dynamic
const argLen = 0
const pointerBitmap = 0
func Stub()
func ResultOnly() uint64
`, 0)
			if err != nil {
				t.Fatal(err)
			}
			sizes := types.SizesFor("gc", goarch)
			config := types.Config{Sizes: sizes}
			typed, err := config.Check("example/dynamic", fset, []*ast.File{syntax}, nil)
			if err != nil {
				t.Fatal(err)
			}
			pkg := &packages.Package{Types: typed, TypesSizes: sizes, Syntax: []*ast.File{syntax}}
			resolve := resolveSymFunc(typed.Path())
			arch, err := toPlan9Arch(goarch)
			if err != nil {
				t.Fatal(err)
			}
			address := "LEAL argframe+0(FP), AX"
			if goarch == "amd64" {
				address = "LEAQ argframe+0(FP), AX"
			} else if goarch == "arm" {
				address = "MOVW $argframe+0(FP), R4"
			}
			for _, locals := range []int{20, 40, 64} {
				file, err := plan9asm.Parse(arch, fmt.Sprintf("TEXT ·Stub(SB),4,$%d\n%s\nRET\nTEXT ·ResultOnly(SB),4,$0\nRET\n", locals, address))
				if err != nil {
					t.Fatal(err)
				}
				sigs, declared, err := sigsForAsmFile(pkg, file, resolve, goarch)
				if err != nil {
					t.Fatal(err)
				}
				if declared["example/dynamic.Stub"] != 0 || declared["example/dynamic.ResultOnly"] != 8 ||
					len(sigs["example/dynamic.ResultOnly"].Frame.Results) == 0 {
					t.Fatalf("result storage and placeholder declaration were conflated: %v", declared)
				}
				options := plan9asm.Options{
					Goarch: goarch, TargetTriple: targetTriple("linux", goarch), ResolveSym: resolve, Sigs: sigs,
				}
				ir, err := plan9asm.Translate(file, options)
				if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("locals=%d metadata zeros invented caller-frame storage: IR bytes=%d err=%v", locals, len(ir), err)
				}
				if err := rejectUnboundCallerFrame(file, options, declared); !errors.Is(err, plan9asm.ErrProbeNeedsContext) ||
					!strings.Contains(err.Error(), "empty Go declaration does not bind a dynamic caller frame") {
					t.Fatalf("complete-source preflight lost its real dynamic-entry failure: %v", err)
				}
			}
		})
	}
}

func TestDynamicFPPreflightCannotReplaceOrdinaryOwner(t *testing.T) {
	resolve := resolveSymFunc("example/dynamic")
	for _, row := range []struct {
		name, source     string
		translationError bool
	}{
		// Go's NOP pseudo accepts this operand without reading frame storage.
		{"unused FP operand", "TEXT ·Stub(SB),4,$0\nNOP argframe+0(FP)\nRET\n", false},
		{"other failed function", "TEXT ·Other(SB),4,$0-0\nUNKNOWN_OPCODE AX\nRET\nTEXT ·Stub(SB),4,$0\nLEAQ argframe+0(FP),AX\nRET\n", true},
		{"explicit ordinary frame", "TEXT ·Stub(SB),4,$0-0\nRET\n", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, row.source)
			if err != nil {
				t.Fatal(err)
			}
			sigs := map[string]plan9asm.FuncSig{}
			declared := map[string]int64{}
			for _, fn := range file.Funcs {
				name := resolve(fn.Sym)
				sigs[name] = plan9asm.FuncSig{Name: name, Ret: plan9asm.Void}
				declared[name] = 0
			}
			options := plan9asm.Options{Goarch: "amd64", TargetTriple: targetTriple("linux", "amd64"), ResolveSym: resolve, Sigs: sigs}
			_, err = plan9asm.Translate(file, options)
			if (err != nil) != row.translationError || errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("counterexample did not retain its ordinary outcome", err)
			}
			if err := rejectUnboundCallerFrame(file, options, declared); err != nil {
				t.Fatal("preflight replaced the ordinary owner path", err)
			}
		})
	}
}
